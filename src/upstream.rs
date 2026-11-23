//! Reaching a destination: directly or through upstream proxies, then TLS if the route says so.
//!
//! The answers for a destination come from an [`Egress`] (the route's own upstream, else the
//! server's). They are tried in order, so a PAC result such as `PROXY a:3128; DIRECT` fails over.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::net::SocketAddr;
use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;

use coqui_proxy::asynch::ProxyConnector;
use coqui_proxy::pac::{PacScript, PacSource};
use coqui_proxy::{
    ConnectorSettings, Environment, PacSettings, Proxy, ProxyScheme, ProxySetting, Resolver, Route,
};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::connection::Connection;
use crate::error::{Error, RejectedError, Result, UpstreamError, config};
use crate::route::{Action, Route as CaRoute, TlsSource};

/// Where upstream answers come from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Egress {
    /// The operating system's settings, whatever the environment says.
    System,
    /// The proxy variables (`HTTP_PROXY` and the others); a scheme with none goes direct.
    Environment,
    /// The proxy variables when any is set, else the operating system's settings.
    Auto,
    /// No proxy.
    Direct,
    /// A PAC file at this location (an `http(s)` URL, a `file:` URL or a path), loaded when the
    /// egress is first used.
    Pac(String),
    /// A proxy URL, a gateway or a PAC result such as `PROXY a:3128; DIRECT`.
    Proxy(String),
    /// A resolver of your own.
    Resolver(Resolver),
}

impl Egress {
    /// The resolver this egress describes. A PAC location is downloaded here.
    ///
    /// # Errors
    ///
    /// [`Error::Proxy`] for a PAC location that cannot be loaded or text that is not a proxy.
    pub fn resolver(&self) -> Result<Resolver> {
        let no_variables = || Environment::from_pairs(Vec::<(String, String)>::new());
        Ok(match self {
            Self::System => Resolver::builder().environment(no_variables()).build(),
            Self::Environment => Resolver::builder().system(false).build(),
            Self::Auto => Resolver::system(),
            Self::Direct => Resolver::builder()
                .environment(no_variables())
                .system(false)
                .proxy(ProxySetting::Direct)
                .build(),
            Self::Pac(location) => {
                let script = PacScript::from_location(location, &PacSettings::default())?;
                Resolver::builder()
                    .environment(no_variables())
                    .system(false)
                    .source(PacSource::new(script))
                    .build()
            }
            Self::Proxy(text) => Resolver::builder()
                .environment(no_variables())
                .system(false)
                .proxy(text.parse::<ProxySetting>()?)
                .build(),
            Self::Resolver(resolver) => resolver.clone(),
        })
    }

    /// The text this egress is read from in a configuration file, `None` for a [`Resolver`] of
    /// your own.
    pub fn spelling(&self) -> Option<String> {
        Some(match self {
            Self::System => "system".into(),
            Self::Environment => "env".into(),
            Self::Auto => "auto".into(),
            Self::Direct => "direct".into(),
            Self::Pac(location) => alloc::format!("pac:{location}"),
            Self::Proxy(text) => text.clone(),
            Self::Resolver(_) => return None,
        })
    }
}

impl FromStr for Egress {
    type Err = Error;

    /// Reads `system`, `env`, `auto`, `direct`, `pac:<location>`, or a proxy URL or PAC result.
    fn from_str(text: &str) -> Result<Self> {
        let text = text.trim();
        Ok(match text {
            "" => return Err(config("an egress is not empty")),
            "system" => Self::System,
            "env" => Self::Environment,
            "auto" => Self::Auto,
            "direct" => Self::Direct,
            _ => match text.strip_prefix("pac:") {
                Some(location) => Self::Pac(location.into()),
                None => Self::Proxy(text.into()),
            },
        })
    }
}

impl From<Resolver> for Egress {
    fn from(resolver: Resolver) -> Self {
        Self::Resolver(resolver)
    }
}

/// Resolvers already built, by the egress spelling.
#[derive(Debug, Clone, Default)]
struct Resolvers(Arc<Mutex<HashMap<String, Resolver>>>);

impl Resolvers {
    async fn get(&self, egress: &Egress) -> Result<Resolver> {
        let Some(key) = egress.spelling() else {
            return egress.resolver();
        };
        {
            let known = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(resolver) = known.get(&key) {
                return Ok(resolver.clone());
            }
        }
        let owned = egress.clone();
        let resolver = tokio::task::spawn_blocking(move || owned.resolver())
            .await
            .map_err(|_| Error::Timeout("the proxy lookup thread ended"))??;
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, resolver.clone());
        Ok(resolver)
    }
}

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// An open connection to a destination (or to the upstream proxy that forwards a request).
pub struct UpstreamStream {
    io: Box<dyn Io>,
    via: Option<String>,
    tls: bool,
    forward: bool,
    proxy_authorization: Option<String>,
    server: Option<SocketAddr>,
}

impl UpstreamStream {
    /// `scheme://host:port` of the upstream proxy used; `None` when direct.
    pub fn via(&self) -> Option<&str> {
        self.via.as_deref()
    }

    /// Whether the proxy made a TLS connection to the destination.
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// Whether the stream reaches an upstream HTTP proxy without a tunnel: send it absolute-form
    /// requests.
    pub fn forward(&self) -> bool {
        self.forward
    }

    /// The `Proxy-Authorization` value for a [`forward`](Self::forward) stream, from the proxy
    /// URL's credentials.
    pub fn proxy_authorization(&self) -> Option<&str> {
        self.proxy_authorization.as_deref()
    }

    /// The address the proxy connected to: the destination, or the upstream proxy.
    pub fn server(&self) -> Option<SocketAddr> {
        self.server
    }

    /// A stream the caller already holds, as an upstream (for custom front ends and tests).
    pub fn from_io(io: impl AsyncRead + AsyncWrite + Send + Unpin + 'static, tls: bool) -> Self {
        Self {
            io: Box::new(io),
            via: None,
            tls,
            forward: false,
            proxy_authorization: None,
            server: None,
        }
    }
}

impl fmt::Debug for UpstreamStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamStream")
            .field("via", &self.via)
            .field("tls", &self.tls)
            .field("forward", &self.forward)
            .field(
                "proxy_authorization",
                &self.proxy_authorization.as_ref().map(|_| "***"),
            )
            .field("server", &self.server)
            .finish()
    }
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.io).poll_read(context, buffer)
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.io).poll_write(context, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.io).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.io).poll_shutdown(context)
    }
}

/// How [`connect`] reaches a destination.
#[derive(Clone)]
#[must_use]
pub struct ConnectOptions {
    egress: Option<Egress>,
    timeout: Duration,
    forward_http: bool,
    keylog: Option<Arc<dyn rustls::KeyLog>>,
    happy_eyeballs_delay: Duration,
    resolvers: Resolvers,
    connector: Arc<tokio::sync::OnceCell<ProxyConnector>>,
}

impl fmt::Debug for ConnectOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectOptions")
            .field("egress", &self.egress)
            .field("timeout", &self.timeout)
            .field("forward_http", &self.forward_http)
            .field("keylog", &self.keylog.is_some())
            .field("happy_eyeballs_delay", &self.happy_eyeballs_delay)
            .finish_non_exhaustive()
    }
}

impl Default for ConnectOptions {
    fn default() -> Self {
        let defaults = ConnectorSettings::default();
        Self {
            egress: None,
            timeout: defaults.timeout,
            forward_http: false,
            keylog: None,
            happy_eyeballs_delay: defaults.happy_eyeballs_delay,
            resolvers: Resolvers::default(),
            connector: Arc::new(tokio::sync::OnceCell::new()),
        }
    }
}

impl ConnectOptions {
    /// The upstream for routes that set none (default none: direct).
    pub fn egress(mut self, egress: Egress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Bounds each connect, handshake and upstream `CONNECT` reply (default 30 s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.connector = Arc::new(tokio::sync::OnceCell::new());
        self
    }

    /// The delay before racing the next address (default 250 ms).
    pub fn happy_eyeballs_delay(mut self, delay: Duration) -> Self {
        self.happy_eyeballs_delay = delay;
        self.connector = Arc::new(tokio::sync::OnceCell::new());
        self
    }

    /// A plain `http://` request being forwarded: an upstream HTTP proxy answer returns a stream
    /// to the proxy itself instead of a `CONNECT` tunnel, since proxies commonly refuse `CONNECT`
    /// to port 80 (default false).
    pub fn forward_http(mut self, forward: bool) -> Self {
        self.forward_http = forward;
        self
    }

    /// Where every TLS connection this makes logs its secrets (default none).
    pub fn keylog(mut self, keylog: Arc<dyn rustls::KeyLog>) -> Self {
        self.keylog = Some(keylog);
        self
    }

    /// Builds the server's egress now (a PAC location is downloaded), so a mistake in it is found
    /// before the first connection rather than at it.
    ///
    /// # Errors
    ///
    /// [`Error::Proxy`] when the egress cannot be built.
    pub async fn warm_up(&self) -> Result<()> {
        if let Some(egress) = &self.egress {
            self.resolvers.get(egress).await?;
        }
        Ok(())
    }

    /// The server's egress.
    pub fn egress_ref(&self) -> Option<&Egress> {
        self.egress.as_ref()
    }

    /// The connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.timeout
    }

    async fn connector(&self) -> Result<&ProxyConnector> {
        self.connector
            .get_or_try_init(|| async {
                let mut settings = ConnectorSettings::default();
                settings.timeout = self.timeout;
                settings.happy_eyeballs_delay = self.happy_eyeballs_delay;
                let tls = coqui_sslcontext::client_config()?;
                Ok::<_, Error>(
                    coqui_proxy::ProxyConnector::builder()
                        .settings(settings)
                        .proxy_tls(tls)
                        .build()
                        .asynch(),
                )
            })
            .await
    }
}

/// The upstream answers to try for `connection`: proxies, and `None` for a direct connection, in
/// order.
///
/// # Errors
///
/// [`Error::Proxy`] when the egress cannot be built or the lookup fails.
pub async fn resolve_upstream(
    connection: &Connection,
    route: &CaRoute,
    egress: Option<&Egress>,
) -> Result<Vec<Option<Proxy>>> {
    resolve_with(&Resolvers::default(), connection, route, egress)
        .await
        .map(|(answers, _)| answers)
}

async fn resolve_with(
    resolvers: &Resolvers,
    connection: &Connection,
    route: &CaRoute,
    egress: Option<&Egress>,
) -> Result<(Vec<Option<Proxy>>, Option<Resolver>)> {
    let Some(source) = route.upstream().or(egress) else {
        return Ok((alloc::vec![None], None));
    };
    let resolver = resolvers.get(source).await?;
    let routes = coqui_proxy::asynch::lookup(&resolver, &connection.url()).await?;
    let answers = routes
        .into_iter()
        .map(|route| match route {
            Route::Proxy(proxy) => Some(proxy),
            _ => None,
        })
        .collect();
    Ok((answers, Some(resolver)))
}

fn describe(proxy: &Proxy) -> String {
    // Never the credentials: only scheme, host and port.
    alloc::format!(
        "{}://{}",
        proxy.scheme().as_str(),
        crate::connection::join_host(proxy.host(), proxy.port())
    )
}

fn peer(connection: &coqui_proxy::asynch::Connection) -> Option<SocketAddr> {
    match connection {
        coqui_proxy::asynch::Connection::Tcp(stream) => stream.peer_addr().ok(),
        coqui_proxy::asynch::Connection::Tls(stream) => stream.get_ref().0.peer_addr().ok(),
        _ => None,
    }
}

async fn open_proxy(proxy: &Proxy, timeout: Duration) -> Result<UpstreamStream> {
    let target = (proxy.host().to_owned(), proxy.port());
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(target))
        .await
        .map_err(|_| Error::Timeout("connecting to the upstream proxy"))??;
    let server = tcp.peer_addr().ok();
    let io: Box<dyn Io> = match proxy.scheme() {
        ProxyScheme::Https => {
            let tls = TlsConnector::from(coqui_sslcontext::client_config()?);
            let name = ServerName::try_from(proxy.host().to_owned())
                .map_err(|_| config("the upstream proxy's name is not valid for TLS"))?;
            let stream = tokio::time::timeout(timeout, tls.connect(name, tcp))
                .await
                .map_err(|_| Error::Timeout("the TLS handshake with the upstream proxy"))??;
            Box::new(stream)
        }
        _ => Box::new(tcp),
    };
    Ok(UpstreamStream {
        io,
        via: Some(describe(proxy)),
        tls: false,
        forward: true,
        proxy_authorization: proxy.credentials().map(coqui_proxy::auth::basic_header),
        server,
    })
}

/// Opens the connection `route` describes to `connection`'s destination.
///
/// # Errors
///
/// - [`Error::Rejected`] for a `Reject` route (the caller should not have asked);
/// - [`Error::Upstream`] when no upstream answer works (the message lists each attempt, never
///   proxy credentials) or the TLS handshake fails;
/// - [`Error::CredentialUnavailable`] when a TLS route's credential cannot be loaded.
pub async fn connect(
    connection: &Connection,
    route: &CaRoute,
    options: &ConnectOptions,
) -> Result<UpstreamStream> {
    if route.action() == Action::Reject {
        return Err(RejectedError::new(connection.authority()).into());
    }
    let tls_config = match (route.action(), route.tls()) {
        (Action::Tls, Some(TlsSource::Config(config))) => Some(Arc::clone(config)),
        (Action::Tls, Some(TlsSource::Credential(credential))) => {
            Some(credential.tls_config(connection.host()).await?)
        }
        (Action::Tls, None) => return Err(config("a TLS route needs a client configuration")),
        _ => None,
    };
    let tls_config = tls_config.map(|config| match &options.keylog {
        Some(keylog) => {
            let mut config = (*config).clone();
            config.key_log = Arc::clone(keylog);
            Arc::new(config)
        }
        None => config,
    });
    let connector = options.connector().await?;
    let (answers, resolver) = resolve_with(
        &options.resolvers,
        connection,
        route,
        options.egress.as_ref(),
    )
    .await?;
    let mut failures = Vec::new();
    for answer in answers {
        let place = answer.as_ref().map_or_else(|| "direct".into(), describe);
        let opened = match &answer {
            Some(proxy)
                if options.forward_http
                    && tls_config.is_none()
                    && matches!(proxy.scheme(), ProxyScheme::Http | ProxyScheme::Https) =>
            {
                return open_proxy(proxy, options.timeout).await.map_err(|error| {
                    UpstreamError::unreachable(
                        &connection.authority(),
                        alloc::vec![alloc::format!("{place}: {error}")],
                    )
                    .into()
                });
            }
            Some(proxy) => {
                connector
                    .connect(
                        &Route::Proxy(proxy.clone()),
                        connection.host(),
                        connection.port(),
                    )
                    .await
            }
            None => {
                connector
                    .connect(&Route::Direct, connection.host(), connection.port())
                    .await
            }
        };
        let stream = match opened {
            Ok(stream) => stream,
            Err(error) => {
                if let (Some(proxy), Some(resolver)) = (&answer, &resolver) {
                    resolver.report_failure(proxy);
                }
                tracing::debug!(
                    target: "caguax",
                    destination = %connection.authority(),
                    via = %place,
                    %error,
                    "upstream attempt failed"
                );
                failures.push(alloc::format!("{place}: {error}"));
                continue;
            }
        };
        let server = peer(&stream);
        let via = answer.as_ref().map(describe);
        let Some(config) = &tls_config else {
            return Ok(UpstreamStream {
                io: Box::new(stream),
                via,
                tls: false,
                forward: false,
                proxy_authorization: None,
                server,
            });
        };
        let name = ServerName::try_from(connection.host().to_owned())
            .map_err(|_| config_error("the destination's name is not valid for TLS"))?;
        let handshake = TlsConnector::from(Arc::clone(config)).connect(name, stream);
        let tls = match tokio::time::timeout(options.timeout, handshake).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(error)) => {
                return Err(UpstreamError::new(alloc::format!(
                    "TLS to {} via {place} failed: {error}",
                    connection.authority()
                ))
                .into());
            }
            Err(_) => {
                return Err(UpstreamError::new(alloc::format!(
                    "TLS to {} via {place} timed out",
                    connection.authority()
                ))
                .into());
            }
        };
        return Ok(UpstreamStream {
            io: Box::new(tls),
            via,
            tls: true,
            forward: false,
            proxy_authorization: None,
            server,
        });
    }
    Err(UpstreamError::unreachable(&connection.authority(), failures).into())
}

fn config_error(message: &str) -> Error {
    config(message)
}
