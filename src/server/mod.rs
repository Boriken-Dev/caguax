//! The server: listeners, per-connection tasks, lifecycle.
//!
//! Point clients at `http://<addresses()[0]>`: `HTTP_PROXY`/`HTTPS_PROXY`, a browser, `curl -x`.
//! Every request through it is routed as a [`Connection`] whose listener is `proxy`. A server is
//! built with [`Server::builder`] and stopped with [`Server::shutdown`].

pub mod blocking;
mod http;
mod relay;
mod tunnel;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, watch};

pub use relay::{IdleRead, RelayOptions, relay};
pub(crate) use tunnel::check_credentials as check_tunnel_credentials;
pub use tunnel::{Tunnel, TunnelBuilder};

use crate::auth::{Auth, Login};
use crate::connection::Connection;
use crate::error::{Result, config};
use crate::intercept::{Interceptor, load_ca};
use crate::keylog::FileKeyLog;
use crate::listen::ListenAddr;
use crate::record::{LogRecorder, RecordedStream, Recorder, Recording, Session};
use crate::route::{Route, Router, Routing};
use crate::settings::ServerSettings;
use crate::upstream::{ConnectOptions, Egress, UpstreamStream, connect};

/// How [`Server::open_upstream`] connects.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct OpenOptions {
    /// A plain `http://` request being forwarded: an upstream HTTP proxy answer returns a stream
    /// to the proxy itself instead of a `CONNECT` tunnel (default false).
    pub forward_http: bool,
}

/// What [`Server::relay_session`] is told beyond the streams.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct RelaySession {
    /// A recording already started; `None` starts one when the server has recorders.
    pub recording: Option<Arc<Recording>>,
    /// Bytes written to the upstream before anything the client sends.
    pub before_server: Option<Bytes>,
    /// The client side is TLS, so one direction ending ends both.
    pub client_tls: bool,
}

/// What a reload swaps: everything a request consults.
pub(crate) struct State {
    pub(crate) router: Arc<dyn Routing>,
    pub(crate) settings: ServerSettings,
    pub(crate) connect: ConnectOptions,
    pub(crate) interceptor: Option<Arc<Interceptor>>,
    pub(crate) recorders: Vec<Arc<dyn Recorder>>,
    /// What a request to the HTTP proxy listener must present; `None` asks for nothing.
    pub(crate) login: Option<Arc<Login>>,
}

/// What the builder was given in code, kept so a reload can keep it.
struct Given {
    interceptor: Option<Arc<Interceptor>>,
    recorders: Vec<Arc<dyn Recorder>>,
    /// The generated listener login, kept so a reload does not change it.
    generated: Mutex<Option<Login>>,
}

pub(crate) struct Inner {
    state: RwLock<Arc<State>>,
    given: Given,
    sessions: AtomicU64,
    active: AtomicUsize,
    warned: AtomicU64,
    plain_tls: tokio::sync::OnceCell<Arc<rustls::ClientConfig>>,
    shutdown: watch::Sender<bool>,
    drain: Mutex<Option<mpsc::Sender<()>>>,
    proxy_addresses: Vec<SocketAddr>,
    tunnels: Vec<(Arc<Tunnel>, SocketAddr)>,
}

/// Counts a client connection against `max_connections` until dropped.
pub(crate) struct Admission(Arc<Inner>);

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Inner {
    pub(crate) fn state(&self) -> Arc<State> {
        Arc::clone(
            &self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Runs `work` until it ends or the server shuts down; shutdown waits for it.
    pub(crate) fn spawn(&self, work: impl Future<Output = ()> + Send + 'static) {
        let guard = self
            .drain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(guard) = guard else {
            return;
        };
        let mut stop = self.shutdown.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => {}
                () = work => {}
            }
            drop(guard);
        });
    }

    fn admit(self: &Arc<Self>, limit: usize) -> Option<Arc<Admission>> {
        let current = self.active.fetch_add(1, Ordering::AcqRel);
        if current >= limit {
            self.active.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Arc::new(Admission(Arc::clone(self))))
    }

    /// Logs at most once per `interval`.
    fn warn_limited(&self, interval: core::time::Duration, message: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        let last = self.warned.load(Ordering::Acquire);
        let due = last == 0 || now.saturating_sub(last) >= interval.as_millis() as u64;
        if due
            && self
                .warned
                .compare_exchange(last, now.max(1), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            tracing::warn!(target: "caguax", "{message}");
        }
    }

    pub(crate) async fn open_upstream(
        &self,
        connection: &Connection,
        route: &Route,
        options: OpenOptions,
    ) -> Result<UpstreamStream> {
        let state = self.state();
        let connect_options = state.connect.clone().forward_http(options.forward_http);
        connect(connection, route, &connect_options).await
    }

    pub(crate) fn start_recording(
        &self,
        connection: &Connection,
        route: &Route,
        client: Option<SocketAddr>,
        upstream: &UpstreamStream,
    ) -> Option<Arc<Recording>> {
        let state = self.state();
        let id = self.sessions.fetch_add(1, Ordering::AcqRel) + 1;
        Recording::start(
            &state.recorders,
            Session::new(
                id,
                connection.clone(),
                route.clone(),
                client,
                upstream.server(),
            ),
        )
    }

    pub(crate) async fn relay_session<C>(
        &self,
        client: C,
        upstream: UpstreamStream,
        recording: Option<Arc<Recording>>,
        before_server: Option<Bytes>,
        client_tls: bool,
    ) where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let state = self.state();
        let settings = &state.settings;
        let end_both = client_tls || upstream.tls();
        let options = RelayOptions {
            idle_timeout: settings.idle_timeout,
            buffer: settings.relay_buffer,
            close_timeout: settings.close_timeout,
            end_both,
        };
        let mut upstream = RecordedStream::new(upstream, recording);
        if let Some(bytes) = before_server
            && (upstream.write_all(&bytes).await.is_err() || upstream.flush().await.is_err())
        {
            return;
        }
        relay(client, upstream, options).await;
    }
}

/// Builds a [`Server`].
#[must_use]
pub struct ServerBuilder {
    router: Arc<dyn Routing>,
    settings: ServerSettings,
    tunnels: Vec<Tunnel>,
    recorders: Vec<Arc<dyn Recorder>>,
    interceptor: Option<Interceptor>,
}

impl fmt::Debug for ServerBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerBuilder")
            .field("settings", &self.settings)
            .field("tunnels", &self.tunnels.len())
            .finish_non_exhaustive()
    }
}

impl ServerBuilder {
    /// All the settings at once (default [`ServerSettings::default`]).
    pub fn settings(mut self, settings: ServerSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Where the HTTP proxy accepts; none means tunnels only.
    pub fn listen(mut self, listen: impl IntoIterator<Item = ListenAddr>) -> Self {
        self.settings.listen = listen.into_iter().collect();
        self
    }

    /// Whether the HTTP proxy listener asks for a login, and which.
    pub fn auth(mut self, auth: Auth) -> Self {
        self.settings.auth = auth;
        self
    }

    /// Allows listening beyond loopback.
    pub fn allow_remote(mut self, allow: bool) -> Self {
        self.settings.allow_remote = allow;
        self
    }

    /// Where upstream answers come from for routes that set none.
    pub fn egress(mut self, egress: Egress) -> Self {
        self.settings.egress = Some(egress);
        self
    }

    /// Enables interception with this CA.
    pub fn ca(self, ca: coqui_sslcontext::CertificateAuthority) -> Result<Self> {
        let settings = self.settings.intercept.clone();
        Ok(self.interceptor(Interceptor::new(ca, settings)?))
    }

    /// Enables interception with this interceptor.
    pub fn interceptor(mut self, interceptor: Interceptor) -> Self {
        self.interceptor = Some(interceptor);
        self
    }

    /// Adds a recorder that sees every relayed session.
    pub fn recorder(mut self, recorder: impl Recorder + 'static) -> Self {
        self.recorders.push(Arc::new(recorder));
        self
    }

    /// Adds a tunnel listener.
    pub fn tunnel(mut self, tunnel: impl Into<Tunnel>) -> Self {
        self.tunnels.push(tunnel.into());
        self
    }

    /// Adds tunnel listeners.
    pub fn tunnels<T: Into<Tunnel>>(mut self, tunnels: impl IntoIterator<Item = T>) -> Self {
        self.tunnels.extend(tunnels.into_iter().map(Into::into));
        self
    }

    /// Binds every listener and starts serving.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for settings that mean nothing or a listener beyond loopback without
    /// `allow_remote`; [`crate::Error::Io`] when an address is taken; the errors of loading the CA, the
    /// key log or the capture file; [`crate::Error::Proxy`] when the egress cannot be built.
    pub async fn start(self) -> Result<Server> {
        let Self {
            router,
            settings,
            tunnels,
            recorders,
            interceptor,
        } = self;
        settings.validate()?;
        let all: Vec<ListenAddr> = settings
            .listen
            .iter()
            .copied()
            .chain(tunnels.iter().map(Tunnel::listen))
            .collect();
        if !settings.allow_remote
            && let Some(address) = all.iter().find(|address| !address.is_local())
        {
            return Err(config(alloc::format!(
                "refusing to listen on {address}: a proxy holding client credentials should only \
                 accept local connections; set allow_remote to listen beyond loopback"
            )));
        }
        let given = Given {
            interceptor: interceptor.map(Arc::new),
            recorders,
            generated: Mutex::new(None),
        };
        let state = build_state(router, settings, &given).await?;
        tunnel::check_credentials(tunnels.iter(), state.router.as_ref(), &state.settings)?;
        let mut proxy_sockets = Vec::new();
        for address in &state.settings.listen {
            proxy_sockets.push(bind(*address, state.settings.listen_backlog)?);
        }
        let tunnels: Vec<Arc<Tunnel>> = tunnels.into_iter().map(Arc::new).collect();
        let mut tunnel_sockets = Vec::new();
        for tunnel in &tunnels {
            tunnel_sockets.push(bind(tunnel.listen(), state.settings.listen_backlog)?);
        }
        let proxy_addresses: Vec<SocketAddr> = proxy_sockets
            .iter()
            .map(TcpListener::local_addr)
            .collect::<std::io::Result<_>>()?;
        let tunnel_addresses: Vec<(Arc<Tunnel>, SocketAddr)> = tunnels
            .iter()
            .zip(&tunnel_sockets)
            .map(|(tunnel, listener)| {
                listener
                    .local_addr()
                    .map(|address| (Arc::clone(tunnel), address))
            })
            .collect::<std::io::Result<_>>()?;
        let (shutdown, _) = watch::channel(false);
        let (drain, drained) = mpsc::channel(1);
        let inner = Arc::new(Inner {
            state: RwLock::new(Arc::new(state)),
            given,
            sessions: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            warned: AtomicU64::new(0),
            plain_tls: tokio::sync::OnceCell::new(),
            shutdown,
            drain: Mutex::new(Some(drain)),
            proxy_addresses,
            tunnels: tunnel_addresses,
        });
        for listener in proxy_sockets {
            let loop_inner = Arc::clone(&inner);
            inner.spawn(accept_loop(listener, loop_inner, None));
        }
        for (listener, tunnel) in tunnel_sockets.into_iter().zip(tunnels) {
            let loop_inner = Arc::clone(&inner);
            inner.spawn(accept_loop(listener, loop_inner, Some(tunnel)));
        }
        Ok(Server { inner, drained })
    }
}

fn bind(address: ListenAddr, backlog: u32) -> Result<TcpListener> {
    let socket = if address.address().is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // On Windows a reused address lets another process take the port.
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(address.socket_addr())?;
    Ok(socket.listen(backlog)?)
}

async fn build_state(
    router: Arc<dyn Routing>,
    settings: ServerSettings,
    given: &Given,
) -> Result<State> {
    settings.validate()?;
    let keylog = match &settings.keylog {
        Some(path) => Some(FileKeyLog::open(path)?),
        None => None,
    };
    let mut connect = ConnectOptions::default()
        .timeout(settings.connect_timeout)
        .happy_eyeballs_delay(settings.happy_eyeballs_delay);
    if let Some(egress) = &settings.egress {
        connect = connect.egress(egress.clone());
    }
    if let Some(keylog) = &keylog {
        connect = connect.keylog(Arc::clone(keylog) as Arc<dyn rustls::KeyLog>);
    }
    connect.warm_up().await?;
    let interceptor = if settings.ca.is_configured() {
        let ca = load_ca(&settings.ca)?;
        let mut interceptor = Interceptor::new(ca, settings.intercept.clone())?;
        if let Some(keylog) = &keylog {
            interceptor = interceptor.with_keylog(Arc::clone(keylog) as Arc<dyn rustls::KeyLog>);
        }
        Some(Arc::new(interceptor))
    } else {
        given.interceptor.clone()
    };
    let mut recorders = given.recorders.clone();
    if settings.log_traffic {
        recorders.push(Arc::new(LogRecorder::new()));
    }
    if let Some(path) = &settings.record {
        recorders.push(pcap_recorder(path)?);
    }
    let login = {
        let mut kept = given
            .generated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let login = settings.auth.resolve(kept.as_ref())?;
        if matches!(settings.auth, Auth::Generated { .. }) {
            kept.clone_from(&login);
        }
        login
    };
    Ok(State {
        router,
        settings,
        connect,
        interceptor,
        recorders,
        login: login.map(Arc::new),
    })
}

#[cfg(feature = "pcap")]
fn pcap_recorder(path: &std::path::Path) -> Result<Arc<dyn Recorder>> {
    use crate::record::{PcapFormat, PcapRecorder};
    let format = if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pcapng"))
    {
        PcapFormat::Pcapng
    } else {
        PcapFormat::Pcap
    };
    Ok(Arc::new(PcapRecorder::create(path, format)?))
}

#[cfg(not(feature = "pcap"))]
fn pcap_recorder(_path: &std::path::Path) -> Result<Arc<dyn Recorder>> {
    Err(config("server.record needs the `pcap` feature"))
}

async fn accept_loop(listener: TcpListener, inner: Arc<Inner>, tunnel: Option<Arc<Tunnel>>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                let state = inner.state();
                inner.warn_limited(
                    state.settings.warn_interval,
                    &alloc::format!("accepting a connection failed: {error}"),
                );
                tokio::time::sleep(state.settings.accept_error_delay).await;
                continue;
            }
        };
        let state = inner.state();
        let Some(admission) = inner.admit(state.settings.max_connections) else {
            inner.warn_limited(
                state.settings.warn_interval,
                "max_connections reached: new connections are closed",
            );
            continue;
        };
        let local = stream.local_addr().ok();
        let connection_inner = Arc::clone(&inner);
        match &tunnel {
            Some(tunnel) => {
                let tunnel = Arc::clone(tunnel);
                inner.spawn(async move {
                    let _admission = admission;
                    tunnel::serve(connection_inner, tunnel, stream).await;
                });
            }
            None => {
                inner.spawn(async move {
                    serve_proxy(connection_inner, stream, peer, local, admission).await;
                });
            }
        }
    }
}

async fn serve_proxy(
    inner: Arc<Inner>,
    stream: TcpStream,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    admission: Arc<Admission>,
) {
    let state = inner.state();
    let settings = &state.settings;
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(settings.connect_timeout)
        .max_buf_size(settings.max_head_bytes.max(8192))
        .max_headers(settings.max_headers)
        .keep_alive(settings.keep_alive);
    let connection = http::ClientConnection {
        inner,
        peer,
        local,
        admission,
    };
    let service = service_fn(move |request| {
        let connection = connection.clone();
        async move { Ok::<_, core::convert::Infallible>(http::handle(connection, request).await) }
    });
    let served = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    if let Err(error) = served.await {
        tracing::debug!(target: "caguax", %peer, %error, "client connection ended with an error");
    }
}

/// A running proxy. Dropping it stops the tasks without waiting; [`shutdown`](Self::shutdown)
/// stops listening, cancels every connection and waits for them.
pub struct Server {
    inner: Arc<Inner>,
    drained: mpsc::Receiver<()>,
}

impl fmt::Debug for Server {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Server")
            .field("addresses", &self.inner.proxy_addresses)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// A builder for a server routing with `router`.
    pub fn builder(router: impl Routing + 'static) -> ServerBuilder {
        ServerBuilder {
            router: Arc::new(router),
            settings: ServerSettings::default(),
            tunnels: Vec::new(),
            recorders: Vec::new(),
            interceptor: None,
        }
    }

    /// A builder for a server in which everything goes direct.
    pub fn direct() -> ServerBuilder {
        Self::builder(Router::new())
    }

    /// The addresses the HTTP proxy listens on, ports read back.
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.inner.proxy_addresses
    }

    /// The first HTTP proxy port.
    ///
    /// # Panics
    ///
    /// When the server has no HTTP proxy listener (tunnels only).
    pub fn port(&self) -> u16 {
        self.inner.proxy_addresses[0].port()
    }

    /// The tunnels, with where each listens.
    pub fn tunnels(&self) -> impl Iterator<Item = (&Tunnel, SocketAddr)> {
        self.inner
            .tunnels
            .iter()
            .map(|(tunnel, address)| (tunnel.as_ref(), *address))
    }

    /// Where `tunnel` (one of this server's) listens, port read back.
    pub fn tunnel_address(&self, tunnel: &Tunnel) -> Option<SocketAddr> {
        self.inner
            .tunnels
            .iter()
            .find(|(candidate, _)| candidate.name() == tunnel.name())
            .map(|(_, address)| *address)
    }

    /// The settings in force.
    pub fn settings(&self) -> ServerSettings {
        self.inner.state().settings.clone()
    }

    /// The router in force.
    pub fn router(&self) -> Arc<dyn Routing> {
        Arc::clone(&self.inner.state().router)
    }

    /// The interceptor, when interception is enabled.
    pub fn interceptor(&self) -> Option<Arc<Interceptor>> {
        self.inner.state().interceptor.clone()
    }

    /// The recorders that see every session.
    pub fn recorders(&self) -> Vec<Arc<dyn Recorder>> {
        self.inner.state().recorders.clone()
    }

    /// What is looser than the defaults, as `setting = value` text: the settings, a CA that is not
    /// name-constrained and credentials that verify nothing.
    pub fn non_defaults(&self) -> Vec<alloc::string::String> {
        let state = self.inner.state();
        let mut found = state.settings.non_defaults();
        if let Some(interceptor) = &state.interceptor {
            found.extend(interceptor.non_defaults());
        }
        if let Some(router) = state.router.router() {
            found.extend(crate::config::router_non_defaults(router));
        }
        for (tunnel, _) in &self.inner.tunnels {
            if tunnel.allow_any_local() {
                found.push(alloc::format!(
                    "tunnels.{}.allow_any_local = true",
                    tunnel.name()
                ));
            }
        }
        found
    }

    /// The login the HTTP proxy listener asks for (the generated one included), or `None` with
    /// `server.auth = "none"`. The password is a secret: hand it to the client, never log it.
    pub fn proxy_login(&self) -> Option<Login> {
        self.inner.state().login.as_deref().cloned()
    }

    /// [`ConnectOptions`]-based connect with this server's egress, timeout and key log.
    ///
    /// # Errors
    ///
    /// As [`connect`].
    pub async fn open_upstream(
        &self,
        connection: &Connection,
        route: &Route,
        options: OpenOptions,
    ) -> Result<UpstreamStream> {
        self.inner.open_upstream(connection, route, options).await
    }

    /// A recording of one session, or `None` with no recorders.
    pub fn start_recording(
        &self,
        connection: &Connection,
        route: &Route,
        client: Option<SocketAddr>,
        upstream: &UpstreamStream,
    ) -> Option<Arc<Recording>> {
        self.inner
            .start_recording(connection, route, client, upstream)
    }

    /// Relays `client` with `upstream` until both directions end; `session` says what else to do.
    pub async fn relay_session<C>(
        &self,
        connection: &Connection,
        route: &Route,
        client: C,
        upstream: UpstreamStream,
        session: RelaySession,
    ) where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let recording = session.recording.or_else(|| {
            self.inner
                .start_recording(connection, route, connection.client(), &upstream)
        });
        self.inner
            .relay_session(
                client,
                upstream,
                recording,
                session.before_server,
                session.client_tls,
            )
            .await;
    }

    /// Replaces the settings and the router in force, building the new state beside the old: a
    /// state that fails to build leaves the running one. Listeners, their number and addresses and
    /// the tunnels are not changed; a different `listen` is refused.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for a different `listen`; otherwise as [`ServerBuilder::start`].
    pub async fn reload(
        &self,
        settings: ServerSettings,
        router: impl Routing + 'static,
    ) -> Result<()> {
        let current = self.inner.state();
        if current.settings.listen != settings.listen {
            return Err(config(
                "the listen addresses cannot change without a restart",
            ));
        }
        let state = build_state(Arc::new(router), settings, &self.inner.given).await?;
        tunnel::check_credentials(
            self.inner.tunnels.iter().map(|(tunnel, _)| tunnel.as_ref()),
            state.router.as_ref(),
            &state.settings,
        )?;
        *self
            .inner
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(state);
        Ok(())
    }

    /// Returns when [`shutdown`](Self::shutdown) has been asked for (from another task) or the
    /// server is dropped.
    pub async fn serve(&self) {
        let mut stop = self.inner.shutdown.subscribe();
        let _ = stop.wait_for(|stopped| *stopped).await;
    }

    /// Stops listening, cancels every connection and waits for them.
    pub async fn shutdown(mut self) {
        let _ = self.inner.shutdown.send(true);
        self.inner
            .drain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        while self.drained.recv().await.is_some() {}
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.inner.shutdown.send(true);
    }
}
