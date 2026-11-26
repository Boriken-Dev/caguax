//! Loopback stand-ins for the tests: origins, an upstream proxy, a raw client and a test PKI.
//! Every server binds port 0 on loopback; every key and certificate is made by the test.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use caguax::Credential;
use coqui_sslcontext::{
    CertificateAuthority, CertificateInfo, ClientAuth, ClientCertificates, KeyPassword, Tls, Trust,
};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// A certificate authority and what it issues.
pub struct Pki {
    pub ca: CertificateAuthority,
}

impl Pki {
    pub fn new() -> Self {
        Self {
            ca: CertificateAuthority::builder("Test Root").create().unwrap(),
        }
    }

    pub fn roots(&self) -> Trust {
        Trust::Roots(vec![self.ca.certificate_der().clone()])
    }

    /// A server certificate for loopback; with `require_client`, clients must present one the CA
    /// issued.
    pub fn server_config(&self, require_client: bool) -> Arc<rustls::ServerConfig> {
        let auth = if require_client {
            ClientAuth::Required(self.roots())
        } else {
            ClientAuth::None
        };
        self.ca
            .issue(["localhost", "127.0.0.1"])
            .unwrap()
            .server_config(auth)
            .unwrap()
    }

    /// A client credential for the name `common_name`, verifying servers against this CA.
    pub fn credential(&self, common_name: &str) -> Credential {
        let issued = self
            .ca
            .leaf(["client.example"])
            .common_name(common_name)
            .issue()
            .unwrap();
        let ca_pem = self.ca.certificate_pem();
        let chain = format!("{}{}", issued.certificate_pem(), issued.chain_pem());
        Credential::from_pem(
            chain.into_bytes(),
            Some(issued.key_pem().as_bytes().to_vec()),
            KeyPassword::None,
        )
        .name(common_name)
        .cadata(ca_pem.into_bytes())
        .build()
    }

    /// A client configuration trusting this CA and presenting no certificate.
    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        Tls::builder()
            .trust(self.roots())
            .client_certificates(ClientCertificates::None)
            .build()
            .unwrap()
            .client_config("127.0.0.1")
            .unwrap()
    }
}

/// What the echo origin saw, as text: the request line, the headers, and the client certificate.
pub async fn echo_origin(tls: Option<Arc<rustls::ServerConfig>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    Some(config) => {
                        let Ok(stream) = TlsAcceptor::from(config).accept(stream).await else {
                            return;
                        };
                        let subject = stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|chain| CertificateInfo::from_chain(chain).ok())
                            .map(|info| info.subject().to_owned());
                        serve(TokioIo::new(stream), subject).await;
                    }
                    None => serve(TokioIo::new(stream), None).await,
                }
            });
        }
    });
    address
}

async fn serve<I>(io: I, subject: Option<String>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
        let subject = subject.clone();
        async move {
            if request.uri().path() == "/upgrade" {
                let upgrade = hyper::upgrade::on(&mut request);
                tokio::spawn(async move {
                    let Ok(upgraded) = upgrade.await else { return };
                    let mut upgraded = TokioIo::new(upgraded);
                    let mut buffer = [0_u8; 1024];
                    while let Ok(count) = upgraded.read(&mut buffer).await {
                        if count == 0 || upgraded.write_all(&buffer[..count]).await.is_err() {
                            break;
                        }
                    }
                });
                return Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "upgrade")
                        .header("upgrade", "echo")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                );
            }
            let mut text = format!("{} {}\n", request.method(), request.uri());
            for (name, value) in request.headers() {
                text.push_str(&format!("{name}: {}\n", value.to_str().unwrap_or("?")));
            }
            if let Some(subject) = subject {
                text.push_str(&format!("client-subject: {subject}\n"));
            }
            Ok(Response::builder()
                .header("x-origin", "echo")
                .header("connection", "x-hop")
                .header("x-hop", "should not pass")
                .body(Full::new(Bytes::from(text)))
                .unwrap())
        }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await;
}

/// A TCP server that sends back what it receives until the client stops.
pub async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                while let Ok(count) = stream.read(&mut buffer).await {
                    if count == 0 || stream.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

/// An HTTP proxy that tunnels `CONNECT` and answers a forwarded request itself, recording each
/// request head it receives.
pub struct StubProxy {
    pub address: SocketAddr,
    pub heads: Arc<Mutex<Vec<String>>>,
}

pub async fn stub_proxy() -> StubProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&heads);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Some(head) = read_head(&mut stream).await else {
                    return;
                };
                seen.lock().unwrap().push(head.clone());
                let first = head.lines().next().unwrap_or("").to_owned();
                if let Some(target) = first.strip_prefix("CONNECT ") {
                    let target = target.split(' ').next().unwrap_or("");
                    let Ok(mut upstream) = TcpStream::connect(target).await else {
                        let _ = stream
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
                            .await;
                        return;
                    };
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                } else {
                    let body = format!("stub proxy answered: {first}");
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                }
            });
        }
    });
    StubProxy { address, heads }
}

/// Reads up to the end of a message head.
pub async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// One response read from a stream: the head and the body (by `Content-Length`).
pub async fn read_response(stream: &mut TcpStream) -> (String, String) {
    let head = read_head(stream).await.expect("a response head");
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).await.unwrap();
    (head, String::from_utf8_lossy(&body).into_owned())
}

/// The login every test server asks for.
pub const TEST_USER: &str = "caguax";
pub const TEST_PASSWORD: &str = "test-password";
/// `curl -U` form of the test login.
pub const TEST_LOGIN: &str = "caguax:test-password";

pub fn test_login() -> caguax::Login {
    caguax::Login::new(TEST_USER, TEST_PASSWORD).unwrap()
}

pub fn test_auth() -> caguax::Auth {
    caguax::Auth::Login(test_login())
}

/// Default settings with the test login.
pub fn test_settings() -> caguax::ServerSettings {
    let mut settings = caguax::ServerSettings::default();
    settings.auth = test_auth();
    settings
}

/// The `Proxy-Authorization` header line of the test login, ending in a line break.
pub fn auth_header() -> String {
    format!("Proxy-Authorization: {}\r\n", test_login().header_value())
}

/// Adds the test login after the request line, unless the request carries a login already.
fn with_login(request: &str) -> String {
    if request
        .to_ascii_lowercase()
        .contains("proxy-authorization:")
    {
        return request.to_owned();
    }
    match request.split_once("\r\n") {
        Some((line, rest)) => format!("{line}\r\n{}{rest}", auth_header()),
        None => request.to_owned(),
    }
}

/// One exchange on a fresh connection with the test login: see [`exchange_raw`].
pub async fn exchange(proxy: SocketAddr, request: &str) -> (String, String) {
    exchange_raw(proxy, &with_login(request)).await
}

/// One exchange on a fresh connection: sends `request` as it is, reads to the end.
pub async fn exchange_raw(proxy: SocketAddr, request: &str) -> (String, String) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    // Until the proxy closes, or goes quiet after answering.
    let mut all = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let wait = if all.is_empty() { 20 } else { 2 };
        match tokio::time::timeout(Duration::from_secs(wait), stream.read(&mut chunk)).await {
            Ok(Ok(count)) if count > 0 => all.extend_from_slice(&chunk[..count]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&all).into_owned();
    match text.split_once("\r\n\r\n") {
        Some((head, body)) => (head.to_owned(), body.to_owned()),
        None => (text, String::new()),
    }
}

/// `GET http://target/path` through the proxy on a fresh connection.
pub async fn get_through(proxy: SocketAddr, target: &str, extra: &str) -> (String, String) {
    let (authority, path) = match target.split_once('/') {
        Some((authority, path)) => (authority.to_owned(), format!("/{path}")),
        None => (target.to_owned(), "/".to_owned()),
    };
    exchange(
        proxy,
        &format!(
            "GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\n{extra}Connection: close\r\n\r\n"
        ),
    )
    .await
}

/// Opens a `CONNECT` tunnel to `target`; returns the stream and the proxy's answer head.
pub async fn connect_through(proxy: SocketAddr, target: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{}\r\n",
                auth_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_head(&mut stream).await.expect("an answer to CONNECT");
    (stream, head)
}

pub fn status(head: &str) -> u16 {
    head.split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap()
}

/// An egress through the proxy `text` names that does not exempt loopback destinations, which
/// the resolver otherwise sends direct.
pub fn proxied(text: &str) -> caguax::Egress {
    let rules = coqui_proxy::BypassRules::parse("<-loopback>", coqui_proxy::Dialect::NoProxy);
    caguax::Egress::Resolver(
        coqui_proxy::Resolver::builder()
            .environment(coqui_proxy::Environment::from_pairs(
                Vec::<(String, String)>::new(),
            ))
            .system(false)
            .proxy(text.parse().unwrap())
            .no_proxy(rules)
            .build(),
    )
}

/// An address on loopback that nothing listens on.
pub async fn dead_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// A TCP origin that answers every request `200` and records each request head it receives and
/// each connection it accepts.
pub struct LoggedOrigin {
    pub address: SocketAddr,
    pub heads: Arc<Mutex<Vec<String>>>,
    pub connections: Arc<std::sync::atomic::AtomicUsize>,
}

pub async fn logged_origin() -> LoggedOrigin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (seen, count) = (Arc::clone(&heads), Arc::clone(&connections));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                while let Some(head) = read_head(&mut stream).await {
                    seen.lock().unwrap().push(head);
                    let reply = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
                    if stream.write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    LoggedOrigin {
        address,
        heads,
        connections,
    }
}

/// Collects the messages of the `tracing` events emitted on this thread while it is set.
#[derive(Clone, Default)]
pub struct LogCapture(Arc<Mutex<Vec<String>>>);

impl LogCapture {
    /// Starts capturing on the current thread until the guard drops.
    pub fn start() -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let guard = tracing::subscriber::set_default(capture.clone());
        (capture, guard)
    }

    pub fn messages(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

struct Message<'a>(&'a mut String);

impl tracing::field::Visit for Message<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{value:?}");
        }
    }
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut message = String::new();
        event.record(&mut Message(&mut message));
        self.0.lock().unwrap().push(message);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}
