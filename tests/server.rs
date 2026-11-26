//! The server end to end on loopback: forwarding, `CONNECT`, upstream proxies, TLS routes,
//! interception, tunnels, recording, bounds and lifecycle.

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use caguax::record::{RecordError, Recorder, Sender, Session};
use caguax::{
    Action, Egress, Error, Interceptor, Route, Router, Rule, Server, ServerSettings, Tunnel,
    create_ca,
};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn builder(router: Router) -> caguax::ServerBuilder {
    Server::builder(router).auth(test_auth())
}

async fn plain_server(router: Router) -> Server {
    builder(router).start().await.unwrap()
}

fn rule(pattern: &str, route: impl Into<Route>) -> Rule {
    Rule::parse(pattern, route).unwrap()
}

#[tokio::test]
async fn a_plain_request_is_forwarded_in_origin_form_without_hop_by_hop_headers() {
    let origin = echo_origin(None).await;
    let server = plain_server(Router::new()).await;
    let (head, body) = get_through(
        server.addresses()[0],
        &format!("127.0.0.1:{}/a/b?c=d", origin.port()),
        "Proxy-Connection: keep-alive\r\nX-Keep: yes\r\nKeep-Alive: 5\r\nX-Named: gone\r\nConnection: x-named\r\n",
    )
    .await;
    assert_eq!(status(&head), 200, "{head}");
    assert!(body.starts_with("GET /a/b?c=d\n"), "{body}");
    assert!(
        body.contains(&format!("host: 127.0.0.1:{}", origin.port())),
        "{body}"
    );
    assert!(body.contains("x-keep: yes"), "{body}");
    for hidden in [
        "proxy-connection",
        "proxy-authorization",
        "keep-alive",
        "x-named",
        TEST_PASSWORD,
    ] {
        assert!(
            !body.to_lowercase().contains(hidden),
            "{hidden} reached the origin: {body}"
        );
    }
    let lower = head.to_lowercase();
    assert!(lower.contains("x-origin: echo"), "{head}");
    assert!(
        !lower.contains("x-hop"),
        "a header the origin named in Connection is dropped: {head}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn one_client_connection_carries_several_requests_each_routed_on_its_own() {
    let allowed = echo_origin(None).await;
    let router = Router::builder()
        .rule(rule(
            &format!("127.0.0.1:{}", allowed.port() + 1),
            Route::reject(),
        ))
        .build();
    let server = plain_server(router).await;
    let mut stream = TcpStream::connect(server.addresses()[0]).await.unwrap();
    for path in ["/one", "/two"] {
        stream
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}{path} HTTP/1.1\r\nHost: x\r\n{}\r\n",
                    allowed.port(),
                    auth_header()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (head, body) = read_response(&mut stream).await;
        assert_eq!(status(&head), 200, "{head}");
        assert!(body.starts_with(&format!("GET {path}\n")), "{body}");
    }
    let rejected = allowed.port() + 1;
    stream
        .write_all(
            format!(
                "GET http://127.0.0.1:{rejected}/ HTTP/1.1\r\nHost: x\r\n{}\r\n",
                auth_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (head, body) = read_response(&mut stream).await;
    assert_eq!(status(&head), 403, "{head}");
    assert!(body.contains("is not allowed"));
    server.shutdown().await;
}

#[cfg(feature = "regex")]
#[tokio::test]
async fn a_path_rule_decides_a_forwarded_request() {
    let origin = echo_origin(None).await;
    let router = Router::builder()
        .rule(Rule::new(
            caguax::Matcher::path("^/private/").unwrap(),
            Route::reject(),
        ))
        .build();
    let server = plain_server(router).await;
    let target = |path: &str| format!("127.0.0.1:{}{path}", origin.port());
    let (head, _) = get_through(server.addresses()[0], &target("/private/x"), "").await;
    assert_eq!(status(&head), 403);
    let (head, _) = get_through(server.addresses()[0], &target("/public/x"), "").await;
    assert_eq!(status(&head), 200);
    server.shutdown().await;
}

#[tokio::test]
async fn connect_tunnels_bytes_both_ways_and_passes_half_closes() {
    let echo = tcp_echo().await;
    let server = plain_server(Router::new()).await;
    let (mut stream, head) = connect_through(server.addresses()[0], &echo.to_string()).await;
    assert_eq!(status(&head), 200, "{head}");
    stream.write_all(b"hello through the tunnel").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    assert_eq!(answer, b"hello through the tunnel");
    server.shutdown().await;
}

#[tokio::test]
async fn a_rejected_connect_is_403_and_an_unreachable_destination_502_listing_each_attempt() {
    let dead = dead_address().await;
    let router = Router::builder()
        .rule(rule("blocked.example", Route::reject().name("block")))
        .build();
    let server = plain_server(router).await;
    let (_, head) = connect_through(server.addresses()[0], "blocked.example:443").await;
    assert_eq!(status(&head), 403, "{head}");
    let (_, head) = connect_through(server.addresses()[0], &dead.to_string()).await;
    assert_eq!(status(&head), 502, "{head}");
    let (head, body) = get_through(server.addresses()[0], &dead.to_string(), "").await;
    assert_eq!(status(&head), 502, "{head}");
    assert!(
        body.contains("cannot reach") && body.contains("direct:"),
        "{body}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn the_pac_file_and_other_local_paths() {
    let router = Router::builder()
        .rule(rule("*.corp.example", Route::reject()))
        .build();
    let server = plain_server(router).await;
    let proxy = server.addresses()[0];
    let (head, body) = exchange(
        proxy,
        "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&head), 200, "{head}");
    assert!(
        head.to_lowercase()
            .contains("application/x-ns-proxy-autoconfig")
    );
    assert!(
        body.contains("FindProxyForURL") && body.contains(&proxy.to_string()),
        "{body}"
    );
    let (head, _) = exchange(
        proxy,
        "GET /other HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&head), 404);
    let (head, _) = exchange(
        proxy,
        "POST /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&head), 404);
    server.shutdown().await;
}

#[tokio::test]
async fn upgrades_are_relayed() {
    let origin = echo_origin(None).await;
    let server = plain_server(Router::new()).await;
    let mut stream = TcpStream::connect(server.addresses()[0]).await.unwrap();
    stream
        .write_all(
            format!(
                "GET http://127.0.0.1:{}/upgrade HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: echo\r\n{}\r\n",
                origin.port(),
                auth_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_head(&mut stream).await.unwrap();
    assert_eq!(status(&head), 101, "{head}");
    stream.write_all(b"ping").await.unwrap();
    let mut answer = [0_u8; 4];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"ping");
    server.shutdown().await;
}

#[tokio::test]
async fn a_malformed_request_is_400() {
    let server = plain_server(Router::new()).await;
    let (head, _) = exchange(
        server.addresses()[0],
        "GET / HTTP/1.1\r\nBad Header Line\r\n\r\n",
    )
    .await;
    assert_eq!(status(&head), 400, "{head}");
    let (head, _) = exchange(
        server.addresses()[0],
        "GET http://a.example:notaport/ HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await;
    assert_eq!(status(&head), 400, "{head}");
    server.shutdown().await;
}

#[tokio::test]
async fn an_upstream_http_proxy_gets_connect_with_basic_and_absolute_form_for_plain_http() {
    let origin = echo_origin(None).await;
    let echo = tcp_echo().await;
    let stub = stub_proxy().await;
    let mut settings = test_settings();
    settings.egress = Some(proxied(&format!("http://user:s3cret@{}", stub.address)));
    let server = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap();
    let proxy = server.addresses()[0];

    let (mut stream, head) = connect_through(proxy, &echo.to_string()).await;
    assert_eq!(status(&head), 200, "{head}");
    stream.write_all(b"via upstream").await.unwrap();
    let mut answer = [0_u8; 12];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"via upstream");

    let (head, body) = get_through(proxy, &format!("127.0.0.1:{}/x", origin.port()), "").await;
    assert_eq!(status(&head), 200, "{head}");
    assert!(
        body.contains(&format!(
            "stub proxy answered: GET http://127.0.0.1:{}/x",
            origin.port()
        )),
        "{body}"
    );
    let heads = stub.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 2, "{heads:?}");
    for head in &heads {
        assert!(
            head.to_lowercase()
                .contains(&"proxy-authorization: Basic dXNlcjpzM2NyZXQ=".to_lowercase()),
            "{head}"
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn a_pac_result_fails_over_to_the_next_answer_and_errors_never_show_credentials() {
    let echo = tcp_echo().await;
    let dead = dead_address().await;
    let route = Route::direct()
        .upstream(proxied(&format!("PROXY {dead}; DIRECT")))
        .build();
    let router = Router::builder().rule(rule("127.0.0.1", route)).build();
    let server = plain_server(router).await;
    let (mut stream, head) = connect_through(server.addresses()[0], &echo.to_string()).await;
    assert_eq!(status(&head), 200, "{head}");
    stream.write_all(b"ok").await.unwrap();
    let mut answer = [0_u8; 2];
    stream.read_exact(&mut answer).await.unwrap();
    server.shutdown().await;

    let only_dead = Route::direct()
        .upstream(proxied(&format!("http://user:topsecret@{dead}")))
        .build();
    let router = Router::builder().rule(rule("127.0.0.1", only_dead)).build();
    let server = plain_server(router).await;
    let (_, head) = connect_through(server.addresses()[0], &echo.to_string()).await;
    assert_eq!(status(&head), 502, "{head}");
    let (head, body) = get_through(server.addresses()[0], &echo.to_string(), "").await;
    assert_eq!(status(&head), 502);
    assert!(
        body.contains("http://127.0.0.1:") && !body.contains("topsecret"),
        "{body}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_tls_route_upgrades_plain_http_with_the_client_certificate() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(true))).await;
    let credential = Arc::new(pki.credential("client-ec"));
    let route = Route::with_tls(credential).name("corp").build();
    let router = Router::builder().rule(rule("127.0.0.1", route)).build();
    let server = plain_server(router).await;
    let (head, body) = get_through(
        server.addresses()[0],
        &format!("127.0.0.1:{}/secure", origin.port()),
        "",
    )
    .await;
    assert_eq!(status(&head), 200, "{head} {body}");
    assert!(body.starts_with("GET /secure\n"), "{body}");
    assert!(body.contains("client-subject: CN=client-ec"), "{body}");
    // The credential verifies the origin against the CA; a destination it does not trust fails.
    let other = echo_origin(Some(Pki::new().server_config(false))).await;
    let (head, body) = get_through(
        server.addresses()[0],
        &format!("127.0.0.1:{}/", other.port()),
        "",
    )
    .await;
    assert_eq!(status(&head), 502, "{head}");
    assert!(body.contains("TLS to"), "{body}");
    server.shutdown().await;
}

#[tokio::test]
async fn a_connect_to_a_tls_route_is_intercepted_with_a_minted_certificate() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(true))).await;
    let route = Route::with_tls(Arc::new(pki.credential("client-rsa"))).build();
    let router = Router::builder().rule(rule("127.0.0.1", route)).build();
    let ca = create_ca(&router, Default::default()).unwrap();
    let ca_der = ca.certificate_der().clone();
    let server = builder(router).ca(ca).unwrap().start().await.unwrap();
    let (stream, head) = connect_through(
        server.addresses()[0],
        &format!("127.0.0.1:{}", origin.port()),
    )
    .await;
    assert_eq!(status(&head), 200, "{head}");
    let trust = coqui_sslcontext::Trust::Roots(vec![ca_der]);
    let config = coqui_sslcontext::Tls::builder()
        .trust(trust)
        .alpn([b"http/1.1".to_vec()])
        .client_certificates(coqui_sslcontext::ClientCertificates::None)
        .build()
        .unwrap()
        .client_config("127.0.0.1")
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(config)
        .connect(name, stream)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    tls.write_all(b"GET /inside HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    tls.read_to_string(&mut answer).await.ok();
    assert!(answer.contains("GET /inside"), "{answer}");
    assert!(answer.contains("client-subject: CN=client-rsa"), "{answer}");
    server.shutdown().await;
}

#[tokio::test]
async fn interception_needs_a_ca_and_the_origin_is_tried_before_the_client_is_answered() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(false))).await;
    let route = Route::with_tls(Arc::new(pki.credential("c"))).build();
    let router = Router::builder().rule(rule("127.0.0.1", route)).build();
    let server = plain_server(router).await;
    let (_, head) = connect_through(
        server.addresses()[0],
        &format!("127.0.0.1:{}", origin.port()),
    )
    .await;
    assert_eq!(status(&head), 502, "{head}");
    server.shutdown().await;

    let route = Route::with_tls(Arc::new(pki.credential("c"))).build();
    let router = Router::builder().rule(rule("127.0.0.1", route)).build();
    let ca = create_ca(&router, Default::default()).unwrap();
    let server = builder(router).ca(ca).unwrap().start().await.unwrap();
    let dead = dead_address().await;
    let (_, head) = connect_through(server.addresses()[0], &dead.to_string()).await;
    assert_eq!(
        status(&head),
        502,
        "no 200 before the origin answers: {head}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_tunnel_gives_a_plain_tcp_client_mutual_tls_to_its_target() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(true))).await;
    let route = Route::with_tls(Arc::new(pki.credential("tunnel-client"))).build();
    let tunnel = Tunnel::builder("127.0.0.1:0", &format!("127.0.0.1:{}", origin.port()))
        .unwrap()
        .route(route)
        .allow_any_local(true)
        .build();
    let server = builder(Router::new())
        .listen([])
        .tunnel(tunnel.clone())
        .start()
        .await
        .unwrap();
    assert!(server.addresses().is_empty());
    let address = server.tunnel_address(&tunnel).unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET /via-tunnel HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    assert!(answer.contains("GET /via-tunnel"), "{answer}");
    assert!(
        answer.contains("client-subject: CN=tunnel-client"),
        "{answer}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn a_rejecting_tunnel_closes_the_connection() {
    let echo = tcp_echo().await;
    let tunnel = Tunnel::builder("127.0.0.1:0", &echo.to_string())
        .unwrap()
        .route(Route::reject())
        .build();
    let server = builder(Router::new())
        .tunnel(tunnel.clone())
        .start()
        .await
        .unwrap();
    let mut stream = TcpStream::connect(server.tunnel_address(&tunnel).unwrap())
        .await
        .unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.ok();
    assert!(answer.is_empty());
    assert_eq!(tunnel.name(), format!("tunnel:{echo}"));
    server.shutdown().await;
}

#[derive(Default)]
struct Collect {
    events: Mutex<Vec<String>>,
    client: Mutex<Vec<u8>>,
    server: Mutex<Vec<u8>>,
}

struct Shared(Arc<Collect>);

impl Recorder for Shared {
    fn opened(&self, session: &Session) -> Result<(), RecordError> {
        self.0
            .events
            .lock()
            .unwrap()
            .push(format!("opened {}", session.connection().authority()));
        Ok(())
    }

    fn data(&self, _: &Session, sender: Sender, data: &[u8]) -> Result<(), RecordError> {
        match sender {
            Sender::Client => self.0.client.lock().unwrap().extend_from_slice(data),
            Sender::Server => self.0.server.lock().unwrap().extend_from_slice(data),
        }
        Ok(())
    }

    fn ended(&self, _: &Session, sender: Sender) -> Result<(), RecordError> {
        self.0
            .events
            .lock()
            .unwrap()
            .push(format!("ended {}", sender.as_str()));
        Ok(())
    }

    fn closed(&self, _: &Session) -> Result<(), RecordError> {
        self.0.events.lock().unwrap().push("closed".into());
        Ok(())
    }
}

struct Failing;

impl Recorder for Failing {
    fn data(&self, _: &Session, _: Sender, _: &[u8]) -> Result<(), RecordError> {
        Err(RecordError::new("always fails"))
    }
}

async fn eventually(check: impl Fn() -> bool) {
    for _ in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the condition never held");
}

#[tokio::test]
async fn recorders_see_the_rewritten_heads_and_a_failing_one_changes_nothing() {
    let origin = echo_origin(None).await;
    let collected = Arc::new(Collect::default());
    let server = builder(Router::new())
        .recorder(Shared(Arc::clone(&collected)))
        .recorder(Failing)
        .start()
        .await
        .unwrap();
    let (head, _) = get_through(
        server.addresses()[0],
        &format!("127.0.0.1:{}/rec", origin.port()),
        "",
    )
    .await;
    assert_eq!(status(&head), 200);
    eventually(|| {
        collected
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "closed")
    })
    .await;
    let sent = String::from_utf8_lossy(&collected.client.lock().unwrap()).into_owned();
    assert!(sent.starts_with("GET /rec HTTP/1.1"), "{sent}");
    let received = String::from_utf8_lossy(&collected.server.lock().unwrap()).into_owned();
    assert!(received.starts_with("HTTP/1.1 200"), "{received}");
    let events = collected.events.lock().unwrap().clone();
    assert!(events[0].starts_with("opened 127.0.0.1:"), "{events:?}");
    assert_eq!(events.iter().filter(|event| *event == "closed").count(), 1);

    let echo = tcp_echo().await;
    let (mut stream, _) = connect_through(server.addresses()[0], &echo.to_string()).await;
    stream.write_all(b"tunnelled bytes").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    eventually(|| {
        collected
            .client
            .lock()
            .unwrap()
            .ends_with(b"tunnelled bytes")
    })
    .await;
    server.shutdown().await;
}

#[cfg(feature = "pcap")]
#[tokio::test]
async fn a_capture_file_holds_each_session_as_a_tcp_flow() {
    use pcap_file::pcap::PcapReader;
    let origin = echo_origin(None).await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("proxy.pcap");
    let mut settings = test_settings();
    settings.record = Some(path.clone());
    let server = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap();
    let (head, _) = get_through(
        server.addresses()[0],
        &format!("127.0.0.1:{}/capture", origin.port()),
        "",
    )
    .await;
    assert_eq!(status(&head), 200);
    server.shutdown().await;
    eventually(|| {
        std::fs::metadata(&path)
            .map(|meta| meta.len() > 100)
            .unwrap_or(false)
    })
    .await;
    let mut reader = PcapReader::new(std::fs::File::open(&path).unwrap()).unwrap();
    let mut payloads = String::new();
    let mut packets = 0;
    while let Some(packet) = reader.next_packet() {
        let packet = packet.unwrap();
        packets += 1;
        // Ethernet 14, IPv4 20, TCP 20.
        payloads.push_str(&String::from_utf8_lossy(
            &packet.data()[54.min(packet.data().len())..],
        ));
    }
    assert!(packets >= 6, "{packets}");
    assert!(payloads.contains("GET /capture HTTP/1.1"), "{payloads}");
    assert!(payloads.contains("HTTP/1.1 200"), "{payloads}");
}

#[tokio::test]
async fn bounds_are_settings() {
    let echo = tcp_echo().await;
    let mut settings = test_settings();
    settings.max_connections = 1;
    settings.max_head_bytes = 8192;
    settings.idle_timeout = Some(Duration::from_millis(300));
    let server = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap();
    let proxy = server.addresses()[0];

    let (mut first, head) = connect_through(proxy, &echo.to_string()).await;
    assert_eq!(status(&head), 200);
    // The second connection finds no room and is closed without an answer.
    let mut second = TcpStream::connect(proxy).await.unwrap();
    second
        .write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), second.read_to_end(&mut answer)).await;
    assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
    // A silent tunnel ends after idle_timeout.
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(10), first.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the idle tunnel was not ended");
    drop(first);
    // With room again, an oversize request head is refused.
    eventually_accepts(proxy).await;
    let big = format!(
        "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: {}\r\n\r\n",
        "a".repeat(20_000)
    );
    let (head, _) = exchange(proxy, &big).await;
    assert!(head.is_empty() || status(&head) >= 400, "{head}");
    server.shutdown().await;
}

async fn eventually_accepts(proxy: SocketAddr) {
    for _ in 0..100 {
        let (head, _) = exchange(
            proxy,
            "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await;
        if head.starts_with("HTTP/1.1 200") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the server never made room");
}

#[tokio::test]
async fn listening_beyond_loopback_needs_allow_remote_and_is_reported() {
    let mut settings = test_settings();
    settings.listen = vec!["0.0.0.0:0".parse().unwrap()];
    let refused = builder(Router::new())
        .settings(settings.clone())
        .start()
        .await
        .unwrap_err();
    assert!(matches!(refused, Error::Config(_)), "{refused}");
    assert!(refused.to_string().contains("allow_remote"));
    let tunnel = Tunnel::builder("0.0.0.0:0", "127.0.0.1:9").unwrap().build();
    let refused = builder(Router::new())
        .tunnel(tunnel)
        .start()
        .await
        .unwrap_err();
    assert!(matches!(refused, Error::Config(_)));
    settings.allow_remote = true;
    let server = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap();
    assert!(
        server
            .non_defaults()
            .iter()
            .any(|entry| entry.contains("allow_remote"))
    );
    server.shutdown().await;
}

#[tokio::test]
async fn an_address_in_use_is_an_io_error_and_meaningless_settings_are_config_errors() {
    let first = plain_server(Router::new()).await;
    let mut settings = test_settings();
    settings.listen = vec![first.addresses()[0].into()];
    let error = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Io(_)), "{error}");
    first.shutdown().await;
    let mut settings = test_settings();
    settings.max_connections = 0;
    let error = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Config(_)));
}

#[tokio::test]
async fn shutdown_stops_listening_and_ends_connections() {
    let echo = tcp_echo().await;
    let server = plain_server(Router::new()).await;
    let proxy = server.addresses()[0];
    let (mut stream, _) = connect_through(proxy, &echo.to_string()).await;
    server.shutdown().await;
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the tunnel outlived the server");
    assert!(
        TcpStream::connect(proxy).await.is_err(),
        "the port still accepts"
    );
}

#[tokio::test]
async fn a_reload_swaps_the_router_and_a_failing_one_leaves_the_running_state() {
    let origin = echo_origin(None).await;
    let router = Router::builder().default_route(Route::reject()).build();
    let server = plain_server(router).await;
    let target = format!("127.0.0.1:{}/r", origin.port());
    let (head, _) = get_through(server.addresses()[0], &target, "").await;
    assert_eq!(status(&head), 403);
    server
        .reload(server.settings(), Router::new())
        .await
        .unwrap();
    let (head, _) = get_through(server.addresses()[0], &target, "").await;
    assert_eq!(status(&head), 200);

    let mut changed = server.settings();
    changed.listen = vec!["127.0.0.1:1".parse().unwrap()];
    let error = server
        .reload(
            changed,
            Router::builder().default_route(Route::reject()).build(),
        )
        .await;
    assert!(matches!(error, Err(Error::Config(_))));
    let mut broken = server.settings();
    broken.keylog = Some("/nonexistent-directory-for-caguax/keys.log".into());
    let error = server
        .reload(
            broken,
            Router::builder().default_route(Route::reject()).build(),
        )
        .await;
    assert!(error.is_err());
    let (head, _) = get_through(server.addresses()[0], &target, "").await;
    assert_eq!(status(&head), 200, "the running state stays");
    server.shutdown().await;
}

#[tokio::test]
async fn a_key_log_receives_the_secrets_of_the_tls_the_proxy_makes() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(false))).await;
    let directory = tempfile::tempdir().unwrap();
    let keylog = directory.path().join("keys.log");
    let route = Route::with_tls(Arc::new(pki.credential("c"))).build();
    let router = Router::builder().rule(rule("127.0.0.1", route)).build();
    let mut settings = test_settings();
    settings.keylog = Some(keylog.clone());
    let server = builder(router).settings(settings).start().await.unwrap();
    assert!(
        server
            .non_defaults()
            .iter()
            .any(|entry| entry.contains("keylog"))
    );
    let (head, _) = get_through(
        server.addresses()[0],
        &format!("127.0.0.1:{}/", origin.port()),
        "",
    )
    .await;
    assert_eq!(status(&head), 200);
    let text = std::fs::read_to_string(&keylog).unwrap();
    assert!(
        text.lines().any(|line| line.split(' ').count() == 3),
        "{text}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn an_environment_resolver_is_an_egress() {
    let echo = tcp_echo().await;
    let stub = stub_proxy().await;
    let resolver = coqui_proxy::Resolver::builder()
        .environment(coqui_proxy::Environment::from_pairs([
            ("https_proxy", format!("http://{}", stub.address)),
            ("no_proxy", "<-loopback>".to_owned()),
        ]))
        .system(false)
        .build();
    let mut settings = test_settings();
    settings.egress = Some(Egress::Resolver(resolver));
    let server = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap();
    let (_, head) = connect_through(server.addresses()[0], &echo.to_string()).await;
    assert_eq!(status(&head), 200);
    assert_eq!(stub.heads.lock().unwrap().len(), 1);
    server.shutdown().await;
}

#[test]
fn the_blocking_server_runs_on_its_own_runtime() {
    let server = caguax::blocking::Server::builder(Router::new())
        .with(|builder| builder.auth(test_auth()))
        .start()
        .unwrap();
    let proxy = server.addresses()[0];
    assert_eq!(server.port(), proxy.port());
    let mut stream = std::net::TcpStream::connect(proxy).unwrap();
    std::io::Write::write_all(
        &mut stream,
        format!(
            "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Connection: close\r\n\r\n",
            auth_header()
        )
        .as_bytes(),
    )
    .unwrap();
    let mut answer = String::new();
    std::io::Read::read_to_string(&mut stream, &mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    server.shutdown();
    assert!(std::net::TcpStream::connect(proxy).is_err());
}

#[tokio::test]
async fn a_custom_router_and_interceptor_work_through_the_traits() {
    struct RejectEverything;
    impl caguax::Routing for RejectEverything {
        fn route(&self, _: &caguax::Connection) -> Route {
            Route::reject().name("all").build()
        }
    }
    let server = Server::builder(RejectEverything)
        .auth(test_auth())
        .start()
        .await
        .unwrap();
    let (_, head) = connect_through(server.addresses()[0], "a.example:443").await;
    assert_eq!(status(&head), 403);
    let (head, _) = exchange(
        server.addresses()[0],
        "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&head),
        404,
        "a router that is not a Router has no PAC form"
    );
    assert_eq!(
        server
            .router()
            .route(&caguax::Connection::new("a.example", 1).unwrap())
            .action(),
        Action::Reject
    );
    let _ = Interceptor::new;
    server.shutdown().await;
}

#[tokio::test]
async fn a_request_without_the_listener_credential_gets_407_and_never_reaches_the_origin() {
    let origin = logged_origin().await;
    let server = Server::direct().start().await.unwrap();
    let proxy = server.addresses()[0];
    let target = format!("127.0.0.1:{}", origin.address.port());

    let (head, _) = exchange(
        proxy,
        &format!("GET http://{target}/x HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&head), 407, "{head}");
    let lower = head.to_lowercase();
    assert!(lower.contains("proxy-authenticate: basic"), "{head}");
    assert!(lower.contains("connection: close"), "{head}");

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let answer = read_head(&mut stream).await.unwrap();
    assert_eq!(status(&answer), 407, "{answer}");

    assert!(origin.heads.lock().unwrap().is_empty());
    assert_eq!(
        origin.connections.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    server.shutdown().await;
}

#[tokio::test]
async fn the_generated_login_passes_where_a_wrong_one_does_not_and_a_reload_keeps_it() {
    let origin = logged_origin().await;
    let server = Server::direct().start().await.unwrap();
    let proxy = server.addresses()[0];
    let login = server.proxy_login().expect("a generated login");
    assert_eq!(login.user(), "caguax");
    assert!(login.password().len() >= 32);
    let target = format!("127.0.0.1:{}", origin.address.port());
    let get = |header: String| {
        format!(
            "GET http://{target}/x HTTP/1.1\r\nHost: {target}\r\n{header}Connection: close\r\n\r\n"
        )
    };

    let wrong = caguax::Login::new("caguax", "not-the-password").unwrap();
    let (head, _) = exchange_raw(
        proxy,
        &get(format!("Proxy-Authorization: {}\r\n", wrong.header_value())),
    )
    .await;
    assert_eq!(status(&head), 407, "{head}");
    assert!(origin.heads.lock().unwrap().is_empty());

    // Positive control: the same request with the login reaches the origin.
    let with_login = get(format!("Proxy-Authorization: {}\r\n", login.header_value()));
    let (head, _) = exchange_raw(proxy, &with_login).await;
    assert_eq!(status(&head), 200, "{head}");
    assert_eq!(origin.heads.lock().unwrap().len(), 1);
    // The scheme name is case-insensitive.
    let lower = with_login.replace("Basic ", "basic ");
    let (head, _) = exchange_raw(proxy, &lower).await;
    assert_eq!(status(&head), 200, "{head}");

    // A CONNECT with the login opens the tunnel (the origin sees a connection).
    let before = origin.connections.load(std::sync::atomic::Ordering::SeqCst);
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\n\r\n",
                login.header_value()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let answer = read_head(&mut stream).await.unwrap();
    assert_eq!(status(&answer), 200, "{answer}");
    assert_eq!(
        origin.connections.load(std::sync::atomic::Ordering::SeqCst),
        before + 1
    );

    // A reload with the default settings keeps the generated login.
    server
        .reload(ServerSettings::default(), Router::new())
        .await
        .unwrap();
    assert_eq!(server.proxy_login().unwrap().password(), login.password());
    server.shutdown().await;
}

#[tokio::test]
async fn auth_none_lets_requests_through_and_is_listed() {
    let origin = logged_origin().await;
    let server = builder(Router::new())
        .auth(caguax::Auth::None)
        .start()
        .await
        .unwrap();
    let target = format!("127.0.0.1:{}", origin.address.port());
    let (head, _) = exchange_raw(
        server.addresses()[0],
        &format!("GET http://{target}/x HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&head), 200, "{head}");
    assert!(server.proxy_login().is_none());
    assert!(
        server
            .non_defaults()
            .iter()
            .any(|entry| entry == "server.auth = none"),
        "{:?}",
        server.non_defaults()
    );
    server.shutdown().await;

    // The strict default lists nothing about the login.
    let strict = Server::direct().start().await.unwrap();
    assert!(
        strict
            .non_defaults()
            .iter()
            .all(|entry| !entry.contains("auth"))
    );
    strict.shutdown().await;
}

#[tokio::test]
async fn a_password_file_names_the_login_and_an_unreadable_one_is_a_config_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("password");
    std::fs::write(&path, "from-a-file\nsecond line\n").unwrap();
    let auth = caguax::Auth::File {
        user: "alice".into(),
        path: path.clone(),
    };
    let server = Server::direct().auth(auth).start().await.unwrap();
    let login = server.proxy_login().unwrap();
    assert_eq!((login.user(), login.password()), ("alice", "from-a-file"));
    let (head, _) = exchange(
        server.addresses()[0],
        &format!(
            "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",
            login.header_value()
        ),
    )
    .await;
    assert_eq!(status(&head), 200, "{head}");
    server.shutdown().await;

    let missing = caguax::Auth::File {
        user: "alice".into(),
        path: directory.path().join("absent"),
    };
    let error = Server::direct().auth(missing).start().await.unwrap_err();
    assert!(matches!(error, Error::Config(_)), "{error}");
}

#[cfg(unix)]
#[tokio::test]
async fn the_generated_login_file_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested").join("caguax.auth");
    let auth = caguax::Auth::Generated {
        user: "caguax".into(),
        file: Some(path.clone()),
    };
    let server = Server::direct().auth(auth).start().await.unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.trim_end(), server.proxy_login().unwrap().userinfo());
    server.shutdown().await;
}

#[tokio::test]
async fn a_silent_connection_is_ended_by_the_default_idle_timeout_that_none_would_remove() {
    assert_eq!(
        ServerSettings::default().idle_timeout,
        Some(ServerSettings::DEFAULT_IDLE_TIMEOUT)
    );
    let echo = tcp_echo().await;
    let tunnel = Tunnel::builder("127.0.0.1:0", &echo.to_string())
        .unwrap()
        .build();
    let mut settings = test_settings();
    settings.idle_timeout = Some(Duration::from_millis(200));
    let server = builder(Router::new())
        .settings(settings)
        .tunnel(tunnel.clone())
        .start()
        .await
        .unwrap();
    let mut stream = TcpStream::connect(server.tunnel_address(&tunnel).unwrap())
        .await
        .unwrap();
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the silent tunnel connection was not ended");
    assert!(
        server
            .non_defaults()
            .iter()
            .all(|entry| !entry.contains("idle_timeout"))
    );
    server.shutdown().await;

    let mut settings = test_settings();
    settings.idle_timeout = None;
    assert!(
        settings
            .non_defaults()
            .iter()
            .any(|entry| entry == "server.idle_timeout = none")
    );
}

#[tokio::test]
async fn a_tunnel_with_a_credential_route_needs_allow_any_local() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(true))).await;
    let target = format!("127.0.0.1:{}", origin.port());
    let route = Route::with_tls(Arc::new(pki.credential("tunnel-client"))).build();
    let plain = || {
        Tunnel::builder("127.0.0.1:0", &target)
            .unwrap()
            .route(route.clone())
    };

    let refused = builder(Router::new())
        .tunnel(plain().build())
        .start()
        .await
        .unwrap_err();
    assert!(matches!(refused, Error::Config(_)), "{refused}");
    assert!(refused.to_string().contains("allow_any_local"), "{refused}");

    let allowed = plain().name("db").allow_any_local(true).build();
    let server = builder(Router::new())
        .tunnel(allowed)
        .start()
        .await
        .unwrap();
    assert!(
        server
            .non_defaults()
            .iter()
            .any(|entry| entry == "tunnels.db.allow_any_local = true"),
        "{:?}",
        server.non_defaults()
    );
    server.shutdown().await;

    // A tunnel with no credential in its route needs no opt-in.
    let echo = tcp_echo().await;
    let open = Tunnel::builder("127.0.0.1:0", &echo.to_string())
        .unwrap()
        .build();
    let server = builder(Router::new()).tunnel(open).start().await.unwrap();
    assert!(
        server.non_defaults().is_empty(),
        "{:?}",
        server.non_defaults()
    );
    server.shutdown().await;
}

#[test]
fn a_capture_file_and_an_unencrypted_ca_key_are_listed_as_non_defaults() {
    let mut settings = test_settings();
    assert!(settings.non_defaults().is_empty());
    settings.record = Some("traffic.pcap".into());
    settings.ca.certificate = Some("ca.pem".into());
    settings.ca.key = Some("ca.key".into());
    let listed = settings.non_defaults();
    assert!(
        listed
            .iter()
            .any(|entry| entry.starts_with("server.record")),
        "{listed:?}"
    );
    assert!(
        listed
            .iter()
            .any(|entry| entry.starts_with("server.ca.key = unencrypted")),
        "{listed:?}"
    );
    settings.ca.password_env = Some("CA_PASSWORD".into());
    assert!(
        settings
            .non_defaults()
            .iter()
            .all(|entry| !entry.starts_with("server.ca.key")),
        "an encrypted key is not listed"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn the_key_log_and_the_capture_file_are_created_readable_by_their_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let directory = tempfile::tempdir().unwrap();
    let keylog = directory.path().join("keys.log");
    let mut settings = test_settings();
    settings.keylog = Some(keylog.clone());
    #[cfg(feature = "pcap")]
    let capture = {
        let capture = directory.path().join("traffic.pcap");
        settings.record = Some(capture.clone());
        capture
    };
    let server = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap();
    assert_eq!(mode(&keylog), 0o600, "{:o}", mode(&keylog));
    #[cfg(feature = "pcap")]
    assert_eq!(mode(&capture), 0o600, "{:o}", mode(&capture));
    server.shutdown().await;

    // A file that exists keeps its mode: the server warns and does not change it.
    let existing = directory.path().join("old.log");
    std::fs::write(&existing, "").unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut settings = test_settings();
    settings.keylog = Some(existing.clone());
    let server = builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap();
    assert_eq!(mode(&existing), 0o644);
    server.shutdown().await;
}

#[tokio::test]
async fn a_reload_logs_every_non_default_it_loosened() {
    let directory = tempfile::tempdir().unwrap();
    let server = builder(Router::new()).start().await.unwrap();
    assert!(server.non_defaults().is_empty());

    let mut loosened = test_settings();
    loosened.keylog = Some(directory.path().join("keys.log"));
    loosened.auth = caguax::Auth::None;
    let (logs, guard) = LogCapture::start();
    server.reload(loosened, Router::new()).await.unwrap();
    drop(guard);
    let messages = logs.messages();
    for expected in [
        "non-default setting: server.keylog = (a file of TLS secrets)",
        "non-default setting: server.auth = none",
    ] {
        assert!(messages.iter().any(|line| line == expected), "{messages:?}");
    }

    // A reload that fails changes nothing and logs no non-default.
    let mut broken = test_settings();
    broken.max_headers = 0;
    let (logs, guard) = LogCapture::start();
    assert!(server.reload(broken, Router::new()).await.is_err());
    drop(guard);
    assert!(
        logs.messages()
            .iter()
            .all(|line| !line.starts_with("non-default")),
        "{:?}",
        logs.messages()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn the_pac_file_is_served_only_to_a_host_that_names_the_listener() {
    let router = Router::builder()
        .rule(rule("*.corp.internal.example", Route::reject()))
        .build();
    let mut settings = test_settings();
    settings.pac_hosts = vec!["Pac.Corp.Example".into()];
    let server = builder(router).settings(settings).start().await.unwrap();
    let proxy = server.addresses()[0];
    let get = |host: String| {
        let request =
            format!("GET /proxy.pac HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        async move { exchange(proxy, &request).await }
    };

    // A page that rebinds a name to the proxy's port sends its own name as Host.
    let (head, body) = get(format!("rebind.example:{}", proxy.port())).await;
    assert_eq!(status(&head), 421, "{head}");
    assert!(
        !body.contains("FindProxyForURL") && !body.contains("internal"),
        "{body}"
    );
    let (head, _) = get("rebind.example".into()).await;
    assert_eq!(status(&head), 421, "{head}");

    // The positive controls: an IP literal, localhost, and a name the operator listed.
    for host in [
        format!("127.0.0.1:{}", proxy.port()),
        "127.0.0.1".into(),
        format!("localhost:{}", proxy.port()),
        "LocalHost".into(),
        format!("pac.corp.example:{}", proxy.port()),
    ] {
        let (head, body) = get(host.clone()).await;
        assert_eq!(status(&head), 200, "{host}: {head}");
        assert!(body.contains("FindProxyForURL"), "{host}: {body}");
    }
    assert!(
        server
            .non_defaults()
            .iter()
            .any(|entry| entry.starts_with("server.pac_hosts")),
        "{:?}",
        server.non_defaults()
    );
    server.shutdown().await;
}
