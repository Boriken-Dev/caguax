//! Real peers: `curl` as the client and `squid` as an upstream proxy. Both are opt-in: the tests
//! are ignored, and run with `CAGUAX_TEST_CURL=1` or `CAGUAX_TEST_SQUID=1` (and
//! `-- --include-ignored`). Nothing is installed by the tests.

mod support;

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;

use caguax::{Route, Router, Rule, Server, ServerSettings};
use support::*;

fn enabled(variable: &str) -> bool {
    std::env::var_os(variable).is_some_and(|value| !value.is_empty() && value != "0")
}

fn curl(arguments: Vec<String>) -> (bool, String) {
    let program = if cfg!(windows) { "curl.exe" } else { "curl" };
    let mut command = Command::new(program);
    command.args(["--silent", "--show-error", "--max-time", "30"]);
    if cfg!(windows) {
        // Windows' TLS library asks a revocation service about our test CA, which has none.
        command.arg("--ssl-no-revoke");
    }
    let output = command
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("curl is installed when CAGUAX_TEST_CURL is set");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr),
    )
}

async fn run_curl(arguments: Vec<String>) -> (bool, String) {
    tokio::task::spawn_blocking(move || curl(arguments))
        .await
        .unwrap()
}

fn text(path: &std::path::Path) -> String {
    path.to_str().unwrap().to_owned()
}

#[tokio::test]
#[ignore = "needs curl; set CAGUAX_TEST_CURL=1"]
async fn curl_through_the_proxy_plain_connect_and_intercepted() {
    if !enabled("CAGUAX_TEST_CURL") {
        return;
    }
    let pki = Pki::new();
    let plain = echo_origin(None).await;
    let tls = echo_origin(Some(pki.server_config(false))).await;
    let mtls = echo_origin(Some(pki.server_config(true))).await;
    let route = Route::with_tls(Arc::new(pki.credential("curl-client"))).build();
    let router = Router::builder()
        .rule(Rule::parse(&format!("localhost:{}", mtls.port()), route).unwrap())
        .build();
    let ca = caguax::create_ca(&router, caguax::CaOptions::default()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let proxy_ca = directory.path().join("proxy-ca.pem");
    let origin_ca = directory.path().join("origin-ca.pem");
    std::fs::write(&proxy_ca, ca.certificate_pem()).unwrap();
    std::fs::write(&origin_ca, pki.ca.certificate_pem()).unwrap();
    let server = Server::builder(router)
        .ca(ca)
        .unwrap()
        .start()
        .await
        .unwrap();
    let proxy = format!("http://{}", server.addresses()[0]);

    let (ok, body) = run_curl(vec![
        "-x".into(),
        proxy.clone(),
        format!("http://127.0.0.1:{}/plain", plain.port()),
    ])
    .await;
    assert!(ok && body.starts_with("GET /plain"), "{body}");

    let (ok, body) = run_curl(vec![
        "-x".into(),
        proxy.clone(),
        "--cacert".into(),
        text(&origin_ca),
        format!("https://127.0.0.1:{}/connect", tls.port()),
    ])
    .await;
    assert!(ok && body.starts_with("GET /connect"), "{body}");

    let (ok, body) = run_curl(vec![
        "-x".into(),
        proxy.clone(),
        "--cacert".into(),
        text(&proxy_ca),
        format!("https://localhost:{}/intercepted", mtls.port()),
    ])
    .await;
    assert!(
        ok && body.contains("client-subject: CN=curl-client"),
        "{body}"
    );
    server.shutdown().await;
}

fn squid_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
#[ignore = "needs squid; set CAGUAX_TEST_SQUID=1"]
async fn an_upstream_squid_carries_connect_and_forwarded_requests() {
    if !enabled("CAGUAX_TEST_SQUID") {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let address = squid_address();
    let configuration = directory.path().join("squid.conf");
    std::fs::write(
        &configuration,
        format!(
            "http_port {address}\nacl all src all\nhttp_access allow all\ncache deny all\naccess_log none\ncache_log {dir}/cache.log\npid_filename {dir}/squid.pid\ncoredump_dir {dir}\nvisible_hostname caguax-test\nnever_direct allow all\n",
            dir = directory.path().display()
        ),
    )
    .unwrap();
    let squid = std::env::var("CAGUAX_SQUID").unwrap_or_else(|_| "squid".into());
    let mut child = Command::new(squid)
        .args(["-N", "-f"])
        .arg(&configuration)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("squid is installed when CAGUAX_TEST_SQUID is set");
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let echo = tcp_echo().await;
    let origin = echo_origin(None).await;
    let mut settings = ServerSettings::default();
    settings.egress = Some(proxied(&format!("http://{address}")));
    let server = Server::builder(Router::new())
        .settings(settings)
        .start()
        .await
        .unwrap();
    let proxy = server.addresses()[0];

    let (mut stream, head) = connect_through(proxy, &echo.to_string()).await;
    assert_eq!(status(&head), 200, "{head}");
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"via squid")
        .await
        .unwrap();
    let mut answer = [0_u8; 9];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut answer)
        .await
        .unwrap();
    assert_eq!(&answer, b"via squid");

    let (head, body) = get_through(proxy, &format!("127.0.0.1:{}/squid", origin.port()), "").await;
    assert_eq!(status(&head), 200, "{head} {body}");
    assert!(body.starts_with("GET /squid"), "{body}");
    assert!(head.to_lowercase().contains("x-origin: echo"));
    server.shutdown().await;
    let _ = child.kill();
    let _ = child.wait();
}
