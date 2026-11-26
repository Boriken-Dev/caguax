//! Credential rules and proxy rules: the matcher, the outcomes, first match wins and every refusal.

mod support;

use std::sync::Arc;
use std::time::Duration;

use caguax::config::{BuildOptions, LoadOptions, build_parts, loads};
use caguax::upstream::connect;
use caguax::{
    ConnectOptions, Connection, CredentialKind, CredentialPolicy, CredentialRule, CredentialUse,
    Egress, Error, Matcher, ProxyPolicy, ProxyRule, Route, Router, Server, Tunnel,
};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn connection(host: &str) -> Connection {
    Connection::new(host, 443).unwrap()
}

fn rule(pattern: &str, using: CredentialUse) -> CredentialRule {
    CredentialRule::new(pattern.parse::<Matcher>().unwrap(), using).unwrap()
}

fn config_error(text: &str) -> String {
    let document = loads(text.as_bytes(), LoadOptions::default());
    match document.and_then(|document| build_parts(&document, BuildOptions::default())) {
        Err(Error::Config(error)) => error.to_string(),
        Err(other) => other.to_string(),
        Ok(_) => panic!("the configuration was accepted: {text}"),
    }
}

// ---------------------------------------------------------------- the rules themselves

#[test]
fn the_first_matching_rule_decides_and_hosts_no_rule_names_get_no_decision() {
    let policy = CredentialPolicy::new()
        .rule(rule("*.corp.example", CredentialUse::None))
        .rule(rule(".example", CredentialUse::First))
        .rule(rule("10.0.0.0/8", CredentialUse::Default));
    let decided = |host: &str| {
        policy
            .client_certificate(&connection(host))
            .map(|rule| rule.using().as_str())
    };
    // The first rule wins over the later, broader one.
    assert_eq!(decided("api.corp.example"), Some("none"));
    assert_eq!(decided("www.example"), Some("first"));
    assert_eq!(decided("example"), Some("first"));
    assert_eq!(decided("10.1.2.3"), Some("default"));
    // No rule names this host.
    assert_eq!(decided("other.test"), None);
}

#[test]
fn a_rule_covers_the_kinds_its_outcome_allows() {
    let none = rule("*.corp.example", CredentialUse::None);
    assert_eq!(
        none.covers(),
        [
            CredentialKind::ClientCertificate,
            CredentialKind::ProxyLogin
        ]
    );
    let first = rule("*.corp.example", CredentialUse::First);
    assert_eq!(first.covers(), [CredentialKind::ClientCertificate]);
    // First and pin choose among certificates: a proxy login has none to choose from.
    assert!(first.kinds([CredentialKind::ProxyLogin]).is_err());
    assert!(
        rule("x", CredentialUse::None)
            .kinds(std::iter::empty())
            .is_err()
    );
}

#[test]
fn proxy_login_is_the_default_unless_a_rule_says_none() {
    let policy = CredentialPolicy::new()
        .rule(rule("*.dmz.example", CredentialUse::None))
        .rule(rule("*.example", CredentialUse::Default));
    assert!(!policy.proxy_login("gw.dmz.example", 8080));
    assert!(policy.proxy_login("gw.example", 8080));
    // No rule matches: the default.
    assert!(policy.proxy_login("gw.other.test", 8080));
    // A rule about client certificates only does not touch a proxy login.
    let only_certificates = CredentialPolicy::new().rule(rule("*", CredentialUse::First));
    assert!(only_certificates.proxy_login("gw.example", 8080));
}

#[test]
fn a_rule_that_matches_on_more_than_the_host_is_refused() {
    let with_port: Matcher = "*.corp.example:8443".parse().unwrap();
    assert!(CredentialRule::new(with_port, CredentialUse::None).is_err());
    let by_port = Matcher::port([443_u16]).unwrap();
    assert!(CredentialRule::new(by_port, CredentialUse::None).is_err());
    #[cfg(feature = "regex")]
    {
        let by_path = Matcher::path("^/private").unwrap();
        assert!(CredentialRule::new(by_path, CredentialUse::None).is_err());
        // A host regex looks at the host only.
        let by_host = Matcher::host_regex("\\.corp$", true).unwrap();
        assert!(CredentialRule::new(by_host, CredentialUse::None).is_ok());
    }
    let by_scheme = Matcher::scheme([caguax::Scheme::Http]).unwrap();
    assert!(CredentialRule::new(by_scheme, CredentialUse::None).is_err());
    let nested = "*.corp.example".parse::<Matcher>().unwrap() & !Matcher::port([443_u16]).unwrap();
    assert!(CredentialRule::new(nested, CredentialUse::None).is_err());
}

#[test]
fn only_a_rule_that_may_send_any_certificate_is_a_non_default() {
    let policy = CredentialPolicy::new()
        .rule(rule("a.example", CredentialUse::None))
        .rule(rule("b.example", CredentialUse::Default))
        .rule(rule("c.example", CredentialUse::First).named("anything"))
        .rule(rule("d.example", CredentialUse::First));
    assert_eq!(
        policy.non_defaults(),
        [
            "credential_rule.anything.use = first",
            "credential_rule.3.use = first"
        ]
    );
}

// ---------------------------------------------------------------- the configuration

const CREDENTIALS: &str = r#"
[credentials.alice]
backend = "system"
[credentials.bob]
backend = "system"
"#;

#[test]
fn credential_and_proxy_rules_are_read_from_the_configuration() {
    let text = format!(
        r#"{CREDENTIALS}
[[credential_rule]]
match = ["*.corp.example", "10.0.0.0/8"]
use = "none"
name = "keep-out"

[[credential_rule]]
match = ".example"
use = {{ pin = "alice" }}

[[credential_rule]]
match = "gw.example"
for = "proxy_login"
use = "default"

[[proxy_rule]]
match = ["*.dmz.example"]
port = 443
use = "none"

[[proxy_rule]]
match = ".example"
use = "system"

[[proxy_rule]]
match = "*"
use = {{ proxy = "http://gw.example:3128" }}
"#
    );
    let document = loads(text.as_bytes(), LoadOptions::default()).unwrap();
    let parts = build_parts(&document, BuildOptions::default()).unwrap();
    let credentials = parts.router.credential_policy().unwrap();
    assert_eq!(credentials.rules().len(), 3);
    assert_eq!(credentials.rules()[0].name(), "keep-out");
    assert_eq!(credentials.rules()[1].using().as_str(), "pin");
    assert_eq!(
        credentials.rules()[2].covers(),
        [CredentialKind::ProxyLogin]
    );
    let proxies = parts.router.proxy_policy().unwrap();
    let egress = |host: &str, port: u16| {
        proxies
            .decide(&Connection::new(host, port).unwrap())
            .map(|rule| rule.egress().spelling().unwrap())
    };
    assert_eq!(egress("a.dmz.example", 443).as_deref(), Some("direct"));
    // The port keeps the first rule from matching, so the next one decides.
    assert_eq!(egress("a.dmz.example", 80).as_deref(), Some("system"));
    assert_eq!(egress("www.example", 443).as_deref(), Some("system"));
    assert_eq!(
        egress("elsewhere.test", 443).as_deref(),
        Some("http://gw.example:3128")
    );
}

#[test]
fn every_refused_rule_names_its_table() {
    let cases = [
        (
            "[[credential_rule]]\nmatch = \"a.example\"\nuse = \"none\"\nport = 443\n",
            "credential_rule[0]: a credential rule matches on the host only",
        ),
        (
            "[[credential_rule]]\nmatch = \"a.example\"\nuse = \"none\"\npath = \"/x\"\n",
            "credential_rule[0]: a credential rule matches on the host only",
        ),
        (
            "[[credential_rule]]\nmatch = \"a.example:8443\"\nuse = \"none\"\n",
            "credential_rule[0]: a credential rule matches on the host only",
        ),
        (
            "[[credential_rule]]\nmatch = \"a.example\"\nuse = \"sometimes\"\n",
            "credential_rule[0]: use must be",
        ),
        (
            "[[credential_rule]]\nmatch = \"a.example\"\nuse = { pin = \"nobody\" }\n",
            "credential_rule[0]: pin names no credential: nobody",
        ),
        (
            "[[credential_rule]]\nmatch = \"a.example\"\nuse = \"none\"\nfor = \"origin_login\"\n",
            "credential_rule[0]: a credential kind is",
        ),
        (
            "[[credential_rule]]\nmatch = \"a.example\"\nuse = \"first\"\nfor = [\"proxy_login\"]\n",
            "credential_rule[0]: \"first\" and \"pin\" choose a client certificate",
        ),
        (
            "[[credential_rule]]\nmatch = []\nuse = \"none\"\n",
            "credential_rule[0]: match must be",
        ),
        ("[[credential_rule]]\nmatch = \"a.example\"\n", "use"),
        (
            "[[proxy_rule]]\nmatch = \"a.example\"\nuse = \"maybe\"\n",
            "proxy_rule[0]: use must be",
        ),
        (
            "[[proxy_rule]]\nmatch = \"a.example\"\nuse = { proxy = \"http://\" }\n",
            "proxy_rule[0]",
        ),
        (
            "[[proxy_rule]]\nmatch = []\nuse = \"none\"\n",
            "proxy_rule[0]: match must be",
        ),
    ];
    for (text, expected) in cases {
        let message = config_error(&format!("{CREDENTIALS}{text}"));
        assert!(message.contains(expected), "{text}: {message}");
    }
}

// ---------------------------------------------------------------- client certificates

/// The subject the origin saw in the client certificate, or `None` when the request did not
/// complete (the origin requires a certificate).
async fn client_subject(
    origin_port: u16,
    route: &Route,
    policy: Option<CredentialPolicy>,
) -> Option<String> {
    let options = ConnectOptions::default()
        .timeout(Duration::from_secs(5))
        .credential_policy(policy.map(Arc::new));
    let connection = Connection::new("127.0.0.1", origin_port).unwrap();
    let mut stream = connect(&connection, route, &options).await.ok()?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .ok()?;
    let mut body = String::new();
    stream.read_to_string(&mut body).await.ok()?;
    body.lines()
        .find_map(|line| line.strip_prefix("client-subject: "))
        .map(str::to_owned)
}

#[tokio::test]
async fn every_client_certificate_outcome_and_the_absence_of_a_rule() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(true))).await;
    let route = Route::with_tls(Arc::new(pki.credential("route-credential"))).build();
    let pinned = Arc::new(pki.credential("pinned-credential"));
    let port = origin.port();

    // No rule at all, and a rule that names other hosts: the route's own credential, as configured.
    let subject = client_subject(port, &route, None).await;
    assert_eq!(subject.as_deref(), Some("CN=route-credential"));
    let elsewhere = CredentialPolicy::new().rule(rule("*.corp.example", CredentialUse::None));
    let subject = client_subject(port, &route, Some(elsewhere)).await;
    assert_eq!(subject.as_deref(), Some("CN=route-credential"));

    // Default and first send the route's credential.
    for using in [CredentialUse::Default, CredentialUse::First] {
        let name = using.as_str();
        let policy = CredentialPolicy::new().rule(rule("127.0.0.1", using));
        let subject = client_subject(port, &route, Some(policy)).await;
        assert_eq!(subject.as_deref(), Some("CN=route-credential"), "{name}");
    }

    // None sends no certificate: the origin, which requires one, never serves the request.
    let none = CredentialPolicy::new().rule(rule("127.0.0.1", CredentialUse::None));
    assert_eq!(client_subject(port, &route, Some(none)).await, None);

    // A pin sends the named credential instead of the route's.
    let pin = CredentialPolicy::new().rule(rule("127.0.0.1", CredentialUse::Pin(pinned)));
    let subject = client_subject(port, &route, Some(pin)).await;
    assert_eq!(subject.as_deref(), Some("CN=pinned-credential"));

    // First match wins: the earlier none keeps the later pin from applying.
    let ordered = CredentialPolicy::new()
        .rule(rule("127.0.0.1", CredentialUse::None))
        .rule(rule("*", CredentialUse::Default));
    assert_eq!(client_subject(port, &route, Some(ordered)).await, None);
}

#[tokio::test]
async fn a_tunnel_whose_credential_is_withheld_needs_no_allow_any_local() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(true))).await;
    let target = format!("127.0.0.1:{}", origin.port());
    let route = Route::with_tls(Arc::new(pki.credential("tunnel-client"))).build();
    let tunnel = || {
        Tunnel::builder("127.0.0.1:0", &target)
            .unwrap()
            .route(route.clone())
            .build()
    };
    let start = |router: Router| async move {
        Server::builder(router)
            .auth(test_auth())
            .tunnel(tunnel())
            .start()
            .await
    };

    // Without a rule the credential is sent, so any local process would use it.
    assert!(start(Router::new()).await.is_err());
    // A rule withholding it for this target makes the tunnel safe without the opt-in.
    let withheld = Router::builder()
        .credential_policy(CredentialPolicy::new().rule(rule("127.0.0.1", CredentialUse::None)))
        .build();
    let server = start(withheld).await.unwrap();
    assert!(
        server.non_defaults().is_empty(),
        "{:?}",
        server.non_defaults()
    );
    server.shutdown().await;
    // A rule that sends it (default, first or pin) does not.
    for using in [CredentialUse::Default, CredentialUse::First] {
        let router = Router::builder()
            .credential_policy(CredentialPolicy::new().rule(rule("127.0.0.1", using)))
            .build();
        assert!(start(router).await.is_err());
    }
}

#[tokio::test]
async fn a_server_lists_a_first_rule_as_a_non_default() {
    let router = Router::builder()
        .credential_policy(CredentialPolicy::new().rule(rule("*", CredentialUse::First)))
        .build();
    let server = Server::builder(router)
        .auth(test_auth())
        .start()
        .await
        .unwrap();
    assert_eq!(server.non_defaults(), ["credential_rule.0.use = first"]);
    server.shutdown().await;
}

// ---------------------------------------------------------------- proxy rules

/// Which attempts the error of reaching an unreachable destination lists.
async fn attempts(destination: &str, route: &Route, options: ConnectOptions) -> String {
    let connection = Connection::new(destination, 443).unwrap();
    let options = options.timeout(Duration::from_millis(500));
    match connect(&connection, route, &options).await {
        Err(error) => error.to_string(),
        Ok(_) => panic!("{destination} should be unreachable"),
    }
}

#[tokio::test]
async fn every_proxy_outcome_and_a_routes_own_upstream_wins() {
    let stub = stub_proxy().await;
    let proxy = format!("http://{}", stub.address);
    // A destination that is not loopback (the resolver sends loopback direct), and reserved.
    let target = "198.51.100.7";
    let policy = ProxyPolicy::new()
        .rule(ProxyRule::new(
            ".direct.example".parse::<Matcher>().unwrap(),
            Egress::Direct,
        ))
        .rule(ProxyRule::new(Matcher::All, Egress::Proxy(proxy.clone())));
    let with = |policy: &ProxyPolicy| {
        ConnectOptions::default().proxy_policy(Some(Arc::new(policy.clone())))
    };

    // A matching rule that names a proxy sends the destination through it.
    let direct_route = Route::direct().build();
    let error = attempts(target, &direct_route, with(&policy)).await;
    assert!(error.contains(&stub.address.to_string()), "{error}");
    assert_eq!(stub.heads.lock().unwrap().len(), 1);
    assert!(stub.heads.lock().unwrap()[0].starts_with(&format!("CONNECT {target}:443")));

    // The first rule wins: `none` for this host is direct and the stub is not asked again.
    let error = attempts("198.51.100.8", &direct_route, with(&policy)).await;
    assert!(error.contains(&stub.address.to_string()), "{error}");
    let before = stub.heads.lock().unwrap().len();
    let first_none = ProxyPolicy::new()
        .rule(ProxyRule::new(Matcher::All, Egress::Direct))
        .rule(ProxyRule::new(Matcher::All, Egress::Proxy(proxy.clone())));
    let error = attempts(target, &direct_route, with(&first_none)).await;
    assert!(!error.contains(&stub.address.to_string()), "{error}");
    assert_eq!(stub.heads.lock().unwrap().len(), before);

    // A route's own upstream wins over a proxy rule: this route says direct explicitly.
    let explicit = Route::direct().upstream(Egress::Direct).build();
    let error = attempts(target, &explicit, with(&policy)).await;
    assert!(!error.contains(&stub.address.to_string()), "{error}");
    assert_eq!(stub.heads.lock().unwrap().len(), before);

    // A proxy rule wins over the server's egress.
    let dead = dead_address().await;
    let options = with(&policy).egress(proxied(&format!("http://{dead}")));
    let error = attempts(target, &direct_route, options).await;
    assert!(error.contains(&stub.address.to_string()), "{error}");
    assert!(!error.contains(&dead.to_string()), "{error}");
    // With no rule matching, the server's egress applies.
    let unmatched = ProxyPolicy::new().rule(ProxyRule::new(
        "*.other.example".parse::<Matcher>().unwrap(),
        Egress::Direct,
    ));
    let options = with(&unmatched).egress(proxied(&format!("http://{dead}")));
    let error = attempts(target, &direct_route, options).await;
    assert!(error.contains(&dead.to_string()), "{error}");
}

#[test]
fn the_examples_in_the_rules_guide_are_valid_configuration() {
    let guide =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/rules.md")).unwrap();
    let blocks: Vec<&str> = guide
        .split("```toml\n")
        .skip(1)
        .filter_map(|rest| rest.split("```").next())
        .collect();
    assert_eq!(blocks.len(), 2, "one example per table");
    for block in blocks {
        let document = loads(block.as_bytes(), LoadOptions::default()).unwrap();
        // The proxy example builds as it is; the credential example names files that are not here.
        if document.credentials.is_empty() {
            build_parts(&document, BuildOptions::default()).unwrap();
        }
    }
}
