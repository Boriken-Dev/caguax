//! Matchers, `Matcher::from_str`, connections and the router.

use caguax::{
    Action, Connection, Credential, Error, Matcher, PortSpec, Route, Router, Rule, Scheme,
    TlsSource,
};
use coqui_net_acl::IpNet;
use proptest::prelude::*;

fn conn(host: &str, port: u16) -> Connection {
    Connection::new(host, port).unwrap()
}

fn corp() -> Connection {
    conn("api.corp.example", 443)
}

#[test]
fn host_globs_ignore_case_and_mean_what_they_say() {
    let cases = [
        ("*.corp.example", "api.corp.example", true),
        ("*.corp.example", "corp.example", false),
        (".corp.example", "corp.example", true),
        (".corp.example", "a.b.corp.example", true),
        ("API.CORP.EXAMPLE", "api.corp.example", true),
        ("api?.corp.example", "api1.corp.example", true),
        ("[ab].example", "a.example", false),
        ("[ab].example", "[ab].example", true),
        ("a*b*c", "aXXbYYc", true),
        ("a*b*c", "aXXbYY", false),
    ];
    for (pattern, host, expected) in cases {
        let matcher = Matcher::host([pattern]).unwrap();
        assert_eq!(
            matcher.matches(&conn(host, 443)),
            expected,
            "{pattern} {host}"
        );
    }
}

#[cfg(feature = "regex")]
#[test]
fn a_host_regex_matches_the_whole_host() {
    let matcher = Matcher::host_regex(r"api\d+\.corp\.example", true).unwrap();
    assert!(matcher.matches(&conn("API7.corp.example", 443)));
    assert!(!Matcher::host_regex("api", true).unwrap().matches(&corp()));
    assert!(
        !Matcher::host_regex("API.CORP.EXAMPLE", false)
            .unwrap()
            .matches(&corp())
    );
    assert!(matches!(
        Matcher::host_regex("(", true),
        Err(Error::Config(_))
    ));
}

#[test]
fn a_network_matches_address_literals_only() {
    let matcher = Matcher::network([
        "10.0.0.0/8".parse::<IpNet>().unwrap(),
        "fd00::/8".parse().unwrap(),
    ])
    .unwrap();
    assert!(matcher.matches(&conn("10.1.2.3", 443)));
    assert!(matcher.matches(&conn("[fd00::1]", 443)));
    assert!(!matcher.matches(&conn("192.168.1.1", 443)));
    assert!(!matcher.matches(&conn("ten.example", 443)));
}

#[test]
fn port_scheme_path_and_listener() {
    let ports = Matcher::port([PortSpec::from(443), PortSpec::from(8000..=8999)]).unwrap();
    assert!(ports.matches(&conn("a.example", 8443)));
    assert!(!ports.matches(&conn("a.example", 80)));
    let http = Connection::builder("a.example", 80)
        .scheme(Scheme::Http)
        .path("/api/v1")
        .listener("corp")
        .build()
        .unwrap();
    let schemes = Matcher::scheme([Scheme::Http]).unwrap();
    assert!(schemes.matches(&http) && !schemes.matches(&corp()));
    assert!(Matcher::listener(["corp"]).matches(&http));
    #[cfg(feature = "regex")]
    {
        let path = Matcher::path("/api/").unwrap();
        assert!(path.matches(&http));
        assert!(!path.matches(&corp()));
    }
}

#[test]
fn matchers_combine() {
    let rule = (Matcher::host(["*.corp.example"]).unwrap() & !Matcher::port([80]).unwrap())
        | Matcher::network(["10.0.0.0/8".parse::<IpNet>().unwrap()]).unwrap();
    assert!(rule.matches(&corp()));
    assert!(!rule.matches(&conn("api.corp.example", 80)));
    assert!(rule.matches(&conn("10.9.9.9", 80)));
    assert!(Matcher::All.matches(&conn("anything.example", 1)));
    let inner = Matcher::All;
    assert_eq!(!!inner.clone(), inner, "double negation collapses");
    let custom = Matcher::custom(|connection| connection.host().ends_with(".test"));
    assert!(custom.matches(&conn("a.test", 1)) && !custom.matches(&conn("a.example", 1)));
}

#[test]
fn from_str_reads_the_configuration_spellings() {
    let host = |pattern: &str| Matcher::host([pattern]).unwrap();
    let net = |text: &str| Matcher::network([text.parse::<IpNet>().unwrap()]).unwrap();
    assert_eq!(
        "*.corp.example".parse::<Matcher>().unwrap(),
        host("*.corp.example")
    );
    assert_eq!("10.0.0.0/8".parse::<Matcher>().unwrap(), net("10.0.0.0/8"));
    assert_eq!("fd00::/8".parse::<Matcher>().unwrap(), net("fd00::/8"));
    assert_eq!("10.1.2.3".parse::<Matcher>().unwrap(), net("10.1.2.3"));
    assert_eq!("*".parse::<Matcher>().unwrap(), Matcher::All);
    assert_eq!(
        "*.corp.example:8443".parse::<Matcher>().unwrap(),
        host("*.corp.example") & Matcher::port([8443]).unwrap()
    );
    assert_eq!(
        "[fd00::1]:8443".parse::<Matcher>().unwrap(),
        net("fd00::1") & Matcher::port([8443]).unwrap()
    );
    assert_eq!("fd00::1".parse::<Matcher>().unwrap(), net("fd00::1"));
    #[cfg(feature = "regex")]
    assert_eq!(
        "re:api\\d+".parse::<Matcher>().unwrap(),
        Matcher::host_regex("api\\d+", true).unwrap()
    );
    for bad in ["", "   ", "host:notaport", "host:99999", ":80"] {
        assert!(
            matches!(bad.parse::<Matcher>(), Err(Error::Config(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn a_router_takes_the_first_match_then_the_default() {
    let config = coqui_sslcontext::client_config().unwrap();
    let corp_route = Route::with_tls(TlsSource::Config(config))
        .name("corp")
        .build();
    let router = Router::builder()
        .rule(Rule::parse("blocked.corp.example", Route::reject().name("block")).unwrap())
        .rule(Rule::parse("*.corp.example", corp_route).unwrap())
        .default_route(Route::direct().name("rest"))
        .build();
    assert_eq!(
        router.route(&conn("blocked.corp.example", 443)).name(),
        "block"
    );
    assert_eq!(router.route(&corp()).name(), "corp");
    assert_eq!(router.route(&corp()).action(), Action::Tls);
    let explanation = router.explain(&conn("www.example", 443));
    assert!(explanation.rule.is_none());
    assert_eq!(explanation.route.name(), "rest");
    assert_eq!(Router::new().default_route().name(), "default");
}

#[test]
fn a_connection_normalises_and_builds_the_lookup_url() {
    let connection = Connection::builder("[FD00::1].", 8443)
        .scheme(Scheme::Tcp)
        .build()
        .unwrap();
    assert_eq!(connection.host(), "fd00::1");
    assert_eq!(connection.authority(), "[fd00::1]:8443");
    assert_eq!(connection.url(), "https://[fd00::1]:8443/");
    assert!(matches!(
        Connection::new("x.example", 0),
        Err(Error::Config(_))
    ));
    assert!(matches!(Connection::new("", 80), Err(Error::Config(_))));
    let forwarded = Connection::builder("a.example", 80)
        .scheme(Scheme::Http)
        .path("/p?q=1")
        .build()
        .unwrap();
    assert_eq!(forwarded.url(), "http://a.example/p?q=1");
}

#[tokio::test]
async fn a_credential_that_cannot_load_is_unavailable_and_asked_again() {
    let credential = Credential::from_pem(b"not a certificate".to_vec(), None, Default::default())
        .name("broken")
        .build();
    for _ in 0..2 {
        let error = credential.tls_config("a.example").await.unwrap_err();
        assert!(matches!(error, Error::CredentialUnavailable(_)), "{error}");
        assert!(error.to_string().contains("broken"));
    }
}

proptest! {
    #[test]
    fn from_str_returns_a_matcher_or_an_error_for_any_text(text in "\\PC{0,40}") {
        let _ = text.parse::<Matcher>();
    }

    #[test]
    fn a_glob_of_literal_characters_matches_itself(host in "[a-z0-9]{1,8}(\\.[a-z0-9]{1,8}){0,3}") {
        let matcher: Matcher = host.parse().unwrap();
        prop_assert!(matcher.matches(&Connection::new(&host, 443).unwrap()));
    }

    #[test]
    fn a_trailing_port_adds_a_port_condition(host in "[a-z]{1,8}\\.example", port in 1_u16..) {
        let matcher: Matcher = format!("{host}:{port}").parse().unwrap();
        prop_assert!(matcher.matches(&Connection::new(&host, port).unwrap()));
        let other = if port == 1 { 2 } else { 1 };
        prop_assert!(!matcher.matches(&Connection::new(&host, other).unwrap()));
    }
}
