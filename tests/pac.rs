//! The generated PAC script, evaluated by the PAC engine of coqui-proxy.

use caguax::{Egress, Matcher, Route, Router, Rule, generate_pac};
use coqui_net_acl::IpNet;
use coqui_proxy::pac::PacScript;

const PROXY: &str = "127.0.0.1:3128";

fn answer(script: &PacScript, url: &str) -> String {
    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', ':']).next())
        .unwrap_or_default();
    script.find_proxy_for_url(url, host).unwrap()
}

fn evaluate(router: &Router, egress: Option<&Egress>) -> PacScript {
    let source = generate_pac(router, PROXY, egress);
    PacScript::builder(source).build().unwrap()
}

fn rule(pattern: &str, route: impl Into<Route>) -> Rule {
    Rule::parse(pattern, route).unwrap()
}

#[test]
fn direct_routes_are_direct_only_when_the_proxy_itself_goes_direct() {
    let router = Router::builder()
        .rule(rule("*.corp.example", Route::reject()))
        .rule(rule(
            "direct.example",
            Route::direct().upstream(Egress::Direct),
        ))
        .rule(rule("plain.example", Route::direct()))
        .build();
    let without_egress = evaluate(&router, None);
    assert_eq!(
        answer(&without_egress, "https://api.corp.example/"),
        format!("PROXY {PROXY}")
    );
    assert_eq!(answer(&without_egress, "https://direct.example/"), "DIRECT");
    assert_eq!(answer(&without_egress, "https://plain.example/"), "DIRECT");
    assert_eq!(answer(&without_egress, "https://other.example/"), "DIRECT");
    let system = Egress::System;
    let with_egress = evaluate(&router, Some(&system));
    assert_eq!(answer(&with_egress, "https://direct.example/"), "DIRECT");
    assert_eq!(
        answer(&with_egress, "https://plain.example/"),
        format!("PROXY {PROXY}")
    );
    assert_eq!(
        answer(&with_egress, "https://other.example/"),
        format!("PROXY {PROXY}")
    );
    let direct = Egress::Direct;
    assert_eq!(
        answer(&evaluate(&router, Some(&direct)), "https://plain.example/"),
        "DIRECT"
    );
}

#[test]
fn host_domain_port_scheme_and_network_rules_translate() {
    let proxied = Route::reject();
    let router = Router::builder()
        .rule(rule("*.a.example", proxied.clone()))
        .rule(rule(".b.example", proxied.clone()))
        .rule(rule("c.example:8443", proxied.clone()))
        .rule(rule("10.0.0.0/8", proxied.clone()))
        .rule(Rule::new(
            Matcher::scheme([caguax::Scheme::Http]).unwrap()
                & Matcher::host(["d.example"]).unwrap(),
            proxied.clone(),
        ))
        .rule(Rule::new(
            Matcher::host(["e.example"]).unwrap() & !Matcher::port([443]).unwrap(),
            proxied,
        ))
        .build();
    let script = evaluate(&router, None);
    let proxy = format!("PROXY {PROXY}");
    for url in [
        "https://x.a.example/",
        "https://B.example/".replace('B', "b").as_str(),
        "https://x.b.example/",
        "https://c.example:8443/",
        "https://10.2.3.4/",
        "http://d.example/",
        "https://e.example:8443/",
    ] {
        assert_eq!(answer(&script, url), proxy, "{url}");
    }
    for url in [
        "https://a.example/",
        "https://c.example/",
        "https://11.2.3.4/",
        "https://d.example/",
        "https://e.example/",
    ] {
        assert_eq!(answer(&script, url), "DIRECT", "{url}");
    }
}

#[cfg(feature = "regex")]
#[test]
fn a_regular_expression_rule_translates() {
    let router = Router::builder()
        .rule(Rule::new(
            Matcher::host_regex(r"api\d+\.corp\.example", true).unwrap(),
            Route::reject(),
        ))
        .build();
    let script = evaluate(&router, None);
    assert_eq!(
        answer(&script, "https://API7.corp.example/"),
        format!("PROXY {PROXY}")
    );
    assert_eq!(answer(&script, "https://api.corp.example/"), "DIRECT");
}

#[test]
fn a_rule_with_no_pac_form_sends_what_is_undecided_to_the_proxy() {
    let router = Router::builder()
        .rule(rule(
            "early.example",
            Route::direct().upstream(Egress::Direct),
        ))
        .rule(Rule::new(
            Matcher::custom(|connection| connection.host() == "late.example"),
            Route::reject(),
        ))
        .rule(rule(
            "never.example",
            Route::direct().upstream(Egress::Direct),
        ))
        .build();
    let script = evaluate(&router, None);
    assert_eq!(answer(&script, "https://early.example/"), "DIRECT");
    assert_eq!(
        answer(&script, "https://late.example/"),
        format!("PROXY {PROXY}")
    );
    assert_eq!(
        answer(&script, "https://never.example/"),
        format!("PROXY {PROXY}")
    );
    let ipv6 = Router::builder()
        .rule(rule("fd00::/8", Route::reject()))
        .build();
    assert_eq!(
        answer(&evaluate(&ipv6, None), "https://other.example/"),
        format!("PROXY {PROXY}")
    );
    let network: IpNet = "fd00::/8".parse().unwrap();
    assert!(matches!(network, IpNet::V6(..)));
}

#[test]
fn the_default_route_comes_last() {
    let router = Router::builder()
        .rule(rule(
            "direct.example",
            Route::direct().upstream(Egress::Direct),
        ))
        .default_route(Route::reject())
        .build();
    let script = evaluate(&router, None);
    assert_eq!(answer(&script, "https://direct.example/"), "DIRECT");
    assert_eq!(
        answer(&script, "https://x.example/"),
        format!("PROXY {PROXY}")
    );
    assert_eq!(
        router.pac_script(PROXY, None),
        generate_pac(&router, PROXY, None)
    );
}
