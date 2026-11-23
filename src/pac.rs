//! A proxy auto-config (PAC) script generated from a router's rules.
//!
//! Clients that read a PAC (browsers, operating-system proxy settings) then send only what needs
//! the proxy through it. A rule PAC JavaScript cannot express exactly (a path, an IPv6 network, a
//! custom predicate) sends everything still undecided to the proxy, which routes it exactly: the
//! script errs towards the proxy, never away from it.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use coqui_net_acl::IpNet;

use crate::connection::{LISTENER, Scheme};
use crate::route::{Action, Route, Router};
use crate::rules::{Matcher, PortSpec};
use crate::upstream::Egress;

const HELPERS: &str = "function _port(url) {
  var m = /^([a-z][a-z0-9+.-]*):\\/\\/(?:\\[[^\\]]*\\]|[^\\/:]*)(?::(\\d+))?/i.exec(url);
  if (!m) return 0;
  if (m[2]) return parseInt(m[2], 10);
  return m[1].toLowerCase() == \"https\" ? 443 : 80;
}
function _scheme(url) {
  return url.substring(0, url.indexOf(\":\")).toLowerCase();
}
function _ipv4(host) {
  return /^\\d{1,3}(\\.\\d{1,3}){3}$/.test(host);
}
";

fn js(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("\"\""))
}

fn join(parts: Vec<Option<String>>, joiner: &str) -> Option<String> {
    let parts: Option<Vec<String>> = parts.into_iter().collect();
    parts.map(|parts| alloc::format!("({})", parts.join(joiner)))
}

/// The matcher as a PAC JavaScript expression, or `None` when it has none.
fn expression(matcher: &Matcher) -> Option<String> {
    match matcher {
        Matcher::All => Some("true".into()),
        Matcher::Host(patterns) => {
            let terms: Vec<String> = patterns
                .iter()
                .map(|pattern| {
                    let pattern = pattern.to_ascii_lowercase();
                    let pattern = pattern.trim_end_matches('.');
                    match pattern.strip_prefix('.') {
                        Some(domain) => alloc::format!(
                            "(host == {} || dnsDomainIs(host, {}))",
                            js(domain),
                            js(pattern)
                        ),
                        None => alloc::format!("shExpMatch(host, {})", js(pattern)),
                    }
                })
                .collect();
            Some(alloc::format!("({})", terms.join(" || ")))
        }
        #[cfg(feature = "regex")]
        Matcher::HostRegex(regex) => {
            let flags = if regex.case_insensitive() { "i" } else { "" };
            Some(alloc::format!(
                "new RegExp({}, {}).test(host)",
                js(&alloc::format!("^(?:{})$", regex.pattern())),
                js(flags)
            ))
        }
        Matcher::Port(ports) => {
            let terms: Vec<String> = ports
                .iter()
                .map(|port| match port {
                    PortSpec::Single(port) => alloc::format!("_port(url) == {port}"),
                    PortSpec::Range(range) => alloc::format!(
                        "(_port(url) >= {} && _port(url) <= {})",
                        range.start(),
                        range.end()
                    ),
                })
                .collect();
            Some(alloc::format!("({})", terms.join(" || ")))
        }
        Matcher::Scheme(schemes) => {
            let terms: Vec<String> = schemes
                .iter()
                .map(|scheme: &Scheme| alloc::format!("_scheme(url) == {}", js(scheme.as_str())))
                .collect();
            Some(alloc::format!("({})", terms.join(" || ")))
        }
        Matcher::Network(networks) => {
            let mut terms = Vec::new();
            for network in networks {
                let IpNet::V4(bits, prefix) = network else {
                    return None;
                };
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from((*prefix).min(32)))
                };
                terms.push(alloc::format!(
                    "isInNet(host, {}, {})",
                    js(&Ipv4Addr::from(*bits).to_string()),
                    js(&Ipv4Addr::from(mask).to_string())
                ));
            }
            Some(alloc::format!("(_ipv4(host) && ({}))", terms.join(" || ")))
        }
        Matcher::Listener(names) => Some(if names.iter().any(|name| name == LISTENER) {
            "true".into()
        } else {
            "false".into()
        }),
        Matcher::AllOf(matchers) => join(matchers.iter().map(expression).collect(), " && "),
        Matcher::AnyOf(matchers) => join(matchers.iter().map(expression).collect(), " || "),
        Matcher::Not(inner) => expression(inner).map(|inner| alloc::format!("!{inner}")),
        _ => None,
    }
}

fn outcome(route: &Route, proxy: &str, egress: Option<&Egress>) -> String {
    let server_direct = matches!(egress, None | Some(Egress::Direct));
    let goes_direct = route.action() == Action::Direct
        && match route.upstream() {
            Some(upstream) => matches!(upstream, Egress::Direct),
            None => server_direct,
        };
    if goes_direct {
        "DIRECT".into()
    } else {
        alloc::format!("PROXY {proxy}")
    }
}

/// A PAC script sending to `proxy` (`host:port`) every request `router` does not send straight to
/// its destination.
///
/// A route goes `DIRECT` in the script only when the proxy itself would connect directly: a
/// `Direct` route whose upstream is [`Egress::Direct`], or none with no `egress`. Rules are
/// evaluated in order, the default last.
pub fn generate_pac(router: &Router, proxy: &str, egress: Option<&Egress>) -> String {
    let mut lines: Vec<String> = alloc::vec![
        "// Generated by caguax from its routing rules.".into(),
        HELPERS.into(),
        "function FindProxyForURL(url, host) {".into(),
        "  host = host.toLowerCase();".into(),
    ];
    for rule in router.rules() {
        let result = outcome(rule.route(), proxy, egress);
        match expression(rule.matcher()) {
            Some(condition) => {
                lines.push(alloc::format!("  if ({condition}) return {};", js(&result)))
            }
            None => {
                lines.push(alloc::format!(
                    "  return {};  // a rule PAC cannot express",
                    js(&alloc::format!("PROXY {proxy}"))
                ));
                lines.push("}".into());
                return lines.join("\n") + "\n";
            }
        }
    }
    lines.push(alloc::format!(
        "  return {};",
        js(&outcome(router.default_route(), proxy, egress))
    ));
    lines.push("}".into());
    lines.join("\n") + "\n"
}

impl Router {
    /// A PAC script for this router's rules; see [`generate_pac`].
    pub fn pac_script(&self, proxy: &str, egress: Option<&Egress>) -> String {
        generate_pac(self, proxy, egress)
    }
}
