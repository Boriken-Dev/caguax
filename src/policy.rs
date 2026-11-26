//! Credential rules: which credential, if any, goes to which host.
//!
//! A [`CredentialRule`] pairs a [`Matcher`] with a [`CredentialUse`]; the first rule of a
//! [`CredentialPolicy`] that matches and covers the kind of credential decides. The matcher is the
//! one the routing rules use, so the same patterns (`*.corp.example`, `.corp.example`, `10.0.0.0/8`,
//! `re:...`) apply.
//!
//! Two kinds of credential are decided:
//!
//! - [`CredentialKind::ClientCertificate`], sent to a destination in a TLS handshake. Matched on the
//!   destination's host alone (a certificate request names no port or path), so a rule for this
//!   kind that matches on port or path is refused. With no matching rule the route's own
//!   credential is used as configured, and a keystore selector sends nothing it was not told to.
//! - [`CredentialKind::ProxyLogin`], the Kerberos or NTLM login to an upstream proxy (feature
//!   `negotiate`). Matched on the proxy's host. With no matching rule: [`CredentialUse::Default`],
//!   the logon session's credentials.
//!
//! caguax performs no login to origin servers, so there is no rule kind for one.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::connection::Connection;
use crate::credential::Credential;
use crate::error::{Result, config};
use crate::rules::Matcher;
use crate::upstream::Egress;

/// What a credential rule decides for the hosts it matches.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CredentialUse {
    /// Send no credential.
    None,
    /// The default: for a client certificate the route's own credential as configured, for a
    /// proxy login the system's default credentials.
    Default,
    /// The first candidate that works: for a client certificate, the first identity a keystore
    /// query finds (listed as `non-default`: any certificate the keystore holds may be sent).
    First,
    /// This credential, whatever the route names (client certificates only).
    Pin(Arc<Credential>),
}

impl CredentialUse {
    /// The name used in configuration files.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Default => "default",
            Self::First => "first",
            Self::Pin(_) => "pin",
        }
    }
}

/// Which credential a rule is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CredentialKind {
    /// A client certificate for a destination's TLS handshake.
    ClientCertificate,
    /// A Negotiate or NTLM login to an upstream proxy.
    ProxyLogin,
}

impl CredentialKind {
    /// The name used in configuration files: `client_certificate` or `proxy_login`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientCertificate => "client_certificate",
            Self::ProxyLogin => "proxy_login",
        }
    }
}

impl core::str::FromStr for CredentialKind {
    type Err = crate::Error;

    fn from_str(text: &str) -> Result<Self> {
        match text {
            "client_certificate" => Ok(Self::ClientCertificate),
            "proxy_login" => Ok(Self::ProxyLogin),
            _ => Err(config(
                "a credential kind is \"client_certificate\" or \"proxy_login\"",
            )),
        }
    }
}

/// Whether the matcher looks at anything but the host.
fn host_only(matcher: &Matcher) -> bool {
    match matcher {
        Matcher::Port(_) | Matcher::Scheme(_) | Matcher::Listener(_) => false,
        #[cfg(feature = "regex")]
        Matcher::Path(_) => false,
        Matcher::AllOf(parts) | Matcher::AnyOf(parts) => parts.iter().all(host_only),
        Matcher::Not(inner) => host_only(inner),
        _ => true,
    }
}

/// One credential rule.
#[derive(Debug, Clone)]
pub struct CredentialRule {
    matcher: Matcher,
    kinds: Vec<CredentialKind>,
    using: CredentialUse,
    name: String,
}

impl CredentialRule {
    /// A rule for `matcher`. Without [`kinds`](Self::kinds) it covers client certificates when
    /// `using` is `First` or `Pin`, and both kinds otherwise.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for a matcher that looks at more than the host.
    pub fn new(matcher: impl Into<Matcher>, using: CredentialUse) -> Result<Self> {
        let matcher = matcher.into();
        if !host_only(&matcher) {
            return Err(config(
                "a credential rule matches on the host only: no port, path, scheme or listener",
            ));
        }
        let kinds = match using {
            CredentialUse::First | CredentialUse::Pin(_) => {
                alloc::vec![CredentialKind::ClientCertificate]
            }
            _ => alloc::vec![
                CredentialKind::ClientCertificate,
                CredentialKind::ProxyLogin
            ],
        };
        Ok(Self {
            matcher,
            kinds,
            using,
            name: String::new(),
        })
    }

    /// The kinds of credential this rule decides.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for no kind, or `First` or `Pin` with a proxy login (only a
    /// client certificate has candidates to choose from).
    pub fn kinds(mut self, kinds: impl IntoIterator<Item = CredentialKind>) -> Result<Self> {
        let kinds: Vec<CredentialKind> = kinds.into_iter().collect();
        if kinds.is_empty() {
            return Err(config("a credential rule covers at least one kind"));
        }
        if matches!(self.using, CredentialUse::First | CredentialUse::Pin(_))
            && kinds.contains(&CredentialKind::ProxyLogin)
        {
            return Err(config(
                "\"first\" and \"pin\" choose a client certificate: a proxy login is \"none\" or \"default\"",
            ));
        }
        self.kinds = kinds;
        Ok(self)
    }

    /// Names the rule, for logs and `non_defaults`.
    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// The matcher.
    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    /// What the rule decides.
    pub fn using(&self) -> &CredentialUse {
        &self.using
    }

    /// The kinds the rule covers.
    pub fn covers(&self) -> &[CredentialKind] {
        &self.kinds
    }

    /// The rule's name (empty when it has none).
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The credential rules in force, first match wins per kind.
#[derive(Debug, Clone, Default)]
pub struct CredentialPolicy {
    rules: Vec<CredentialRule>,
}

impl CredentialPolicy {
    /// A policy with no rule: every kind takes its default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a rule after the ones already there.
    #[must_use]
    pub fn rule(mut self, rule: CredentialRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// The rules, in order.
    pub fn rules(&self) -> &[CredentialRule] {
        &self.rules
    }

    fn decide(&self, kind: CredentialKind, connection: &Connection) -> Option<&CredentialRule> {
        self.rules
            .iter()
            .find(|rule| rule.kinds.contains(&kind) && rule.matcher.matches(connection))
    }

    /// The rule deciding the client certificate for `connection`, `None` when no rule matches
    /// (the route's own credential then applies as configured).
    pub fn client_certificate(&self, connection: &Connection) -> Option<&CredentialRule> {
        self.decide(CredentialKind::ClientCertificate, connection)
    }

    /// Whether to log in to the upstream proxy at `host:port` with the system's credentials: the
    /// first matching rule's answer, `true` when none matches.
    pub fn proxy_login(&self, host: &str, port: u16) -> bool {
        let Ok(connection) = Connection::new(host, port) else {
            return true;
        };
        self.decide(CredentialKind::ProxyLogin, &connection)
            .is_none_or(|rule| !matches!(rule.using, CredentialUse::None))
    }

    /// What is looser than the defaults, as `setting = value` text: a rule that may send any
    /// certificate a keystore holds.
    pub fn non_defaults(&self) -> Vec<String> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                matches!(rule.using, CredentialUse::First)
                    && rule.kinds.contains(&CredentialKind::ClientCertificate)
            })
            .map(|(index, rule)| {
                let label = if rule.name.is_empty() {
                    alloc::format!("{index}")
                } else {
                    rule.name.clone()
                };
                alloc::format!("credential_rule.{label}.use = first")
            })
            .collect()
    }
}

/// `egress` applies to the destinations `matcher` accepts.
#[derive(Debug, Clone)]
pub struct ProxyRule {
    matcher: Matcher,
    egress: Egress,
    name: String,
}

impl ProxyRule {
    /// A rule sending the destinations `matcher` accepts through `egress`: [`Egress::System`] for
    /// the system's proxy settings or PAC, [`Egress::Direct`] for no proxy, [`Egress::Proxy`] for
    /// one proxy.
    pub fn new(matcher: impl Into<Matcher>, egress: impl Into<Egress>) -> Self {
        Self {
            matcher: matcher.into(),
            egress: egress.into(),
            name: String::new(),
        }
    }

    /// Names the rule.
    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// The matcher.
    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    /// Where matching destinations go.
    pub fn egress(&self) -> &Egress {
        &self.egress
    }

    /// The rule's name (empty when it has none).
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Proxy rules: the first that matches picks the egress for a destination whose route names no
/// upstream of its own. A route's `upstream` always wins over these, and these win over the
/// server's `egress`.
#[derive(Debug, Clone, Default)]
pub struct ProxyPolicy {
    rules: Vec<ProxyRule>,
}

impl ProxyPolicy {
    /// A policy with no rule.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a rule after the ones already there.
    #[must_use]
    pub fn rule(mut self, rule: ProxyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// The rules, in order.
    pub fn rules(&self) -> &[ProxyRule] {
        &self.rules
    }

    /// The rule deciding `connection`, if any.
    pub fn decide(&self, connection: &Connection) -> Option<&ProxyRule> {
        self.rules
            .iter()
            .find(|rule| rule.matcher.matches(connection))
    }
}
