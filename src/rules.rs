//! Matchers: predicates on a [`Connection`], combined with `&`, `|` and `!`.
//!
//! Host patterns mean the same everywhere: matching ignores case, `*` matches any run of
//! characters (dots too), `?` one character, every other character (`[` included) is literal, and a
//! leading `.` matches the domain and its subdomains (`NO_PROXY` style).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::net::IpAddr;
use core::ops::{BitAnd, BitOr, Not, RangeInclusive};
use core::str::FromStr;

use coqui_net_acl::IpNet;

use crate::connection::{Connection, Scheme, normalize_host};
use crate::error::{Error, Result, config};

/// One port, or an inclusive range of ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    /// This port.
    Single(u16),
    /// Every port from the start to the end, inclusive.
    Range(RangeInclusive<u16>),
}

impl PortSpec {
    /// Whether `port` is this port or inside this range.
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Single(single) => *single == port,
            Self::Range(range) => range.contains(&port),
        }
    }
}

impl From<u16> for PortSpec {
    fn from(port: u16) -> Self {
        Self::Single(port)
    }
}

impl From<RangeInclusive<u16>> for PortSpec {
    fn from(range: RangeInclusive<u16>) -> Self {
        Self::Range(range)
    }
}

/// A regular expression over a host or a request path. Needs feature `regex`.
#[cfg(feature = "regex")]
#[cfg_attr(docsrs, doc(cfg(feature = "regex")))]
#[derive(Clone)]
pub struct RegexMatcher {
    pattern: String,
    case_insensitive: bool,
    compiled: regex::Regex,
}

#[cfg(feature = "regex")]
impl RegexMatcher {
    fn new(pattern: &str, case_insensitive: bool, whole: bool) -> Result<Self> {
        let anchored = if whole {
            alloc::format!("^(?:{pattern})$")
        } else {
            alloc::format!("^(?:{pattern})")
        };
        let compiled = regex::RegexBuilder::new(&anchored)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|_| config("a rule's regular expression is not valid"))?;
        Ok(Self {
            pattern: pattern.into(),
            case_insensitive,
            compiled,
        })
    }

    /// The expression as written.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Whether letter case is ignored.
    pub fn case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    fn is_match(&self, text: &str) -> bool {
        self.compiled.is_match(text)
    }
}

#[cfg(feature = "regex")]
impl PartialEq for RegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.case_insensitive == other.case_insensitive
    }
}

#[cfg(feature = "regex")]
impl fmt::Debug for RegexMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegexMatcher")
            .field("pattern", &self.pattern)
            .field("case_insensitive", &self.case_insensitive)
            .finish()
    }
}

/// A predicate written in code, for rules a file cannot spell.
#[derive(Clone)]
pub struct CustomMatcher(Arc<dyn Fn(&Connection) -> bool + Send + Sync>);

impl PartialEq for CustomMatcher {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for CustomMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CustomMatcher")
    }
}

/// A predicate on a [`Connection`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Matcher {
    /// Every connection.
    All,
    /// The host matches any of these glob patterns.
    Host(Vec<String>),
    /// The whole host matches the expression (case-insensitive unless told otherwise).
    #[cfg(feature = "regex")]
    #[cfg_attr(docsrs, doc(cfg(feature = "regex")))]
    HostRegex(RegexMatcher),
    /// The destination port is one of these.
    Port(Vec<PortSpec>),
    /// The connection's scheme is one of these.
    Scheme(Vec<Scheme>),
    /// The host is an address literal inside one of these networks (names are never resolved).
    Network(Vec<IpNet>),
    /// A forwarded request's path matches the expression from its start; never a `CONNECT` or a
    /// tunnel, which have none.
    #[cfg(feature = "regex")]
    #[cfg_attr(docsrs, doc(cfg(feature = "regex")))]
    Path(RegexMatcher),
    /// The connection came in on one of these named listeners.
    Listener(Vec<String>),
    /// Every one of these matches.
    AllOf(Vec<Matcher>),
    /// At least one of these matches.
    AnyOf(Vec<Matcher>),
    /// The inner matcher does not match.
    Not(alloc::boxed::Box<Matcher>),
    /// A predicate in code.
    Custom(CustomMatcher),
}

fn non_empty<T>(items: Vec<T>, what: &str) -> Result<Vec<T>> {
    if items.is_empty() {
        Err(config(alloc::format!("{what} needs one or more entries")))
    } else {
        Ok(items)
    }
}

impl Matcher {
    /// [`Matcher::Host`] over these patterns.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for no pattern or an empty one.
    pub fn host<I, S>(patterns: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let patterns: Vec<String> = patterns.into_iter().map(Into::into).collect();
        if patterns.iter().any(|pattern| pattern.is_empty()) {
            return Err(config("a host pattern is not empty"));
        }
        Ok(Self::Host(non_empty(patterns, "Host")?))
    }

    /// [`Matcher::HostRegex`], case-insensitive unless `case_insensitive` is false.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for an expression that does not compile.
    #[cfg(feature = "regex")]
    #[cfg_attr(docsrs, doc(cfg(feature = "regex")))]
    pub fn host_regex(pattern: &str, case_insensitive: bool) -> Result<Self> {
        Ok(Self::HostRegex(RegexMatcher::new(
            pattern,
            case_insensitive,
            true,
        )?))
    }

    /// [`Matcher::Path`].
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for an expression that does not compile.
    #[cfg(feature = "regex")]
    #[cfg_attr(docsrs, doc(cfg(feature = "regex")))]
    pub fn path(pattern: &str) -> Result<Self> {
        Ok(Self::Path(RegexMatcher::new(pattern, false, false)?))
    }

    /// [`Matcher::Port`] over ports and ranges.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for none.
    pub fn port<I, P>(ports: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: Into<PortSpec>,
    {
        let ports: Vec<PortSpec> = ports.into_iter().map(Into::into).collect();
        Ok(Self::Port(non_empty(ports, "Port")?))
    }

    /// [`Matcher::Scheme`].
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for none.
    pub fn scheme<I>(schemes: I) -> Result<Self>
    where
        I: IntoIterator<Item = Scheme>,
    {
        Ok(Self::Scheme(non_empty(
            schemes.into_iter().collect(),
            "Scheme",
        )?))
    }

    /// [`Matcher::Network`].
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for none.
    pub fn network<I>(networks: I) -> Result<Self>
    where
        I: IntoIterator<Item = IpNet>,
    {
        Ok(Self::Network(non_empty(
            networks.into_iter().collect(),
            "Network",
        )?))
    }

    /// [`Matcher::Listener`].
    pub fn listener<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Listener(names.into_iter().map(Into::into).collect())
    }

    /// A predicate in code.
    pub fn custom(predicate: impl Fn(&Connection) -> bool + Send + Sync + 'static) -> Self {
        Self::Custom(CustomMatcher(Arc::new(predicate)))
    }

    /// Whether the connection matches.
    pub fn matches(&self, connection: &Connection) -> bool {
        match self {
            Self::All => true,
            Self::Host(patterns) => patterns
                .iter()
                .any(|pattern| glob_matches(pattern, connection.host())),
            #[cfg(feature = "regex")]
            Self::HostRegex(regex) => regex.is_match(connection.host()),
            Self::Port(ports) => ports.iter().any(|port| port.contains(connection.port())),
            Self::Scheme(schemes) => schemes.contains(&connection.scheme()),
            Self::Network(networks) => connection
                .host()
                .parse::<IpAddr>()
                .is_ok_and(|address| networks.iter().any(|network| network.contains(address))),
            #[cfg(feature = "regex")]
            Self::Path(regex) => connection.path().is_some_and(|path| regex.is_match(path)),
            Self::Listener(names) => names.iter().any(|name| name == connection.listener()),
            Self::AllOf(matchers) => matchers.iter().all(|matcher| matcher.matches(connection)),
            Self::AnyOf(matchers) => matchers.iter().any(|matcher| matcher.matches(connection)),
            Self::Not(matcher) => !matcher.matches(connection),
            Self::Custom(custom) => (custom.0)(connection),
        }
    }
}

/// Case-insensitive glob over a normalised host.
fn glob_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalize_host(pattern);
    if let Some(domain) = pattern.strip_prefix('.') {
        return host == domain
            || host
                .strip_suffix(domain)
                .is_some_and(|rest| rest.ends_with('.'));
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = host.chars().collect();
    let (mut p, mut t) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(position) = star {
            p = position + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

impl BitAnd for Matcher {
    type Output = Matcher;

    fn bitand(self, other: Matcher) -> Matcher {
        match self {
            Matcher::AllOf(mut matchers) => {
                matchers.push(other);
                Matcher::AllOf(matchers)
            }
            first => Matcher::AllOf(alloc::vec![first, other]),
        }
    }
}

impl BitOr for Matcher {
    type Output = Matcher;

    fn bitor(self, other: Matcher) -> Matcher {
        match self {
            Matcher::AnyOf(mut matchers) => {
                matchers.push(other);
                Matcher::AnyOf(matchers)
            }
            first => Matcher::AnyOf(alloc::vec![first, other]),
        }
    }
}

impl Not for Matcher {
    type Output = Matcher;

    fn not(self) -> Matcher {
        match self {
            Matcher::Not(inner) => *inner,
            other => Matcher::Not(alloc::boxed::Box::new(other)),
        }
    }
}

/// Splits `host`, `host:port`, `[v6]` and `[v6]:port`; a bare IPv6 address has no port.
pub(crate) fn split_host_port(text: &str) -> Result<(&str, Option<u16>)> {
    let port = |digits: &str| {
        digits
            .parse::<u16>()
            .map_err(|_| config("a rule's port is 0 to 65535"))
    };
    if let Some(rest) = text.strip_prefix('[')
        && let Some((host, after)) = rest.split_once(']')
        && host.parse::<IpAddr>().is_ok()
    {
        return match after.strip_prefix(':') {
            Some(digits) => Ok((host, Some(port(digits)?))),
            None if after.is_empty() => Ok((host, None)),
            None => Err(config("a rule's address has text after ]")),
        };
    }
    if text.matches(':').count() == 1 {
        let (host, digits) = text.split_once(':').unwrap_or((text, ""));
        return Ok((host, Some(port(digits)?)));
    }
    Ok((text, None))
}

fn as_network(text: &str) -> Option<IpNet> {
    let (address, _) = text.split_once('/').unwrap_or((text, ""));
    address.parse::<IpAddr>().ok()?;
    text.parse::<IpNet>().ok()
}

impl FromStr for Matcher {
    type Err = Error;

    /// Reads a configuration spelling: `re:<regex>` is a host regex (case-insensitive); an address
    /// or a CIDR network is [`Matcher::Network`]; `*` is [`Matcher::All`]; anything else is a
    /// [`Matcher::Host`] glob; a trailing `:<port>` adds a [`Matcher::Port`].
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for empty text, a bad port or (`re:`) an expression that does not compile
    /// or a build without feature `regex`.
    fn from_str(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.is_empty() {
            return Err(config("a rule pattern must be a non-empty string"));
        }
        if let Some(expression) = text.strip_prefix("re:") {
            #[cfg(feature = "regex")]
            return Self::host_regex(expression, true);
            #[cfg(not(feature = "regex"))]
            {
                let _ = expression;
                return Err(config("a `re:` pattern needs the `regex` feature"));
            }
        }
        if text == "*" {
            return Ok(Self::All);
        }
        if let Some(network) = as_network(text) {
            return Ok(Self::Network(alloc::vec![network]));
        }
        let (host, port) = split_host_port(text)?;
        let matcher = match as_network(host) {
            Some(network) => Self::Network(alloc::vec![network]),
            None if host.is_empty() => return Err(config("a rule pattern needs a host")),
            None => Self::Host(alloc::vec![host.into()]),
        };
        Ok(match port {
            Some(port) => matcher & Self::Port(alloc::vec![PortSpec::Single(port)]),
            None => matcher,
        })
    }
}
