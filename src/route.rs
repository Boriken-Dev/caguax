//! Routes (what to do with a connection) and the router that picks one.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::connection::Connection;
use crate::credential::Credential;
use crate::error::{Error, Result, config};
use crate::policy::{CredentialPolicy, ProxyPolicy};
use crate::rules::Matcher;
use crate::upstream::Egress;

/// What the proxy does with a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Action {
    /// Relay bytes to the destination unchanged.
    #[default]
    Direct,
    /// The proxy makes the TLS connection to the destination with the route's client
    /// configuration. Plain HTTP is upgraded to HTTPS; a `CONNECT` tunnel is intercepted (the
    /// client's TLS ends at the proxy).
    Tls,
    /// Refuse the connection.
    Reject,
}

impl Action {
    /// The lower-case name: `direct`, `tls` or `reject`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Tls => "tls",
            Self::Reject => "reject",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Action {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        match text {
            "direct" => Ok(Self::Direct),
            "tls" => Ok(Self::Tls),
            "reject" => Ok(Self::Reject),
            _ => Err(config("action must be \"tls\", \"direct\" or \"reject\"")),
        }
    }
}

/// The client TLS the proxy uses to reach a destination.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TlsSource {
    /// A rustls client configuration used as is.
    Config(Arc<rustls::ClientConfig>),
    /// A credential that builds one on first use.
    Credential(Arc<Credential>),
}

impl From<Arc<rustls::ClientConfig>> for TlsSource {
    fn from(config: Arc<rustls::ClientConfig>) -> Self {
        Self::Config(config)
    }
}

impl From<Arc<Credential>> for TlsSource {
    fn from(credential: Arc<Credential>) -> Self {
        Self::Credential(credential)
    }
}

impl From<Credential> for TlsSource {
    fn from(credential: Credential) -> Self {
        Self::Credential(Arc::new(credential))
    }
}

/// Where a route's upstream answers come from; the same values as the server's [`Egress`].
pub type UpstreamSpec = Egress;

/// The decision for one connection.
#[derive(Debug, Clone)]
pub struct Route {
    action: Action,
    tls: Option<TlsSource>,
    upstream: Option<UpstreamSpec>,
    name: String,
}

impl Route {
    /// A route that relays bytes unchanged.
    pub fn direct() -> RouteBuilder {
        RouteBuilder::new(Action::Direct, None)
    }

    /// A route that refuses the connection.
    pub fn reject() -> RouteBuilder {
        RouteBuilder::new(Action::Reject, None)
    }

    /// A route on which the proxy owns the TLS to the destination.
    pub fn with_tls(tls: impl Into<TlsSource>) -> RouteBuilder {
        RouteBuilder::new(Action::Tls, Some(tls.into()))
    }

    /// What the proxy does.
    pub fn action(&self) -> Action {
        self.action
    }

    /// The client TLS of an [`Action::Tls`] route.
    pub fn tls(&self) -> Option<&TlsSource> {
        self.tls.as_ref()
    }

    /// The route's own upstream; `None` uses the server's egress.
    pub fn upstream(&self) -> Option<&UpstreamSpec> {
        self.upstream.as_ref()
    }

    /// The label shown in logs and by `check` (empty when none).
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Default for Route {
    fn default() -> Self {
        Self::direct().name("default").build()
    }
}

/// Builds a [`Route`].
#[derive(Debug, Clone)]
#[must_use]
pub struct RouteBuilder {
    route: Route,
}

impl RouteBuilder {
    fn new(action: Action, tls: Option<TlsSource>) -> Self {
        Self {
            route: Route {
                action,
                tls,
                upstream: None,
                name: String::new(),
            },
        }
    }

    /// The route's own upstream (default: the server's egress).
    pub fn upstream(mut self, upstream: impl Into<UpstreamSpec>) -> Self {
        self.route.upstream = Some(upstream.into());
        self
    }

    /// The label shown in logs and by `check` (default empty).
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.route.name = name.into();
        self
    }

    /// The finished route.
    pub fn build(self) -> Route {
        self.route
    }
}

impl From<RouteBuilder> for Route {
    fn from(builder: RouteBuilder) -> Self {
        builder.build()
    }
}

/// Anything that routes connections; [`Router`] is the built-in one.
pub trait Routing: Send + Sync {
    /// The route for `connection`.
    fn route(&self, connection: &Connection) -> Route;

    /// The [`Router`] behind this, when there is one: it lets the server answer `/proxy.pac` and
    /// report credentials that verify nothing.
    fn router(&self) -> Option<&Router> {
        None
    }

    /// The credential rules in force (default none: every kind takes its default).
    fn credential_policy(&self) -> Option<Arc<CredentialPolicy>> {
        None
    }

    /// The proxy rules in force (default none).
    fn proxy_policy(&self) -> Option<Arc<ProxyPolicy>> {
        None
    }
}

/// `route` applies to the connections `matcher` accepts.
#[derive(Debug, Clone)]
pub struct Rule {
    matcher: Matcher,
    route: Route,
    name: String,
}

impl Rule {
    /// A rule applying `route` to what `matcher` accepts.
    pub fn new(matcher: impl Into<Matcher>, route: impl Into<Route>) -> Self {
        Self {
            matcher: matcher.into(),
            route: route.into(),
            name: String::new(),
        }
    }

    /// A rule from a configuration pattern ([`Matcher`]'s `FromStr`).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for a pattern that does not parse.
    pub fn parse(pattern: &str, route: impl Into<Route>) -> Result<Self> {
        Ok(Self::new(pattern.parse::<Matcher>()?, route))
    }

    /// Names the rule (default empty).
    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// The predicate.
    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    /// The decision.
    pub fn route(&self) -> &Route {
        &self.route
    }

    /// The rule's name (empty when none).
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Which rule decided a connection.
#[derive(Debug, Clone, Copy)]
pub struct Explanation<'a> {
    /// The rule that matched; `None` when the default route applies.
    pub rule: Option<&'a Rule>,
    /// The route chosen.
    pub route: &'a Route,
}

/// Ordered rules: the first that matches decides, else the default route.
#[derive(Debug, Clone, Default)]
pub struct Router {
    rules: Vec<Rule>,
    default: Route,
    credentials: Option<Arc<CredentialPolicy>>,
    proxies: Option<Arc<ProxyPolicy>>,
}

impl Router {
    /// A router with no rule: everything goes direct.
    pub fn new() -> Self {
        Self::default()
    }

    /// A builder for a router with rules and a default route.
    pub fn builder() -> RouterBuilder {
        RouterBuilder {
            router: Self::default(),
        }
    }

    /// Appends a rule.
    pub fn add(&mut self, rule: Rule) -> &Rule {
        self.rules.push(rule);
        &self.rules[self.rules.len() - 1]
    }

    /// Appends a rule for `matcher`.
    pub fn add_match(&mut self, matcher: impl Into<Matcher>, route: impl Into<Route>) -> &Rule {
        self.add(Rule::new(matcher, route))
    }

    /// The rules in order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The route when no rule matches.
    pub fn default_route(&self) -> &Route {
        &self.default
    }

    /// The credential rules, when set.
    pub fn credential_policy(&self) -> Option<&Arc<CredentialPolicy>> {
        self.credentials.as_ref()
    }

    /// The proxy rules, when set.
    pub fn proxy_policy(&self) -> Option<&Arc<ProxyPolicy>> {
        self.proxies.as_ref()
    }

    /// The route for `connection`.
    pub fn route(&self, connection: &Connection) -> &Route {
        self.explain(connection).route
    }

    /// The rule that decided `connection` and its route.
    pub fn explain(&self, connection: &Connection) -> Explanation<'_> {
        for rule in &self.rules {
            if rule.matcher.matches(connection) {
                return Explanation {
                    rule: Some(rule),
                    route: &rule.route,
                };
            }
        }
        Explanation {
            rule: None,
            route: &self.default,
        }
    }
}

impl Routing for Router {
    fn route(&self, connection: &Connection) -> Route {
        Router::route(self, connection).clone()
    }

    fn router(&self) -> Option<&Router> {
        Some(self)
    }

    fn credential_policy(&self) -> Option<Arc<CredentialPolicy>> {
        self.credentials.clone()
    }

    fn proxy_policy(&self) -> Option<Arc<ProxyPolicy>> {
        self.proxies.clone()
    }
}

/// Builds a [`Router`].
#[derive(Debug, Clone)]
#[must_use]
pub struct RouterBuilder {
    router: Router,
}

impl RouterBuilder {
    /// Appends a rule.
    pub fn rule(mut self, rule: Rule) -> Self {
        self.router.rules.push(rule);
        self
    }

    /// Appends rules.
    pub fn rules(mut self, rules: impl IntoIterator<Item = Rule>) -> Self {
        self.router.rules.extend(rules);
        self
    }

    /// The route when no rule matches (default `direct`, named `default`).
    pub fn default_route(mut self, route: impl Into<Route>) -> Self {
        self.router.default = route.into();
        self
    }

    /// Which credential goes to which host (default none: every kind takes its default).
    pub fn credential_policy(mut self, policy: CredentialPolicy) -> Self {
        self.router.credentials = Some(Arc::new(policy));
        self
    }

    /// Which proxy serves which destination, for routes with no `upstream` of their own.
    pub fn proxy_policy(mut self, policy: ProxyPolicy) -> Self {
        self.router.proxies = Some(Arc::new(policy));
        self
    }

    /// The finished router.
    pub fn build(self) -> Router {
        self.router
    }
}
