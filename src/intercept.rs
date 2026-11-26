//! TLS interception: the proxy ends the client's TLS with a certificate it mints.
//!
//! A `CONNECT` whose route is [`Action::Tls`] is intercepted: the proxy
//! connects to the destination first (with the route's client credential), answers `200`,
//! completes the client's handshake with a leaf issued by its CA for the `CONNECT` host, and
//! relays the plaintext between the two TLS connections. Clients must trust the CA.
//!
//! Create the CA with [`create_ca`] so it is name-constrained to exactly the hosts the TLS rules
//! intercept: a leaked key then cannot vouch for anything else.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;
use std::sync::Mutex;

use coqui_sslcontext::{
    CertificateAuthority, IssueSettings, KeyLogging, KeyPassword, KeySettings, Secret, ServerTls,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use crate::error::{Error, Result, config};
use crate::route::{Action, Router};
use crate::rules::Matcher;
use crate::settings::{CaSettings, InterceptSettings};

/// The common name of a CA made without one.
pub const DEFAULT_CA_NAME: &str = "caguax local CA";

struct Cache {
    tick: u64,
    entries: BTreeMap<String, (u64, Arc<rustls::ServerConfig>)>,
}

/// Server-side TLS for intercepted hosts, minted from a CA. Leaves (one per host) are cached, the
/// least recently used going first.
pub struct Interceptor {
    ca: CertificateAuthority,
    settings: InterceptSettings,
    keylog: Option<Arc<dyn rustls::KeyLog>>,
    cache: Mutex<Cache>,
}

impl fmt::Debug for Interceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Interceptor")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Interceptor {
    /// An interceptor minting leaves from `ca` as `settings` say.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for a leaf cache of no entries or a leaf validity of zero.
    pub fn new(ca: CertificateAuthority, settings: InterceptSettings) -> Result<Self> {
        if settings.leaf_cache_capacity == 0 || settings.leaf_validity.is_zero() {
            return Err(config(
                "the leaf cache holds at least one certificate and a leaf is valid for some time",
            ));
        }
        Ok(Self {
            ca,
            settings,
            keylog: None,
            cache: Mutex::new(Cache {
                tick: 0,
                entries: BTreeMap::new(),
            }),
        })
    }

    /// Where minted configurations log TLS secrets (set by the server from its `keylog`).
    #[must_use]
    pub fn with_keylog(mut self, keylog: Arc<dyn rustls::KeyLog>) -> Self {
        self.keylog = Some(keylog);
        self
    }

    /// The CA clients must trust.
    pub fn ca(&self) -> &CertificateAuthority {
        &self.ca
    }

    /// The configured key log.
    pub fn keylog(&self) -> Option<&Arc<dyn rustls::KeyLog>> {
        self.keylog.as_ref()
    }

    /// The settings in force.
    pub fn settings(&self) -> &InterceptSettings {
        &self.settings
    }

    /// The configuration presenting a leaf for `host`, minted on first use. Blocking.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Tls`] when the leaf cannot be issued.
    pub fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        {
            let mut cache = self.cache();
            cache.tick += 1;
            let tick = cache.tick;
            if let Some((used, config)) = cache.entries.get_mut(host) {
                *used = tick;
                return Ok(Arc::clone(config));
            }
        }
        let identity = self
            .ca
            .leaf([host])
            .validity(self.settings.leaf_validity)
            .issue()?
            .identity()?;
        let served = ServerTls::builder(identity)
            .alpn([b"http/1.1".to_vec()])
            .key_log(KeyLogging::Off)
            .build()?
            .server_config();
        let config = match &self.keylog {
            Some(keylog) => {
                let mut copy = (*served).clone();
                copy.key_log = Arc::clone(keylog);
                Arc::new(copy)
            }
            None => served,
        };
        let mut cache = self.cache();
        cache.tick += 1;
        let tick = cache.tick;
        cache
            .entries
            .insert(host.to_owned(), (tick, Arc::clone(&config)));
        while cache.entries.len() > self.settings.leaf_cache_capacity {
            let oldest = cache
                .entries
                .iter()
                .min_by_key(|(_, (used, _))| *used)
                .map(|(host, _)| host.clone());
            match oldest {
                Some(host) => {
                    cache.entries.remove(&host);
                }
                None => break,
            }
        }
        Ok(config)
    }

    /// Completes the TLS handshake of an intercepted client, with a leaf for `host`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Tls`] when the leaf cannot be issued, [`crate::Error::Io`] when the handshake fails and
    /// [`crate::Error::Timeout`] when it takes longer than `timeout`.
    pub async fn accept<IO>(
        self: &Arc<Self>,
        host: &str,
        client: IO,
        timeout: Duration,
    ) -> Result<tokio_rustls::server::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let minter = Arc::clone(self);
        let name = host.to_owned();
        let config = tokio::task::spawn_blocking(move || minter.server_config(&name))
            .await
            .map_err(|_| Error::Timeout("the certificate thread ended"))??;
        tokio::time::timeout(timeout, TlsAcceptor::from(config).accept(client))
            .await
            .map_err(|_| Error::Timeout("the client's TLS handshake"))?
            .map_err(Error::Io)
    }

    /// What is looser than the defaults: a CA that is not name-constrained.
    pub fn non_defaults(&self) -> Vec<String> {
        let mut found = Vec::new();
        if !is_name_constrained(&self.ca) {
            found.push("server.ca = a CA that is not name-constrained".into());
        }
        found
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Whether the CA certificate carries a name-constraints extension (OID 2.5.29.30) with at least
/// one permitted subtree. A certificate that cannot be parsed, has no such extension or only
/// excludes names is not constrained.
pub fn is_name_constrained(ca: &CertificateAuthority) -> bool {
    use x509_cert::der::Decode as _;
    use x509_cert::ext::pkix::NameConstraints;
    let Ok(certificate) = x509_cert::Certificate::from_der(ca.certificate_der().as_ref()) else {
        return false;
    };
    certificate
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|extension| {
            extension.extn_id == x509_cert::der::oid::db::rfc5280::ID_CE_NAME_CONSTRAINTS
        })
        .filter_map(|extension| NameConstraints::from_der(extension.extn_value.as_bytes()).ok())
        .any(|constraints| {
            constraints
                .permitted_subtrees
                .is_some_and(|subtrees| !subtrees.is_empty())
        })
}

fn names(matcher: &Matcher) -> Option<Vec<String>> {
    match matcher {
        Matcher::Host(patterns) => Some(patterns.clone()),
        Matcher::Network(networks) => Some(networks.iter().map(ToString::to_string).collect()),
        Matcher::AnyOf(matchers) => {
            let mut found = Vec::new();
            for part in matchers {
                found.extend(names(part)?);
            }
            Some(found)
        }
        // Every branch must hold, so any one bounding branch bounds the rule.
        Matcher::AllOf(matchers) => matchers.iter().find_map(names),
        _ => None,
    }
}

/// The hosts and networks the router's TLS routes can intercept, or `None` when some TLS rule (or
/// the default route) is not bounded by `Host` and `Network` matchers, so no name constraint can
/// cover it.
pub fn permitted_names(router: &Router) -> Option<Vec<String>> {
    if router.default_route().action() == Action::Tls {
        return None;
    }
    let mut found: Vec<String> = Vec::new();
    for rule in router.rules() {
        if rule.route().action() != Action::Tls {
            continue;
        }
        for name in names(rule.matcher())? {
            if !found.contains(&name) {
                found.push(name);
            }
        }
    }
    Some(found)
}

/// How [`create_ca`] makes a certificate authority.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CaOptions {
    /// The CA's common name (default `caguax local CA`).
    pub common_name: String,
    /// Name-constrains the CA to [`permitted_names`] (default true). With `false` the CA can vouch
    /// for any site: protect its key accordingly.
    pub constrain: bool,
    /// How long the CA is valid (default 3650 days).
    pub validity: Duration,
}

impl Default for CaOptions {
    fn default() -> Self {
        Self {
            common_name: DEFAULT_CA_NAME.into(),
            constrain: true,
            validity: CaSettings::DEFAULT_VALIDITY,
        }
    }
}

fn env_password(name: &str) -> KeyPassword {
    let name = name.to_owned();
    KeyPassword::callback(move || {
        std::env::var(&name)
            .ok()
            .filter(|value| !value.is_empty())
            .map(Secret::new)
    })
}

/// Reads the CA the settings name: PEM certificate and key, the key's password from the
/// environment variable `password_env` names (read now).
///
/// # Errors
///
/// [`crate::Error::Config`] when a path is missing or unreadable; [`crate::Error::Tls`] when the files are not a
/// CA certificate and its key or the password is wrong.
pub fn load_ca(settings: &CaSettings, keys: &KeySettings) -> Result<CertificateAuthority> {
    let (Some(certificate), Some(key)) = (&settings.certificate, &settings.key) else {
        return Err(config("server.ca: certificate and key are both needed"));
    };
    let read = |what: &str, path: &std::path::Path| {
        std::fs::read(path).map_err(|error| {
            config(alloc::format!(
                "server.ca.{what}: cannot read: {}",
                error.kind()
            ))
        })
    };
    let certificate = read("certificate", certificate)?;
    let key = read("key", key)?;
    let password = settings
        .password_env
        .as_deref()
        .map_or(KeyPassword::None, env_password);
    Ok(CertificateAuthority::from_pem_with_settings(
        &certificate,
        &key,
        &password,
        keys,
    )?)
}

/// A new CA for intercepting the router's TLS routes.
///
/// With `constrain` (the default) it is name-constrained to [`permitted_names`]; when the rules
/// cannot be bounded that way this is an error rather than an unconstrained CA.
///
/// # Errors
///
/// [`crate::Error::Config`] when the rules cannot be bounded and `constrain` is set; [`crate::Error::Tls`] when
/// the CA cannot be made.
pub fn create_ca(router: &Router, options: CaOptions) -> Result<CertificateAuthority> {
    let mut permitted: Vec<String> = Vec::new();
    if options.constrain {
        let names = permitted_names(router).ok_or_else(|| {
            config(
                "some TLS rule is not bounded by host or network matchers, so the CA cannot be \
                 name-constrained; ask for an unconstrained CA to accept that",
            )
        })?;
        permitted = names
            .into_iter()
            .map(|name| name.strip_prefix('.').map_or(name.clone(), String::from))
            .collect();
    }
    let mut settings = IssueSettings::default();
    settings.ca_validity = options.validity;
    Ok(CertificateAuthority::builder(options.common_name)
        .permitted(permitted)
        .settings(settings)
        .create()?)
}
