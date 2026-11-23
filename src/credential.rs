//! Client credentials for mutual TLS: an identity, a PEM or PKCS#12 bundle, or a keystore query,
//! built into a rustls client configuration on first use.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use std::path::PathBuf;

use coqui_sslcontext::{
    ClientCertificates, Identity, IdentityQuery, IdentitySource as _, KeyPassword, Pin, Tls,
    TlsVersion, Trust,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;

use crate::error::{CredentialUnavailableError, Error, Result, config};

/// Where a credential's identity is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Backend {
    /// The best match among every system keystore (what a browser would send).
    #[default]
    System,
    /// A Windows CNG certificate store.
    Cng,
    /// The macOS Keychain.
    Keychain,
    /// A PKCS#11 module (smart cards, tokens). Needs feature `pkcs11`.
    Pkcs11,
}

impl Backend {
    /// The lower-case name used in configuration files.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Cng => "cng",
            Self::Keychain => "keychain",
            Self::Pkcs11 => "pkcs11",
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Backend {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        match text {
            "system" => Ok(Self::System),
            "cng" => Ok(Self::Cng),
            "keychain" => Ok(Self::Keychain),
            "pkcs11" => Ok(Self::Pkcs11),
            _ => Err(config(
                "backend must be \"system\", \"cng\", \"keychain\", \"pkcs11\" or \"pem\"",
            )),
        }
    }
}

/// Which Windows store location a CNG backend opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum StoreLocation {
    /// The current user's stores.
    #[default]
    User,
    /// The local machine's stores.
    Machine,
}

impl FromStr for StoreLocation {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        match text {
            "user" => Ok(Self::User),
            "machine" => Ok(Self::Machine),
            _ => Err(config("location must be \"user\" or \"machine\"")),
        }
    }
}

/// How a keystore backend is opened. Every field is optional; a PIN is never a field of a
/// configuration file.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct KeystoreOptions {
    /// The CNG store name (default `MY`).
    pub store: Option<String>,
    /// The CNG store location (default the user's).
    pub location: StoreLocation,
    /// A Keychain file (default every keychain the session searches).
    pub keychain: Option<PathBuf>,
    /// The PKCS#11 module (default p11-kit's proxy, then OpenSC's).
    pub module: Option<PathBuf>,
    /// The PKCS#11 token, by label or serial number.
    pub token: Option<String>,
    /// The PKCS#11 slot.
    pub slot: Option<u64>,
    /// Where the PIN comes from (default [`Pin::None`]: a key that needs one fails at once).
    pub pin: Pin,
}

type IdentityFn = Arc<dyn Fn() -> Result<Identity> + Send + Sync>;

#[derive(Clone)]
enum Source {
    Identity(Identity),
    IdentityWith(IdentityFn),
    Pem {
        certificate: Vec<u8>,
        key: Option<Vec<u8>>,
        password: KeyPassword,
    },
    Keystore {
        backend: Backend,
        options: KeystoreOptions,
        query: IdentityQuery,
    },
}

/// How the destination's certificate is checked.
#[derive(Debug, Clone, Default)]
struct Verification {
    verify: Option<bool>,
    cafile: Option<PathBuf>,
    capath: Option<PathBuf>,
    cadata: Option<Vec<u8>>,
    minimum_version: Option<TlsVersion>,
}

/// A client identity for mutual TLS, turned into a rustls client configuration on first use.
///
/// Building touches the keystore, so it runs on a blocking thread. The result is cached until
/// [`invalidate`](Self::invalidate); a failure is not cached, so the next connection tries again.
pub struct Credential {
    name: String,
    source: Source,
    verification: Verification,
    built: tokio::sync::Mutex<Option<Arc<Tls>>>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match &self.source {
            Source::Identity(_) | Source::IdentityWith(_) => "identity",
            Source::Pem { .. } => "pem",
            Source::Keystore { backend, .. } => backend.as_str(),
        };
        formatter
            .debug_struct("Credential")
            .field("name", &self.name)
            .field("source", &source)
            .finish_non_exhaustive()
    }
}

impl Credential {
    /// A credential for this identity.
    pub fn identity(identity: Identity) -> CredentialBuilder {
        CredentialBuilder::new(Source::Identity(identity))
    }

    /// A credential whose identity this function returns, called when the configuration is built.
    pub fn identity_with(
        identity: impl Fn() -> Result<Identity> + Send + Sync + 'static,
    ) -> CredentialBuilder {
        CredentialBuilder::new(Source::IdentityWith(Arc::new(identity)))
    }

    /// A credential from a certificate (and chain) and a key held in memory: PEM or DER. With no
    /// `key`, `certificate` holds both (combined PEM) or is a PKCS#12 bundle. `password` decrypts
    /// the key or the bundle.
    pub fn from_pem(
        certificate: impl Into<Vec<u8>>,
        key: Option<Vec<u8>>,
        password: KeyPassword,
    ) -> CredentialBuilder {
        CredentialBuilder::new(Source::Pem {
            certificate: certificate.into(),
            key,
            password,
        })
    }

    /// A credential found in a keystore: set the [`query`](CredentialBuilder::query) and the
    /// [`keystore_options`](CredentialBuilder::keystore_options) on the builder.
    pub fn keystore(backend: Backend) -> CredentialBuilder {
        CredentialBuilder::new(Source::Keystore {
            backend,
            options: KeystoreOptions::default(),
            query: IdentityQuery::builder().build(),
        })
    }

    /// The credential's name (empty when it has none).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The keystore backend, for a keystore credential.
    pub fn backend(&self) -> Option<Backend> {
        match &self.source {
            Source::Keystore { backend, .. } => Some(*backend),
            _ => None,
        }
    }

    /// The keystore options, for a keystore credential.
    pub fn options(&self) -> Option<&KeystoreOptions> {
        match &self.source {
            Source::Keystore { options, .. } => Some(options),
            _ => None,
        }
    }

    /// The identity query, for a keystore credential.
    pub fn query(&self) -> Option<&IdentityQuery> {
        match &self.source {
            Source::Keystore { query, .. } => Some(query),
            _ => None,
        }
    }

    /// Forgets the built configuration; the next use looks the identity up again (a renewed
    /// certificate).
    pub async fn invalidate(&self) {
        *self.built.lock().await = None;
    }

    /// The client configuration for a connection to `host`, built on first call.
    ///
    /// # Errors
    ///
    /// [`Error::CredentialUnavailable`] when the identity cannot be found or loaded.
    pub async fn tls_config(&self, host: &str) -> Result<Arc<rustls::ClientConfig>> {
        let tls = {
            let mut built = self.built.lock().await;
            if let Some(tls) = built.as_ref() {
                Arc::clone(tls)
            } else {
                let source = self.source.clone();
                let verification = self.verification.clone();
                let name = self.name.clone();
                let tls = tokio::task::spawn_blocking(move || build(&source, &verification, &name))
                    .await
                    .map_err(|_| {
                        CredentialUnavailableError::new(&self.name, "the keystore thread ended")
                    })??;
                let tls = Arc::new(tls);
                *built = Some(Arc::clone(&tls));
                tls
            }
        };
        tls.client_config(host)
            .map_err(|error| CredentialUnavailableError::new(&self.name, error).into())
    }

    /// Whether the destination's certificate is not verified.
    pub fn verification_disabled(&self) -> bool {
        self.verification.verify == Some(false)
    }
}

/// Builds a [`Credential`].
#[derive(Debug)]
#[must_use]
pub struct CredentialBuilder {
    name: String,
    source: Source,
    verification: Verification,
}

impl fmt::Debug for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Source")
    }
}

impl CredentialBuilder {
    fn new(source: Source) -> Self {
        Self {
            name: String::new(),
            source,
            verification: Verification::default(),
        }
    }

    /// Names the credential (default empty).
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Whether the destination's certificate is verified (default true). `false` accepts any
    /// certificate and is listed by `non_defaults()`.
    pub fn verify(mut self, verify: bool) -> Self {
        self.verification.verify = Some(verify);
        self
    }

    /// Trusts only the roots in this PEM file instead of the system's.
    pub fn cafile(mut self, path: impl Into<PathBuf>) -> Self {
        self.verification.cafile = Some(path.into());
        self
    }

    /// Trusts also the roots in every file of this directory.
    pub fn capath(mut self, path: impl Into<PathBuf>) -> Self {
        self.verification.capath = Some(path.into());
        self
    }

    /// Trusts also these roots (PEM text or one DER certificate).
    pub fn cadata(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.verification.cadata = Some(data.into());
        self
    }

    /// The lowest TLS version offered (default 1.2).
    pub fn minimum_version(mut self, version: TlsVersion) -> Self {
        self.verification.minimum_version = Some(version);
        self
    }

    /// How a keystore backend is opened; ignored by the other sources.
    pub fn keystore_options(mut self, options: KeystoreOptions) -> Self {
        if let Source::Keystore { options: slot, .. } = &mut self.source {
            *slot = options;
        }
        self
    }

    /// Which identity a keystore backend picks; ignored by the other sources.
    pub fn query(mut self, query: IdentityQuery) -> Self {
        if let Source::Keystore { query: slot, .. } = &mut self.source {
            *slot = query;
        }
        self
    }

    /// The credential. Nothing is read until it is first used.
    pub fn build(self) -> Credential {
        Credential {
            name: self.name,
            source: self.source,
            verification: self.verification,
            built: tokio::sync::Mutex::new(None),
        }
    }
}

impl From<CredentialBuilder> for crate::route::TlsSource {
    fn from(builder: CredentialBuilder) -> Self {
        Self::Credential(Arc::new(builder.build()))
    }
}

fn unavailable(name: &str, reason: impl fmt::Display) -> Error {
    CredentialUnavailableError::new(name, reason).into()
}

fn roots(verification: &Verification, name: &str) -> Result<Vec<CertificateDer<'static>>> {
    fn add_pem(roots: &mut Vec<CertificateDer<'static>>, bytes: &[u8]) {
        for certificate in CertificateDer::pem_slice_iter(bytes).flatten() {
            roots.push(certificate.into_owned());
        }
    }
    let mut roots = Vec::new();
    if let Some(path) = &verification.cafile {
        let bytes = std::fs::read(path)
            .map_err(|error| unavailable(name, alloc::format!("cafile: {}", error.kind())))?;
        add_pem(&mut roots, &bytes);
    }
    if let Some(path) = &verification.capath {
        let entries = std::fs::read_dir(path)
            .map_err(|error| unavailable(name, alloc::format!("capath: {}", error.kind())))?;
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        for file in files {
            if let Ok(bytes) = std::fs::read(file) {
                add_pem(&mut roots, &bytes);
            }
        }
    }
    if let Some(data) = &verification.cadata {
        let before = roots.len();
        add_pem(&mut roots, data);
        if roots.len() == before && !data.is_empty() {
            roots.push(CertificateDer::from(data.clone()));
        }
    }
    Ok(roots)
}

fn identity_from_pem(
    certificate: &[u8],
    key: Option<&[u8]>,
    password: &KeyPassword,
) -> core::result::Result<Identity, coqui_sslcontext::Error> {
    match key {
        Some(key) => {
            if certificate
                .windows(10)
                .any(|window| window == b"-----BEGIN")
                || key.windows(10).any(|window| window == b"-----BEGIN")
            {
                Identity::from_pem_with(certificate, key, password)
            } else {
                Identity::from_der([certificate], key)
            }
        }
        None if certificate
            .windows(10)
            .any(|window| window == b"-----BEGIN") =>
        {
            Identity::from_pem_with(certificate, certificate, password)
        }
        None => Identity::from_pkcs12(certificate, password),
    }
}

fn keystore_identity(
    backend: Backend,
    options: &KeystoreOptions,
    query: &IdentityQuery,
    name: &str,
) -> Result<Option<Identity>> {
    // `Ok(None)` means the system selector looks the query up at the handshake.
    let found = |result: core::result::Result<Identity, coqui_sslcontext::Error>| {
        result.map(Some).map_err(|error| unavailable(name, error))
    };
    match backend {
        Backend::System => Ok(None),
        Backend::Cng => {
            #[cfg(windows)]
            {
                let store = options.store.as_deref().unwrap_or("MY");
                let source = match options.location {
                    StoreLocation::User => coqui_sslcontext::CngSource::current_user(store),
                    StoreLocation::Machine => coqui_sslcontext::CngSource::local_machine(store),
                }
                .map_err(|error| unavailable(name, error))?;
                found(source.pin(options.pin.clone()).find_one(query))
            }
            #[cfg(not(windows))]
            {
                let _ = (options, query, found);
                Err(unavailable(name, "the cng backend needs Windows"))
            }
        }
        Backend::Keychain => {
            #[cfg(target_os = "macos")]
            {
                let mut source = coqui_sslcontext::KeychainSource::new().pin(options.pin.clone());
                if let Some(path) = &options.keychain {
                    source = source.keychain(path);
                }
                found(source.find_one(query))
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (options, query, found);
                Err(unavailable(name, "the keychain backend needs macOS"))
            }
        }
        Backend::Pkcs11 => {
            #[cfg(feature = "pkcs11")]
            {
                let builder = match &options.module {
                    Some(module) => coqui_sslcontext::Pkcs11Source::builder(module),
                    None => coqui_sslcontext::Pkcs11Source::discover(
                        &coqui_sslcontext::Pkcs11Settings::default(),
                    )
                    .ok_or_else(|| {
                        unavailable(name, "no PKCS#11 module was found; name one with `module`")
                    })?,
                };
                let mut builder = builder.pin(options.pin.clone());
                if let Some(token) = &options.token {
                    builder = builder.token(token.clone());
                }
                if let Some(slot) = options.slot {
                    builder = builder.slot(slot);
                }
                found(builder.build().find_one(query))
            }
            #[cfg(not(feature = "pkcs11"))]
            {
                let _ = (options, query, found);
                Err(unavailable(
                    name,
                    "the pkcs11 backend needs the `pkcs11` feature",
                ))
            }
        }
    }
}

fn build(source: &Source, verification: &Verification, name: &str) -> Result<Tls> {
    let mut builder = Tls::builder();
    let trust = if verification.verify == Some(false) {
        Trust::Disabled
    } else {
        let roots = roots(verification, name)?;
        if verification.cafile.is_some()
            || verification.capath.is_some()
            || verification.cadata.is_some()
        {
            if roots.is_empty() {
                return Err(unavailable(name, "the trusted roots hold no certificate"));
            }
            Trust::Roots(roots)
        } else {
            Trust::System
        }
    };
    builder = builder.trust(trust);
    if let Some(version) = verification.minimum_version {
        builder = builder.minimum_version(version);
    }
    let certificates = match source {
        Source::Identity(identity) => ClientCertificates::Identity(identity.clone()),
        Source::IdentityWith(identity) => ClientCertificates::Identity(identity()?),
        Source::Pem {
            certificate,
            key,
            password,
        } => ClientCertificates::Identity(
            identity_from_pem(certificate, key.as_deref(), password)
                .map_err(|error| unavailable(name, error))?,
        ),
        Source::Keystore {
            backend,
            options,
            query,
        } => {
            builder = builder.pin(options.pin.clone());
            match keystore_identity(*backend, options, query, name)? {
                Some(identity) => ClientCertificates::Identity(identity),
                None => ClientCertificates::Query(query.clone()),
            }
        }
    };
    builder
        .client_certificates(certificates)
        .build()
        .map_err(|error| unavailable(name, error))
}

impl Credential {
    /// What this credential has loosened from the strict defaults, as `setting = value` text.
    pub fn non_defaults(&self) -> Vec<String> {
        let mut found = Vec::new();
        if self.verification_disabled() {
            let label = if self.name.is_empty() {
                "credential"
            } else {
                &self.name
            };
            found.push(alloc::format!("credentials.{label}.verify = false"));
        }
        found
    }
}
