//! The errors of this crate.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Every failure this crate reports. A message names what failed and never quotes a document, a
/// credential or a PIN.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A configuration document or an argument is malformed or inconsistent.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The destination, or every upstream proxy on the way to it, could not be reached.
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
    /// A route's client credential could not be loaded.
    #[error(transparent)]
    CredentialUnavailable(#[from] CredentialUnavailableError),
    /// A rule rejected the connection.
    #[error(transparent)]
    Rejected(#[from] RejectedError),
    /// A proxy lookup or a proxy connection failed.
    #[error("proxy: {0}")]
    Proxy(#[from] coqui_proxy::Error),
    /// A TLS configuration, keystore or certificate could not be used.
    #[error("tls: {0}")]
    Tls(#[from] coqui_sslcontext::Error),
    /// A timeout elapsed; the text says which operation.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// An operating-system call failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A configuration document is malformed or inconsistent.
///
/// `path`, `line` and `column` locate the problem when known; the message never quotes the
/// document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigError {
    path: Option<String>,
    line: Option<usize>,
    column: Option<usize>,
    message: String,
}

impl ConfigError {
    /// An error with this message and no location.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ..Self::default()
        }
    }

    /// Names the file (or label) the problem is in.
    #[must_use]
    pub fn at_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Names the one-based line and column of the problem.
    #[must_use]
    pub fn at_position(mut self, line: Option<usize>, column: Option<usize>) -> Self {
        self.line = line;
        self.column = column;
        self
    }

    /// The file or label, when known.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// The one-based line, when known.
    pub fn line(&self) -> Option<usize> {
        self.line
    }

    /// The one-based column, when known.
    pub fn column(&self) -> Option<usize> {
        self.column
    }

    /// What is wrong, without the location.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut located = false;
        if let Some(path) = &self.path {
            write!(formatter, "{path}")?;
            located = true;
        }
        for part in [self.line, self.column].into_iter().flatten() {
            write!(formatter, ":{part}")?;
            located = true;
        }
        if located {
            formatter.write_str(": ")?;
        }
        formatter.write_str(&self.message)
    }
}

impl core::error::Error for ConfigError {}

/// The destination, or an upstream proxy on the way to it, could not be reached or refused the
/// connection. The message lists each attempt and never a proxy credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamError {
    message: String,
    attempts: Vec<String>,
}

impl UpstreamError {
    /// An error with one message and no listed attempt.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            attempts: Vec::new(),
        }
    }

    /// Every answer failed: `target` could not be reached, one entry per attempt.
    pub fn unreachable(target: &str, attempts: Vec<String>) -> Self {
        Self {
            message: alloc::format!("cannot reach {target}: {}", attempts.join("; ")),
            attempts,
        }
    }

    /// What each attempt reported, in the order tried (`direct` or `scheme://host:port`, a colon,
    /// the reason).
    pub fn attempts(&self) -> &[String] {
        &self.attempts
    }
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl core::error::Error for UpstreamError {}

/// A route's client credential could not be loaded: the keystore entry is missing, there is no PIN
/// or the keystore failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialUnavailableError {
    credential: String,
    reason: String,
}

impl CredentialUnavailableError {
    pub(crate) fn new(credential: &str, reason: impl fmt::Display) -> Self {
        Self {
            credential: credential.into(),
            reason: alloc::format!("{reason}"),
        }
    }

    /// The credential's name (empty when it has none).
    pub fn credential(&self) -> &str {
        &self.credential
    }
}

impl fmt::Display for CredentialUnavailableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.credential.is_empty() {
            write!(formatter, "client credential unavailable: {}", self.reason)
        } else {
            write!(
                formatter,
                "client credential `{}` unavailable: {}",
                self.credential, self.reason
            )
        }
    }
}

impl core::error::Error for CredentialUnavailableError {}

/// A rule rejected the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedError {
    authority: String,
}

impl RejectedError {
    /// A rejection of `authority` (`host:port`).
    pub fn new(authority: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
        }
    }
}

impl fmt::Display for RejectedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} is not allowed", self.authority)
    }
}

impl core::error::Error for RejectedError {}

/// The result type of this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

pub(crate) fn config(message: impl Into<String>) -> Error {
    Error::Config(ConfigError::new(message))
}
