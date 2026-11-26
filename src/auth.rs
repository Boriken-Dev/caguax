//! The login the HTTP proxy listener requires (`server.auth`).
//!
//! Anything that reaches the listener acts with the proxy's client certificates and upstream
//! logins, so a request must carry `Proxy-Authorization: Basic` by default. The password is
//! compared in constant time and never appears in a log, a `Debug` or an error.

use alloc::string::String;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use subtle::ConstantTimeEq as _;

use crate::error::{Result, config};

/// The user name of a generated login, and the default of a named one.
pub const DEFAULT_USER: &str = "caguax";

const PASSWORD_BYTES: usize = 32;

/// A user name and a password. `Debug` shows the user only.
#[derive(Clone)]
pub struct Login {
    user: String,
    password: String,
}

impl core::fmt::Debug for Login {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Login")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl Login {
    /// A login of `user` and `password`.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for an empty password, or a user that is empty or holds `:` or a
    /// control character.
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Result<Self> {
        let (user, password) = (user.into(), password.into());
        if user.is_empty() || user.contains(':') || user.chars().any(char::is_control) {
            return Err(config(
                "a login's user is not empty and holds no ':' or control character",
            ));
        }
        if password.is_empty() || password.chars().any(char::is_control) {
            return Err(config(
                "a login's password is not empty and holds no control character",
            ));
        }
        Ok(Self { user, password })
    }

    fn generate(user: &str) -> Result<Self> {
        let mut secret = [0_u8; PASSWORD_BYTES];
        getrandom::fill(&mut secret).map_err(|error| config(error.to_string()))?;
        Self::new(user, URL_SAFE_NO_PAD.encode(secret))
    }

    /// The user name.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The password: a secret, to hand to the client and nowhere else.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// `user:password`, the form `curl -U` takes.
    pub fn userinfo(&self) -> String {
        alloc::format!("{}:{}", self.user, self.password)
    }

    /// The `Proxy-Authorization` value: `Basic` and the base64 of `user:password`.
    pub fn header_value(&self) -> String {
        alloc::format!("Basic {}", STANDARD.encode(self.userinfo()))
    }

    /// Whether `value` (a `Proxy-Authorization` header value) is this login, compared in constant
    /// time.
    pub(crate) fn accepts(&self, value: &[u8]) -> bool {
        let Some(split) = value.iter().position(|byte| *byte == b' ') else {
            return false;
        };
        let (scheme, rest) = value.split_at(split);
        if !scheme.eq_ignore_ascii_case(b"basic") {
            return false;
        }
        let Ok(decoded) = STANDARD.decode(rest.trim_ascii()) else {
            return false;
        };
        bool::from(decoded.ct_eq(self.userinfo().as_bytes()))
    }

    /// Whether any of the `Proxy-Authorization` values is this login (every one is compared).
    pub(crate) fn accepts_any<'a>(&self, values: impl Iterator<Item = &'a [u8]>) -> bool {
        values.fold(false, |found, value| self.accepts(value) | found)
    }
}

/// Whether the HTTP proxy listener asks for a login, and which.
///
/// Required by default, with a password generated when the server starts; `none` turns the check
/// off and is listed by [`ServerSettings::non_defaults`](crate::ServerSettings::non_defaults).
/// In a configuration file: `auth = "none"`, `auth = "generated"`, or a table with `user` and one
/// of `password_env`, `password_file` or (for a generated password) `file`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Auth {
    /// A random password made when the server starts and kept while it runs (a reload keeps it);
    /// written with the user to `file` as `user:password` when that is set. The file is replaced
    /// whole and, on Unix, readable by its owner only.
    Generated {
        /// The user name.
        user: String,
        /// Where the login is written.
        file: Option<PathBuf>,
    },
    /// The password is in this environment variable, read when the settings are applied.
    Env {
        /// The user name.
        user: String,
        /// The variable's name.
        name: String,
    },
    /// The password is the first line of this file, read when the settings are applied.
    File {
        /// The user name.
        user: String,
        /// The file.
        path: PathBuf,
    },
    /// This login.
    Login(Login),
    /// No check: any local process uses the proxy's credentials.
    None,
}

impl Default for Auth {
    fn default() -> Self {
        Self::Generated {
            user: DEFAULT_USER.into(),
            file: None,
        }
    }
}

impl Auth {
    /// Whether the check is off.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// The login for these settings: the named one, or the generated one (`previous`, when it is
    /// the same user, so a reload keeps it).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for a variable that is unset or empty, a file that cannot be read
    /// or has no password, or a generated login that cannot be written.
    pub(crate) fn resolve(&self, previous: Option<&Login>) -> Result<Option<Login>> {
        match self {
            Self::None => Ok(None),
            Self::Login(login) => Ok(Some(login.clone())),
            Self::Env { user, name } => {
                let password = std::env::var(name).unwrap_or_default();
                Login::new(user, password.trim_end_matches(['\r', '\n']))
                    .map(Some)
                    .map_err(|_| {
                        config(alloc::format!(
                            "server.auth: the variable {name} is unset or holds no usable password"
                        ))
                    })
            }
            Self::File { user, path } => {
                let text = std::fs::read_to_string(path).map_err(|error| {
                    config(alloc::format!(
                        "server.auth: cannot read the password file: {}",
                        error.kind()
                    ))
                })?;
                let line = text.lines().next().unwrap_or_default();
                Login::new(user, line).map(Some).map_err(|_| {
                    config("server.auth: the password file's first line is no usable password")
                })
            }
            Self::Generated { user, file } => {
                if let Some(previous) = previous.filter(|login| login.user == *user) {
                    return Ok(Some(previous.clone()));
                }
                let login = Login::generate(user)?;
                if let Some(file) = file {
                    let mut text = login.userinfo();
                    text.push('\n');
                    crate::fileio::write_private(file, text.as_bytes()).map_err(|error| {
                        config(alloc::format!(
                            "server.auth: cannot write the login file: {}",
                            error.kind()
                        ))
                    })?;
                    tracing::info!(
                        target: "caguax",
                        "the proxy login is in {} (user {user})",
                        file.display()
                    );
                }
                Ok(Some(login))
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Raw {
    Text(String),
    Table(Table),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    user: Option<String>,
    password_env: Option<String>,
    password_file: Option<PathBuf>,
    file: Option<PathBuf>,
}

impl<'de> Deserialize<'de> for Auth {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        match Raw::deserialize(deserializer)? {
            Raw::Text(text) => match text.as_str() {
                "none" => Ok(Self::None),
                "generated" => Ok(Self::default()),
                _ => Err(de::Error::custom(
                    "expected \"none\", \"generated\" or a table",
                )),
            },
            Raw::Table(table) => {
                let user = table.user.unwrap_or_else(|| DEFAULT_USER.into());
                if user.is_empty() || user.contains(':') {
                    return Err(de::Error::custom("user is not empty and holds no ':'"));
                }
                match (table.password_env, table.password_file, table.file) {
                    (Some(name), None, None) => Ok(Self::Env { user, name }),
                    (None, Some(path), None) => Ok(Self::File { user, path }),
                    (None, None, file) => Ok(Self::Generated { user, file }),
                    _ => Err(de::Error::custom(
                        "password_env, password_file and file are alternatives (file is where a generated login is written)",
                    )),
                }
            }
        }
    }
}
