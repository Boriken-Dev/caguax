//! The server's settings: every bound, interval, count and size is a field with a default.
//!
//! The types are `#[non_exhaustive]`: start from `Default` and assign fields. They are also the
//! `[server]` table of a configuration file (unknown keys are errors); a duration there is a
//! number of seconds or a string such as `"30s"`, `"500ms"`, `"2m"`, `"1h"`, `"7d"`.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;
use std::path::PathBuf;

use serde::Deserialize;
use serde::de::{self, Deserializer};

use crate::error::{Result, config};
use crate::listen::ListenAddr;
use crate::upstream::Egress;

/// Parses a duration: a number of seconds (`30`, `0.25`) or a number with a unit `ms`, `s`, `m`,
/// `h` or `d`.
///
/// # Errors
///
/// [`Error::Config`] for text that is not a duration, a negative or a non-finite number.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    let split = text
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let value: f64 = number
        .trim()
        .parse()
        .map_err(|_| config("a duration is a number of seconds or a number with a unit"))?;
    let scale = match unit {
        "" | "s" => 1.0,
        "ms" => 0.001,
        "m" => 60.0,
        "h" => 3600.0,
        "d" => 86_400.0,
        _ => return Err(config("a duration's unit is ms, s, m, h or d")),
    };
    Duration::try_from_secs_f64(value * scale)
        .map_err(|_| config("a duration is a finite number that is not negative"))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Seconds {
    Number(f64),
    Text(String),
}

fn duration_of<E: de::Error>(seconds: Seconds) -> core::result::Result<Duration, E> {
    match seconds {
        Seconds::Number(number) => Duration::try_from_secs_f64(number)
            .map_err(|_| E::custom("expected a number of seconds that is not negative")),
        Seconds::Text(text) => parse_duration(&text).map_err(|error| E::custom(error.to_string())),
    }
}

fn de_duration<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<Duration, D::Error> {
    duration_of(Seconds::deserialize(deserializer)?)
}

fn de_optional_duration<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<Option<Duration>, D::Error> {
    Option::<Seconds>::deserialize(deserializer)?
        .map(duration_of)
        .transpose()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

fn de_listen<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<Vec<ListenAddr>, D::Error> {
    let texts = match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(text) => alloc::vec![text],
        OneOrMany::Many(texts) => texts,
    };
    let mut addresses = Vec::new();
    for text in texts {
        addresses.extend(
            crate::listen::parse_list(&text)
                .map_err(|error| de::Error::custom(error.to_string()))?,
        );
    }
    Ok(addresses)
}

fn de_egress<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<Option<Egress>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|text| {
            text.parse::<Egress>()
                .map_err(|error| de::Error::custom(error.to_string()))
        })
        .transpose()
}

/// The interception certificate authority: where its files are and how long a new one lives
/// (`[server.ca]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct CaSettings {
    /// The CA certificate (PEM). With [`key`](Self::key) it enables interception.
    pub certificate: Option<PathBuf>,
    /// The CA private key (PEM; encrypted PKCS#8 with [`password_env`](Self::password_env)).
    pub key: Option<PathBuf>,
    /// The environment variable holding the key's password, read when the key is loaded.
    pub password_env: Option<String>,
    /// How long a CA made by `caguax ca init` is valid (default 3650 days).
    #[serde(deserialize_with = "de_duration")]
    pub validity: Duration,
}

impl CaSettings {
    /// The default validity of a new CA: 3650 days.
    pub const DEFAULT_VALIDITY: Duration = Duration::from_secs(3650 * 86_400);

    /// Whether any path is set, so the CA is wanted.
    pub fn is_configured(&self) -> bool {
        self.certificate.is_some() || self.key.is_some()
    }
}

impl Default for CaSettings {
    fn default() -> Self {
        Self {
            certificate: None,
            key: None,
            password_env: None,
            validity: Self::DEFAULT_VALIDITY,
        }
    }
}

/// How intercepted tunnels get their certificates (`[server.intercept]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct InterceptSettings {
    /// How many per-host certificates are kept; the least recently used goes first (default 256).
    pub leaf_cache_capacity: usize,
    /// How long a minted certificate is valid (default 7 days).
    #[serde(deserialize_with = "de_duration")]
    pub leaf_validity: Duration,
}

impl Default for InterceptSettings {
    fn default() -> Self {
        Self {
            leaf_cache_capacity: 256,
            leaf_validity: Duration::from_secs(7 * 86_400),
        }
    }
}

/// The server's settings (`[server]` in a configuration file).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct ServerSettings {
    /// Where the HTTP proxy accepts (default `127.0.0.1:0`, a free port); empty means no HTTP
    /// proxy listener, tunnels only.
    #[serde(deserialize_with = "de_listen")]
    pub listen: Vec<ListenAddr>,
    /// Allows listening beyond loopback. Whoever reaches the proxy uses its client credentials, so
    /// this is off by default and listed by [`non_defaults`](Self::non_defaults).
    pub allow_remote: bool,
    /// Bounds each connect, TLS handshake, request-head read and upstream `CONNECT` reply
    /// (default 30 s; the config key `timeout` is the same setting).
    #[serde(alias = "timeout", deserialize_with = "de_duration")]
    pub connect_timeout: Duration,
    /// Ends a relayed direction that stays silent that long (default none).
    #[serde(deserialize_with = "de_optional_duration")]
    pub idle_timeout: Option<Duration>,
    /// Bounds the wait for a peer's reply to a TLS shutdown before the connection is dropped
    /// (default 2 s).
    #[serde(deserialize_with = "de_duration")]
    pub close_timeout: Duration,
    /// The pending-connection queue of each listening socket (default 128).
    pub listen_backlog: u32,
    /// Client connections served at once; a connection beyond it is closed at once (default 1024).
    pub max_connections: usize,
    /// The largest request head accepted (default 64 KiB).
    pub max_head_bytes: usize,
    /// The most header fields in a request head (default 100).
    pub max_headers: usize,
    /// Where upstream answers come from for routes that set none (default none: direct).
    #[serde(deserialize_with = "de_egress")]
    pub egress: Option<Egress>,
    /// A capture file receiving every relayed session; `.pcapng` selects pcapng (needs feature
    /// `pcap`).
    pub record: Option<PathBuf>,
    /// Logs one line per session opened and closed (default false).
    pub log_traffic: bool,
    /// A file receiving the TLS secrets of every TLS connection the proxy makes or ends, in the
    /// `SSLKEYLOGFILE` format. A secret itself; listed by [`non_defaults`](Self::non_defaults).
    pub keylog: Option<PathBuf>,
    /// The interception certificate authority.
    pub ca: CaSettings,
    /// How intercepted tunnels get their certificates.
    pub intercept: InterceptSettings,
    /// The copy buffer of each relayed direction (default 64 KiB).
    pub relay_buffer: usize,
    /// Serves several requests on one client connection (default true); false answers one request
    /// per connection and then closes.
    pub keep_alive: bool,
    /// The delay before racing the next address of a destination (default 250 ms).
    #[serde(deserialize_with = "de_duration")]
    pub happy_eyeballs_delay: Duration,
    /// The least time between two warnings about the same kind of refusal, such as
    /// `max_connections` being reached (default 10 s).
    #[serde(deserialize_with = "de_duration")]
    pub warn_interval: Duration,
    /// How long a listener waits after a failed `accept` before trying again (default 100 ms).
    #[serde(deserialize_with = "de_duration")]
    pub accept_error_delay: Duration,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            listen: alloc::vec![ListenAddr::loopback()],
            allow_remote: false,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: None,
            close_timeout: Duration::from_secs(2),
            listen_backlog: 128,
            max_connections: 1024,
            max_head_bytes: 64 * 1024,
            max_headers: 100,
            egress: None,
            record: None,
            log_traffic: false,
            keylog: None,
            ca: CaSettings::default(),
            intercept: InterceptSettings::default(),
            relay_buffer: 64 * 1024,
            keep_alive: true,
            happy_eyeballs_delay: Duration::from_millis(250),
            warn_interval: Duration::from_secs(10),
            accept_error_delay: Duration::from_millis(100),
        }
    }
}

impl ServerSettings {
    /// Refuses the values that mean nothing: a zero timeout, count or size.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] naming the setting.
    pub fn validate(&self) -> Result<()> {
        let positive_duration = [
            ("connect_timeout", self.connect_timeout),
            ("close_timeout", self.close_timeout),
            ("accept_error_delay", self.accept_error_delay),
        ];
        for (name, value) in positive_duration {
            if value.is_zero() {
                return Err(config(alloc::format!(
                    "server.{name}: expected a duration above zero"
                )));
            }
        }
        if self.idle_timeout.is_some_and(|value| value.is_zero()) {
            return Err(config(
                "server.idle_timeout: expected a duration above zero",
            ));
        }
        let positive = [
            ("listen_backlog", self.listen_backlog as usize),
            ("max_connections", self.max_connections),
            ("max_head_bytes", self.max_head_bytes),
            ("max_headers", self.max_headers),
            ("relay_buffer", self.relay_buffer),
            (
                "intercept.leaf_cache_capacity",
                self.intercept.leaf_cache_capacity,
            ),
        ];
        for (name, value) in positive {
            if value == 0 {
                return Err(config(alloc::format!(
                    "server.{name}: expected a number above zero"
                )));
            }
        }
        if self.intercept.leaf_validity.is_zero() || self.ca.validity.is_zero() {
            return Err(config("server: a certificate validity is above zero"));
        }
        Ok(())
    }

    /// What is looser than the defaults, as `setting = value` text: listening beyond loopback and
    /// a key log.
    pub fn non_defaults(&self) -> Vec<String> {
        let mut found = Vec::new();
        if self.allow_remote {
            found.push("server.allow_remote = true".into());
        }
        if self.keylog.is_some() {
            found.push("server.keylog = (a file of TLS secrets)".into());
        }
        found
    }
}
