//! What a rule sees about one incoming connection.

use alloc::string::String;
use core::fmt;
use core::net::SocketAddr;
use core::str::FromStr;

use crate::error::{Error, Result, config};

/// The listener name of connections through the HTTP proxy.
pub const LISTENER: &str = "proxy";

/// How the destination is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scheme {
    /// A `CONNECT` tunnel, or a forwarded `https://` request.
    Https,
    /// A forwarded plain-HTTP request.
    Http,
    /// A tunnel listener's connection.
    Tcp,
}

impl Scheme {
    /// The lower-case name: `https`, `http` or `tcp`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
            Self::Tcp => "tcp",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Scheme {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        match text.to_ascii_lowercase().as_str() {
            "https" => Ok(Self::Https),
            "http" => Ok(Self::Http),
            "tcp" => Ok(Self::Tcp),
            _ => Err(config("a scheme is https, http or tcp")),
        }
    }
}

/// Lower case, no IPv6 brackets, no trailing root dot.
pub(crate) fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

/// A connection the proxy is about to make, as rules see it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Connection {
    host: String,
    port: u16,
    scheme: Scheme,
    path: Option<String>,
    client: Option<SocketAddr>,
    listener: String,
}

impl Connection {
    /// A `CONNECT`-style connection to `host:port`; the host is normalised.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for an empty host or port 0.
    pub fn new(host: &str, port: u16) -> Result<Self> {
        Self::builder(host, port).build()
    }

    /// A builder for a connection to `host:port`.
    pub fn builder(host: &str, port: u16) -> ConnectionBuilder {
        ConnectionBuilder {
            connection: Self {
                host: normalize_host(host),
                port,
                scheme: Scheme::Https,
                path: None,
                client: None,
                listener: String::new(),
            },
        }
    }

    /// The normalised host: lower case, no brackets, no trailing dot.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The destination port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// How the destination is reached.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The request path and query of a forwarded HTTP request.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// The client's address.
    pub fn client(&self) -> Option<SocketAddr> {
        self.client
    }

    /// The name of the listener that accepted the connection.
    pub fn listener(&self) -> &str {
        &self.listener
    }

    /// `host:port`, IPv6 hosts bracketed.
    pub fn authority(&self) -> String {
        join_host(&self.host, self.port)
    }

    /// The destination as a URL, the key an upstream is asked; the scheme's default port is left
    /// out, as clients and PAC scripts write it.
    pub fn url(&self) -> String {
        let (scheme, default) = match self.scheme {
            Scheme::Http => ("http", 80),
            Scheme::Https | Scheme::Tcp => ("https", 443),
        };
        let host = if self.port == default {
            bracket(&self.host)
        } else {
            self.authority()
        };
        alloc::format!("{scheme}://{host}{}", self.path.as_deref().unwrap_or("/"))
    }
}

pub(crate) fn bracket(host: &str) -> String {
    if host.contains(':') {
        alloc::format!("[{host}]")
    } else {
        host.into()
    }
}

pub(crate) fn join_host(host: &str, port: u16) -> String {
    alloc::format!("{}:{port}", bracket(host))
}

/// Builds a [`Connection`].
#[derive(Debug, Clone)]
#[must_use]
pub struct ConnectionBuilder {
    connection: Connection,
}

impl ConnectionBuilder {
    /// How the destination is reached (default [`Scheme::Https`]).
    pub fn scheme(mut self, scheme: Scheme) -> Self {
        self.connection.scheme = scheme;
        self
    }

    /// The path and query of a forwarded request (default none).
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.connection.path = Some(path.into());
        self
    }

    /// The client's address (default none).
    pub fn client(mut self, client: SocketAddr) -> Self {
        self.connection.client = Some(client);
        self
    }

    /// The name of the accepting listener (default empty).
    pub fn listener(mut self, listener: impl Into<String>) -> Self {
        self.connection.listener = listener.into();
        self
    }

    /// Validates and returns the connection.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Config`] for an empty host or port 0.
    pub fn build(self) -> Result<Connection> {
        if self.connection.host.is_empty() {
            return Err(config("a connection needs a host"));
        }
        if self.connection.port == 0 {
            return Err(config("a connection's port is 1 to 65535"));
        }
        Ok(self.connection)
    }
}
