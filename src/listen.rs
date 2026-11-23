//! Where a listener accepts: `host:port` addresses.

use alloc::vec::Vec;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::str::FromStr;

use crate::error::{Error, Result, config};

/// An address and port to listen on.
///
/// Read from `host:port`, `[v6]:port`, `:port` or `*:port` (every IPv4 address) and a bare `host`
/// (port 0, a free one); the host is an address literal or `localhost` (IPv4 loopback). Interface
/// names are not resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenAddr {
    address: IpAddr,
    port: u16,
}

impl ListenAddr {
    /// An address and port.
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self { address, port }
    }

    /// The loopback address on a free port, the default.
    pub fn loopback() -> Self {
        Self::new(Ipv4Addr::LOCALHOST.into(), 0)
    }

    /// The address.
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// The port (0 asks for a free one).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether only this machine can connect: a loopback address.
    pub fn is_local(&self) -> bool {
        self.address.is_loopback()
    }

    /// The socket address.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

impl From<SocketAddr> for ListenAddr {
    fn from(address: SocketAddr) -> Self {
        Self::new(address.ip(), address.port())
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.socket_addr(), formatter)
    }
}

fn host_address(host: &str) -> Result<IpAddr> {
    match host {
        "" | "*" => Ok(Ipv4Addr::UNSPECIFIED.into()),
        "localhost" => Ok(Ipv4Addr::LOCALHOST.into()),
        _ => host
            .parse::<IpAddr>()
            .map_err(|_| config("a listen host is an address literal or localhost")),
    }
}

impl FromStr for ListenAddr {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let text = text.trim();
        let port = |digits: &str| {
            digits
                .parse::<u16>()
                .map_err(|_| config("a listen port is 0 to 65535"))
        };
        if let Some(rest) = text.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| config("a listen IPv6 address is missing its ]"))?;
            let number = match after.strip_prefix(':') {
                Some(digits) => port(digits)?,
                None if after.is_empty() => 0,
                None => return Err(config("a listen address has text after ]")),
            };
            return Ok(Self::new(host_address(host)?, number));
        }
        if text.is_empty() {
            return Err(config("a listen address is not empty"));
        }
        if let Ok(address) = text.parse::<IpAddr>() {
            return Ok(Self::new(address, 0));
        }
        match text.rsplit_once(':') {
            Some((host, digits)) => Ok(Self::new(host_address(host)?, port(digits)?)),
            None => Ok(Self::new(host_address(text)?, 0)),
        }
    }
}

/// Reads one address or several joined by commas.
///
/// # Errors
///
/// [`Error::Config`] for an entry that is not an address.
pub fn parse_list(text: &str) -> Result<Vec<ListenAddr>> {
    text.split(',').map(str::parse).collect()
}
