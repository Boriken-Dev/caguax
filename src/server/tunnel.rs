//! A local port whose connections go to one fixed target.

use alloc::string::String;
use alloc::sync::Arc;

use tokio::net::TcpStream;

use super::{Inner, OpenOptions};
use crate::connection::{Connection, Scheme};
use crate::error::{Result, config};
use crate::listen::ListenAddr;
use crate::route::{Action, Route};

/// A local port whose connections go to one fixed `target`.
///
/// Each connection is routed as a [`Connection`] with scheme `tcp` and the tunnel's name as its
/// listener; the tunnel's own route, when it has one, overrides the router.
#[derive(Debug, Clone)]
pub struct Tunnel {
    listen: ListenAddr,
    target: String,
    host: String,
    port: u16,
    route: Option<Route>,
    name: String,
}

impl Tunnel {
    /// A tunnel accepting on `listen` (`127.0.0.1:15432`) to `target` (`db.corp.example:5432`).
    ///
    /// # Errors
    ///
    /// [`Error::Config`](crate::Error::Config) for a listen address that does not parse or a
    /// target with no port.
    pub fn builder(listen: &str, target: &str) -> Result<TunnelBuilder> {
        let listen: ListenAddr = listen.parse()?;
        let (host, port) = crate::rules::split_host_port(target)?;
        let port = port.ok_or_else(|| config("a tunnel's target needs a port"))?;
        Ok(TunnelBuilder {
            tunnel: Self {
                listen,
                target: target.trim().into(),
                host: host.into(),
                port,
                route: None,
                name: alloc::format!("tunnel:{}", target.trim()),
            },
        })
    }

    /// Where the tunnel accepts.
    pub fn listen(&self) -> ListenAddr {
        self.listen
    }

    /// The target as written, `host:port`.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The target's host and port.
    pub fn target_host_port(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }

    /// The route that overrides the router, when set.
    pub fn route(&self) -> Option<&Route> {
        self.route.as_ref()
    }

    /// The tunnel's name, the listener name its connections carry (default `tunnel:<target>`).
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Builds a [`Tunnel`].
#[derive(Debug, Clone)]
#[must_use]
pub struct TunnelBuilder {
    tunnel: Tunnel,
}

impl TunnelBuilder {
    /// The route for this tunnel, instead of asking the router (default none).
    pub fn route(mut self, route: impl Into<Route>) -> Self {
        self.tunnel.route = Some(route.into());
        self
    }

    /// The tunnel's name (default `tunnel:<target>`).
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.tunnel.name = name.into();
        self
    }

    /// The finished tunnel.
    pub fn build(self) -> Tunnel {
        self.tunnel
    }
}

impl From<TunnelBuilder> for Tunnel {
    fn from(builder: TunnelBuilder) -> Self {
        builder.build()
    }
}

/// Serves one connection accepted by a tunnel listener.
pub(super) async fn serve(inner: Arc<Inner>, tunnel: Arc<Tunnel>, stream: TcpStream) {
    let peer = stream.peer_addr().ok();
    let (host, port) = tunnel.target_host_port();
    let mut builder = Connection::builder(&host, port)
        .scheme(Scheme::Tcp)
        .listener(tunnel.name());
    if let Some(peer) = peer {
        builder = builder.client(peer);
    }
    let Ok(connection) = builder.build() else {
        return;
    };
    let state = inner.state();
    let route = tunnel
        .route()
        .cloned()
        .unwrap_or_else(|| state.router.route(&connection));
    if route.action() == Action::Reject {
        tracing::info!(
            target: "caguax",
            "rejected {} ({})",
            connection.authority(),
            route.name()
        );
        return;
    }
    let upstream = match inner
        .open_upstream(&connection, &route, OpenOptions::default())
        .await
    {
        Ok(upstream) => upstream,
        Err(error) => {
            tracing::warn!(
                target: "caguax",
                "{} via {}: {error}",
                connection.authority(),
                tunnel.name()
            );
            return;
        }
    };
    let recording = inner.start_recording(&connection, &route, peer, &upstream);
    inner
        .relay_session(stream, upstream, recording, None, false)
        .await;
}
