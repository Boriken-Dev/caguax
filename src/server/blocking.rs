//! The server for synchronous code: it owns a private Tokio runtime.
//!
//! Do not call these functions from inside an async task: they block the thread on that runtime.

use core::net::SocketAddr;

use super::Tunnel;
use crate::error::Result;
use crate::route::Routing;

/// Builds a [`Server`]; every setter of [`super::ServerBuilder`] applies through
/// [`builder`](Self::builder).
#[derive(Debug)]
#[must_use]
pub struct ServerBuilder {
    builder: super::ServerBuilder,
    worker_threads: Option<usize>,
}

impl From<super::ServerBuilder> for ServerBuilder {
    fn from(builder: super::ServerBuilder) -> Self {
        Self {
            builder,
            worker_threads: None,
        }
    }
}

impl ServerBuilder {
    /// Changes the asynchronous builder in place.
    pub fn with(
        mut self,
        change: impl FnOnce(super::ServerBuilder) -> super::ServerBuilder,
    ) -> Self {
        self.builder = change(self.builder);
        self
    }

    /// How many threads the private runtime runs on (default: Tokio's, one per core).
    pub fn worker_threads(mut self, threads: usize) -> Self {
        self.worker_threads = Some(threads);
        self
    }

    /// Binds every listener on a runtime of its own; returns once bound.
    ///
    /// # Errors
    ///
    /// As [`super::ServerBuilder::start`], and [`Error::Io`](crate::Error::Io) when the runtime
    /// cannot start.
    pub fn start(self) -> Result<Server> {
        let mut runtime = tokio::runtime::Builder::new_multi_thread();
        runtime.enable_all().thread_name("caguax");
        if let Some(threads) = self.worker_threads {
            runtime.worker_threads(threads);
        }
        let runtime = runtime.build()?;
        let server = runtime.block_on(self.builder.start())?;
        Ok(Server {
            runtime: Some(runtime),
            server: Some(server),
        })
    }
}

/// A running proxy on a runtime of its own. Dropping it stops the server.
#[derive(Debug)]
pub struct Server {
    runtime: Option<tokio::runtime::Runtime>,
    server: Option<super::Server>,
}

impl Server {
    /// A builder for a server routing with `router`.
    pub fn builder(router: impl Routing + 'static) -> ServerBuilder {
        super::Server::builder(router).into()
    }

    /// The asynchronous server, for what it offers beyond these functions.
    ///
    /// # Panics
    ///
    /// Never, while the server is running.
    pub fn server(&self) -> &super::Server {
        self.server
            .as_ref()
            .expect("the server runs until shutdown")
    }

    /// The addresses the HTTP proxy listens on, ports read back.
    pub fn addresses(&self) -> &[SocketAddr] {
        self.server().addresses()
    }

    /// The first HTTP proxy port.
    ///
    /// # Panics
    ///
    /// When the server has no HTTP proxy listener.
    pub fn port(&self) -> u16 {
        self.server().port()
    }

    /// Where `tunnel` listens, port read back.
    pub fn tunnel_address(&self, tunnel: &Tunnel) -> Option<SocketAddr> {
        self.server().tunnel_address(tunnel)
    }

    /// Stops listening, cancels every connection and waits for them.
    pub fn shutdown(mut self) {
        if let (Some(runtime), Some(server)) = (self.runtime.take(), self.server.take()) {
            runtime.block_on(server.shutdown());
        }
    }
}
