#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    missing_debug_implementations,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod config;
pub mod connection;
pub mod credential;
pub mod error;
pub mod intercept;
pub mod keylog;
pub mod listen;
pub mod pac;
pub mod record;
pub mod route;
pub mod rules;
pub mod server;
pub mod settings;
pub mod upstream;

pub use connection::{Connection, ConnectionBuilder, LISTENER, Scheme};
pub use credential::{Backend, Credential, CredentialBuilder, KeystoreOptions, StoreLocation};
pub use error::{
    ConfigError, CredentialUnavailableError, Error, RejectedError, Result, UpstreamError,
};
pub use intercept::{CaOptions, Interceptor, create_ca, permitted_names};
pub use listen::ListenAddr;
pub use pac::generate_pac;
pub use record::{Recorder, Session};
pub use route::{
    Action, Explanation, Route, RouteBuilder, Router, RouterBuilder, Routing, Rule, TlsSource,
    UpstreamSpec,
};
pub use rules::{CustomMatcher, Matcher, PortSpec};
pub use server::blocking;
pub use server::{OpenOptions, RelaySession, Server, ServerBuilder, Tunnel, TunnelBuilder};
pub use settings::{CaSettings, InterceptSettings, ServerSettings};
pub use upstream::{ConnectOptions, Egress, UpstreamStream};

/// This crate's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
