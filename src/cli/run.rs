//! `caguax run`: serve until interrupted.

use clap::Args;

use super::{Cli, Failure, Loaded, Outcome, load_config, print_line};
use crate::auth::Auth;
use crate::config::{self, build_parts};
use crate::server::Server;
use crate::settings::ServerSettings;

/// `caguax run` takes no arguments of its own: the configuration file says what to serve.
#[derive(Debug, Args)]
pub struct RunArgs {}

#[cfg(unix)]
async fn terminated() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(_) => core::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn terminated() {
    core::future::pending::<()>().await;
}

/// Resolves each time the process is asked to read its configuration again.
#[cfg(unix)]
struct Hangups(Option<tokio::signal::unix::Signal>);

#[cfg(unix)]
impl Hangups {
    fn new() -> Self {
        Self(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok())
    }

    async fn next(&mut self) {
        match &mut self.0 {
            Some(stream) => {
                stream.recv().await;
            }
            None => core::future::pending::<()>().await,
        }
    }
}

#[cfg(not(unix))]
struct Hangups;

#[cfg(not(unix))]
impl Hangups {
    fn new() -> Self {
        Self
    }

    async fn next(&mut self) {
        core::future::pending::<()>().await;
    }
}

/// Where a generated listener login goes when the configuration names no file: `caguax.auth`
/// beside the configuration file (or where the default one would be).
fn with_login_file(settings: &mut ServerSettings, loaded: &Loaded) {
    if let Auth::Generated {
        file: file @ None, ..
    } = &mut settings.auth
    {
        let beside = loaded.path.clone().unwrap_or_else(config::default_path);
        *file = Some(beside.with_file_name(LOGIN_FILE));
    }
}

const LOGIN_FILE: &str = "caguax.auth";

pub(super) async fn run(cli: &Cli, _args: &RunArgs) -> Outcome {
    let loaded = load_config(cli)?;
    let mut parts = build_parts(&loaded.document, loaded.build_options())?;
    with_login_file(&mut parts.settings, &loaded);
    let login_file = match &parts.settings.auth {
        Auth::Generated { file, .. } => file.clone(),
        _ => None,
    };
    let server = Server::builder(parts.router)
        .settings(parts.settings)
        .tunnels(parts.tunnels)
        .start()
        .await?;
    for address in server.addresses() {
        print_line(&alloc::format!(
            "proxy http://{}",
            crate::connection::join_host(&address.ip().to_string(), address.port())
        ))?;
    }
    if let Some(file) = login_file {
        print_line(&alloc::format!("login {}", file.display()))?;
    }
    for (tunnel, address) in server.tunnels() {
        print_line(&alloc::format!("tunnel {address} -> {}", tunnel.target()))?;
    }
    for entry in server.non_defaults() {
        tracing::info!(target: "caguax", "non-default setting: {entry}");
        print_line(&alloc::format!("non-default {entry}"))?;
    }
    let mut hangups = Hangups::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            () = terminated() => break,
            () = hangups.next() => {
                match reload(cli, &server).await {
                    Ok(()) => tracing::info!(target: "caguax", "the configuration was read again"),
                    Err(Failure::Usage(message) | Failure::Failed(message)) => {
                        tracing::warn!(
                            target: "caguax",
                            "the configuration was not reloaded, the running one stays: {message}"
                        );
                    }
                    Err(Failure::Interrupted) => break,
                }
            }
        }
    }
    server.shutdown().await;
    eprintln!("stopped");
    Ok(())
}

async fn reload(cli: &Cli, server: &Server) -> Outcome {
    let loaded = load_config(cli)?;
    let mut parts = build_parts(&loaded.document, loaded.build_options())?;
    with_login_file(&mut parts.settings, &loaded);
    server.reload(parts.settings, parts.router).await?;
    Ok(())
}
