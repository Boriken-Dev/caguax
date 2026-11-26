//! `caguax ca`: create and show the interception CA.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use coqui_sslcontext::{KeyPassword, Secret};

use super::{Cli, Failure, Loaded, Outcome, load_config, print_line, print_raw};
use crate::config::build_router;
use crate::fileio::write_whole;
use crate::intercept::{CaOptions, create_ca};

/// The `caguax ca` commands.
#[derive(Debug, Subcommand)]
pub enum CaCommand {
    /// Create the interception CA, name-constrained to the hosts the TLS rules intercept, at the
    /// paths in `[server.ca]`.
    Init(InitArgs),
    /// Print the CA certificate (PEM): what clients must trust.
    Show,
}

/// `caguax ca init`.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Replace an existing CA. Omitted: refuse to overwrite.
    #[arg(long)]
    pub force: bool,

    /// Allow a CA without name constraints when the rules cannot bound it (it can then vouch for
    /// any site: protect its key).
    #[arg(long)]
    pub unconstrained: bool,
}

fn paths(loaded: &Loaded) -> Result<(PathBuf, PathBuf), Failure> {
    let ca = &loaded.document.server.ca;
    let (Some(certificate), Some(key)) = (&ca.certificate, &ca.key) else {
        return Err(Failure::Usage(
            "the configuration has no [server.ca] with certificate and key paths".into(),
        ));
    };
    let base = loaded.base_dir().unwrap_or_else(|| PathBuf::from("."));
    let resolve = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        }
    };
    Ok((resolve(certificate), resolve(key)))
}

pub(super) fn run(cli: &Cli, command: &CaCommand) -> Outcome {
    let loaded = load_config(cli)?;
    let (certificate, key) = paths(&loaded)?;
    match command {
        CaCommand::Show => {
            let pem = std::fs::read_to_string(&certificate)?;
            print_raw(&pem)
        }
        CaCommand::Init(args) => {
            if !args.force && (certificate.exists() || key.exists()) {
                return Err(Failure::Failed(alloc::format!(
                    "{} or {} exists; pass --force to replace it",
                    certificate.display(),
                    key.display()
                )));
            }
            let router = build_router(&loaded.document, loaded.base_dir().as_deref())?;
            let options = CaOptions {
                constrain: !args.unconstrained,
                validity: loaded.document.server.ca.validity,
                ..CaOptions::default()
            };
            let ca = create_ca(&router, options)?;
            let password = match loaded.document.server.ca.password_env.as_deref() {
                Some(name) => match std::env::var(name) {
                    Ok(value) if !value.is_empty() => KeyPassword::Secret(Secret::new(value)),
                    _ => KeyPassword::None,
                },
                None => KeyPassword::None,
            };
            let encrypted = !matches!(password, KeyPassword::None);
            let key_pem = ca.private_key_pem(&password).map_err(crate::Error::from)?;
            write_whole(&key, key_pem.as_bytes(), true)?;
            write_whole(&certificate, ca.certificate_pem().as_bytes(), false)?;
            if !encrypted {
                tracing::warn!(
                    target: "caguax",
                    "non-default setting: server.ca.key = unencrypted (set server.ca.password_env \
                     to a variable holding a password before running ca init)"
                );
            }
            print_line(&certificate.display().to_string())
        }
    }
}
