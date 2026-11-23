//! The `caguax` command line.
//!
//! [`main`] parses the arguments, installs the `tracing` subscriber and runs one command; the
//! binary is a one-line call to it. Results go to standard output, diagnostics to standard error
//! (one line per error). Exit status: 0 done, 1 failed (a closed standard output included), 2 the
//! invocation or the configuration is wrong, 130 interrupted (`caguax run` stops on Ctrl-C with 0).

mod ca;
mod cert;
mod check;
mod pac;
mod run;

use std::ffi::OsString;
use std::io::{IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Args, CommandFactory as _, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

pub use ca::{CaCommand, InitArgs};
pub use cert::{
    BackendChoice, CertCommand, ListArgs, LocationChoice, PinChoice, ProbeArgs, ShowArgs,
    SourceArgs,
};
pub use check::CheckArgs;
pub use pac::PacArgs;
pub use run::RunArgs;

use crate::config::{self, BuildOptions, Document, LoadOptions};
use crate::error::Error;

/// The environment variable that sets the log filter.
pub const LOG_VARIABLE: &str = "CAGUAX_LOG";

const AFTER_HELP: &str = "Environment variables:
  CAGUAX_CONFIG          the configuration file (same as --config)
  CAGUAX_LOG             the log filter, tracing syntax such as `info` or `caguax=debug`
                         (--verbose, --quiet and --loglevel override it)
  CAGUAX_PKCS11_MODULE   the PKCS#11 module `caguax cert` opens (same as --module)
  HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY
                         read by `egress = \"env\"` and `\"auto\"`
  <named by pin_env, password_env>
                         a credential's PIN, a key or CA password (secrets, read when needed)

Exit status: 0 done, 1 failed, 2 invocation or configuration wrong, 130 interrupted
(`caguax run` stops on Ctrl-C with 0).";

/// The root command.
#[derive(Debug, Parser)]
#[command(
    name = "caguax",
    version,
    about = "A local proxy server that routes each request by rules: directly, through the system's proxy, an upstream proxy, with the proxy owning the TLS, or rejected.",
    after_help = AFTER_HELP
)]
pub struct Cli {
    /// The configuration file: TOML unless its first line names another format (`#!yaml`,
    /// `#!json`, `#!ini`). Omitted: CAGUAX_CONFIG, else caguax/caguax.cfg in the user's
    /// configuration directory; without any file the defaults apply.
    #[arg(
        short = 'c',
        long,
        global = true,
        env = "CAGUAX_CONFIG",
        value_name = "FILE"
    )]
    pub config: Option<PathBuf>,

    /// More diagnostics on standard error (repeat for more).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Fewer diagnostics on standard error (repeat for fewer).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub quiet: u8,

    /// Sets log levels, overriding CAGUAX_LOG: `[NAME:]LEVEL`, comma separated (`debug`,
    /// `caguax::traffic:info`).
    #[arg(long, global = true, value_name = "[NAME:]LEVEL[,...]")]
    pub loglevel: Option<String>,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the proxy described by the configuration file and serve until Ctrl-C.
    Run(run::RunArgs),
    /// Show the rule and route the configuration picks for a destination, without connecting.
    Check(check::CheckArgs),
    /// Print the proxy auto-config (PAC) script generated from the configuration's rules.
    Pac(pac::PacArgs),
    /// Create and show the interception CA.
    #[command(subcommand)]
    Ca(ca::CaCommand),
    /// Look at the client certificates the system's keystores hold, and probe a server with them.
    #[command(subcommand)]
    Cert(cert::CertCommand),
}

/// How a result is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum Format {
    /// Lines for a person.
    #[default]
    Text,
    /// One JSON document, stable across releases.
    Json,
}

/// The output flags of a command: `--format`, with `--json` as its alias.
#[derive(Debug, Clone, Args)]
pub struct OutputArgs {
    /// How the result is printed.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// The same as `--format json`.
    #[arg(long)]
    pub json: bool,
}

impl OutputArgs {
    /// The format asked for.
    pub fn chosen(&self) -> Format {
        if self.json { Format::Json } else { self.format }
    }
}

/// Why a command ended without finishing.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The invocation or configuration is wrong: status 2.
    Usage(String),
    /// The command failed: status 1.
    Failed(String),
    /// Interrupted: status 130.
    Interrupted,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        match error {
            Error::Config(error) => Self::Usage(error.to_string()),
            other => Self::Failed(other.to_string()),
        }
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::Failed(error.to_string())
    }
}

pub(crate) type Outcome = Result<(), Failure>;

/// Prints `text` and a newline on standard output; a closed pipe is a failure.
pub(crate) fn print_line(text: &str) -> Outcome {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")
        .and_then(|()| stdout.flush())
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                Failure::Failed("standard output was closed".into())
            } else {
                Failure::from(error)
            }
        })
}

/// Prints `text` as it is on standard output.
pub(crate) fn print_raw(text: &str) -> Outcome {
    let mut stdout = std::io::stdout().lock();
    write!(stdout, "{text}")
        .and_then(|()| stdout.flush())
        .map_err(Failure::from)
}

/// The configuration the command line names.
pub(crate) struct Loaded {
    pub(crate) document: Document,
    pub(crate) path: Option<PathBuf>,
}

impl Loaded {
    /// The directory relative paths in the file resolve against.
    pub(crate) fn base_dir(&self) -> Option<PathBuf> {
        self.path
            .as_ref()
            .and_then(|path| path.parent().map(PathBuf::from))
    }

    pub(crate) fn build_options(&self) -> BuildOptions {
        let defaults = BuildOptions::default();
        BuildOptions {
            base_dir: self.base_dir(),
            label: self
                .path
                .as_ref()
                .map_or(defaults.label, |path| path.display().to_string()),
        }
    }
}

/// Reads the configuration file: the one named, else the default; without a file the defaults.
pub(crate) fn load_config(cli: &Cli) -> Result<Loaded, Failure> {
    match &cli.config {
        Some(path) => Ok(Loaded {
            document: config::load(path, LoadOptions::default())?,
            path: Some(path.clone()),
        }),
        None => {
            let path = config::default_path();
            if path.is_file() {
                Ok(Loaded {
                    document: config::load(&path, LoadOptions::default())?,
                    path: Some(path),
                })
            } else {
                tracing::info!(target: "caguax", "no configuration file; the defaults apply");
                Ok(Loaded {
                    document: Document::default(),
                    path: None,
                })
            }
        }
    }
}

fn level_name(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "trace" => Some("trace"),
        "debug" => Some("debug"),
        "info" => Some("info"),
        "warn" | "warning" => Some("warn"),
        "error" | "critical" | "fatal" => Some("error"),
        "off" | "none" => Some("off"),
        _ => None,
    }
}

/// `[NAME:]LEVEL,...` as `tracing` directives.
fn loglevel_directives(text: &str) -> Result<String, Failure> {
    let mut directives = Vec::new();
    for entry in text
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (target, level) = match entry.rsplit_once(':') {
            Some((target, level)) if !target.ends_with(':') => (Some(target), level),
            _ => (None, entry),
        };
        let level = level_name(level)
            .ok_or_else(|| Failure::Usage("--loglevel: an unknown level name".into()))?;
        directives.push(match target {
            Some(target) => alloc::format!("{}={level}", target.replace('.', "::")),
            None => level.to_owned(),
        });
    }
    Ok(directives.join(","))
}

fn base_level(verbose: u8, quiet: u8) -> Option<&'static str> {
    let level = i16::from(verbose) - i16::from(quiet);
    if level == 0 {
        return None;
    }
    Some(match level {
        i16::MIN..=-2 => "off",
        -1 => "error",
        1 => "info",
        2 => "debug",
        _ => "trace",
    })
}

fn init_logging(cli: &Cli) -> Result<(), Failure> {
    let directives = if let Some(text) = &cli.loglevel {
        loglevel_directives(text)?
    } else if let Some(level) = base_level(cli.verbose, cli.quiet) {
        level.to_owned()
    } else if let Ok(text) = std::env::var(LOG_VARIABLE) {
        text
    } else {
        "warn".to_owned()
    };
    let filter = EnvFilter::try_new(&directives)
        .map_err(|_| Failure::Usage("the log filter is not valid".into()))?;
    let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    // A second call in one process (a test) finds the subscriber installed; that is fine.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(color)
        .with_target(true)
        .try_init();
    Ok(())
}

/// Runs the command line: `args` start with the program name.
pub fn main<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return ExitCode::from(u8::try_from(code).unwrap_or(2));
        }
    };
    let result = init_logging(&cli).and_then(|()| execute(&cli));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            eprintln!("caguax: {message}");
            ExitCode::from(2)
        }
        Err(Failure::Failed(message)) => {
            eprintln!("caguax: {message}");
            ExitCode::from(1)
        }
        Err(Failure::Interrupted) => ExitCode::from(130),
    }
}

fn execute(cli: &Cli) -> Outcome {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let work = dispatch(cli);
        match &cli.command {
            // `run` handles its own interrupt: stopping on Ctrl-C is how it ends.
            Command::Run(_) => work.await,
            _ => tokio::select! {
                result = work => result,
                _ = tokio::signal::ctrl_c() => Err(Failure::Interrupted),
            },
        }
    })
}

async fn dispatch(cli: &Cli) -> Outcome {
    match &cli.command {
        Command::Run(args) => run::run(cli, args).await,
        Command::Check(args) => check::run(cli, args),
        Command::Pac(args) => pac::run(cli, args),
        Command::Ca(command) => ca::run(cli, command),
        Command::Cert(command) => cert::run(command).await,
    }
}

/// The definition of the command line, for tests and documentation.
pub fn command() -> clap::Command {
    Cli::command()
}
