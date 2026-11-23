//! `caguax cert`: the client certificates the system's keystores hold, and a probe of a server.

use alloc::sync::Arc;
use core::time::Duration;
use std::io::{BufRead as _, IsTerminal as _};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand, ValueEnum};
use coqui_sslcontext::{
    CertificateInfo, CertificateRequest, ClientCertificates, Identity, Pin, PinAnswer, PinPurpose,
    Secret, Selector, Tls, Trust,
};
use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::ServerName;
use rustls::sign::CertifiedKey;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::{Failure, Format, Outcome, OutputArgs, print_line};
use crate::settings::parse_duration;

/// The `caguax cert` commands.
#[derive(Debug, Subcommand)]
pub enum CertCommand {
    /// List the client certificates whose private key can be used, newest expiry first.
    List(ListArgs),
    /// Show one identity in full: by SHA-1 or SHA-256 thumbprint, or a subject substring.
    Show(ShowArgs),
    /// Connect to a server as a browser would: show its certificate, whether it asked for a
    /// client certificate, which ones fit and which was sent, and (https) the HTTP status.
    Probe(ProbeArgs),
}

/// Where identities come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendChoice {
    /// The system's keystores.
    System,
    /// A Windows CNG certificate store.
    Cng,
    /// The macOS Keychain.
    Keychain,
    /// A PKCS#11 module.
    Pkcs11,
}

/// A Windows store location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LocationChoice {
    /// The current user's stores.
    #[value(name = "current_user")]
    CurrentUser,
    /// The local machine's stores.
    #[value(name = "local_machine")]
    LocalMachine,
}

/// How a PIN is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PinChoice {
    /// Fail at once when a key needs one.
    None,
    /// Ask on this terminal.
    Ask,
    /// The keystore's own dialog or PIN pad.
    Keystore,
}

/// The flags every `cert` command takes to choose the keystores.
#[derive(Debug, Clone, Args)]
pub struct SourceArgs {
    /// Where identities come from.
    #[arg(short, long, value_enum, default_value_t = BackendChoice::System)]
    pub backend: BackendChoice,

    /// cng: the certificate store name.
    #[arg(long, default_value = "MY")]
    pub store: String,

    /// cng: the store location.
    #[arg(long, value_enum, default_value_t = LocationChoice::CurrentUser)]
    pub location: LocationChoice,

    /// pkcs11: the PKCS#11 module. Omitted: the system default.
    #[arg(long, env = "CAGUAX_PKCS11_MODULE", value_name = "PATH")]
    pub module: Option<PathBuf>,

    /// pkcs11: only the token with this label or serial number.
    #[arg(long)]
    pub token: Option<String>,

    /// How a PIN is given when a key needs one: none (fail at once), ask (on this terminal; never
    /// without one), keystore (the keystore's own dialog or PIN pad).
    #[arg(long, value_enum, default_value_t = PinChoice::None)]
    pub pin: PinChoice,
}

/// `caguax cert list`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// The keystores.
    #[command(flatten)]
    pub source: SourceArgs,

    /// Include expired and not-yet-valid certificates.
    #[arg(short, long)]
    pub all: bool,

    /// The output format.
    #[command(flatten)]
    pub output: OutputArgs,
}

/// `caguax cert show`.
#[derive(Debug, Args)]
pub struct ShowArgs {
    /// The keystores.
    #[command(flatten)]
    pub source: SourceArgs,

    /// A thumbprint, or text found in the subject.
    pub query: String,
}

/// `caguax cert probe`.
#[derive(Debug, Args)]
pub struct ProbeArgs {
    /// The keystores.
    #[command(flatten)]
    pub source: SourceArgs,

    /// `https://host[:port]/path`, or `host[:port]` for TLS only.
    pub url: String,

    /// Trust this CA bundle instead of the system's.
    #[arg(long, value_name = "FILE")]
    pub cafile: Option<PathBuf>,

    /// Do not verify the server (still shows its certificate).
    #[arg(short = 'k', long)]
    pub insecure: bool,

    /// When several certificates fit and nothing picks one, ask on the terminal.
    #[arg(long)]
    pub ask: bool,

    /// Ignore the browsers' AutoSelectCertificateForUrls policy.
    #[arg(long)]
    pub no_policy: bool,

    /// How long to wait for the connection and each reply: seconds, or `15s`, `500ms`.
    #[arg(long, default_value = "15s", value_parser = parse_duration)]
    pub timeout: Duration,

    /// The output format.
    #[command(flatten)]
    pub output: OutputArgs,
}

fn ask_pin() -> Pin {
    Pin::callback(|request| {
        if request.purpose() == PinPurpose::List || !std::io::stdin().is_terminal() {
            return PinAnswer::Decline;
        }
        let what = if request.token().is_empty() {
            request
                .certificate()
                .map_or_else(String::new, |info| info.subject().to_owned())
        } else {
            request.token().to_owned()
        };
        match rpassword::prompt_password(alloc::format!("PIN for {what}: ")) {
            Ok(pin) if !pin.is_empty() => PinAnswer::Secret(Secret::new(pin)),
            _ => PinAnswer::Decline,
        }
    })
}

impl SourceArgs {
    fn pin_source(&self) -> Pin {
        match self.pin {
            PinChoice::None => Pin::None,
            PinChoice::Keystore => Pin::Keystore,
            PinChoice::Ask => ask_pin(),
        }
    }

    fn selector(
        &self,
        browser_policy: bool,
        chooser: Option<coqui_sslcontext::Chooser>,
    ) -> Result<Selector, Failure> {
        let pin = self.pin_source();
        let mut builder = match self.backend {
            BackendChoice::System => Selector::system_builder(pin),
            BackendChoice::Cng => {
                #[cfg(windows)]
                {
                    let source = match self.location {
                        LocationChoice::CurrentUser => {
                            coqui_sslcontext::CngSource::current_user(&self.store)
                        }
                        LocationChoice::LocalMachine => {
                            coqui_sslcontext::CngSource::local_machine(&self.store)
                        }
                    }
                    .map_err(crate::Error::from)?;
                    Selector::builder().source(source.pin(pin))
                }
                #[cfg(not(windows))]
                {
                    let _ = pin;
                    return Err(Failure::Usage("the cng backend needs Windows".into()));
                }
            }
            BackendChoice::Keychain => {
                #[cfg(target_os = "macos")]
                {
                    Selector::builder().source(coqui_sslcontext::KeychainSource::new().pin(pin))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = pin;
                    return Err(Failure::Usage("the keychain backend needs macOS".into()));
                }
            }
            BackendChoice::Pkcs11 => {
                #[cfg(feature = "pkcs11")]
                {
                    let builder = match &self.module {
                        Some(module) => coqui_sslcontext::Pkcs11Source::builder(module),
                        None => coqui_sslcontext::Pkcs11Source::discover(
                            &coqui_sslcontext::Pkcs11Settings::default(),
                        )
                        .ok_or_else(|| Failure::Failed("no PKCS#11 module was found".into()))?,
                    };
                    let mut builder = builder.pin(pin);
                    if let Some(token) = &self.token {
                        builder = builder.token(token.clone());
                    }
                    Selector::builder().source(builder.build())
                }
                #[cfg(not(feature = "pkcs11"))]
                {
                    let _ = pin;
                    return Err(Failure::Usage(
                        "the pkcs11 backend needs the `pkcs11` feature".into(),
                    ));
                }
            }
        };
        builder = builder.browser_policy(browser_policy);
        if let Some(chooser) = chooser {
            builder = builder.chooser(chooser);
        }
        Ok(builder.build())
    }
}

/// Civil time from seconds since the epoch: `(year, month, day, hour, minute, second)`.
fn civil(seconds: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400) as u32;
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_part + 2) / 5 + 1) as u32;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day, rest / 3600, rest % 3600 / 60, rest % 60)
}

fn date(time: SystemTime) -> String {
    let seconds = match time.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_secs() as i64,
        Err(before) => -(before.duration().as_secs() as i64),
    };
    let (year, month, day, ..) = civil(seconds);
    alloc::format!("{year:04}-{month:02}-{day:02}")
}

fn date_time(time: SystemTime) -> String {
    let seconds = match time.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_secs() as i64,
        Err(before) => -(before.duration().as_secs() as i64),
    };
    let (year, month, day, hour, minute, second) = civil(seconds);
    alloc::format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02X}");
        text
    })
}

fn describe_info(info: &CertificateInfo, label: &str) -> Value {
    json!({
        "sha1": hex(info.sha1()),
        "subject": info.subject(),
        "issuer": info.issuer(),
        "not_after": date(info.not_after()),
        "key": alloc::format!("{:?}-{}", info.key_type(), info.key_bits()),
        "client_auth": info.client_auth(),
        "valid": info.valid_now(),
        "label": label,
    })
}

fn describe(identity: &Identity) -> Value {
    describe_info(identity.info(), identity.label())
}

fn list_lines(rows: &[Value]) -> String {
    rows.iter()
        .map(|row| {
            let usable = match row["client_auth"].as_bool() {
                Some(true) => "client",
                Some(false) => "no-client",
                None => "?",
            };
            alloc::format!(
                "{}  {}  {:<8} {:<9} {}  (issuer {})",
                row["sha1"].as_str().unwrap_or(""),
                row["not_after"].as_str().unwrap_or(""),
                row["key"].as_str().unwrap_or(""),
                usable,
                row["subject"].as_str().unwrap_or(""),
                row["issuer"].as_str().unwrap_or(""),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) async fn run(command: &CertCommand) -> Outcome {
    match command {
        CertCommand::List(args) => {
            let args_source = args.source.clone();
            let identities = tokio::task::spawn_blocking(move || {
                args_source
                    .selector(false, None)
                    .map(|selector| selector.identities())
            })
            .await
            .map_err(|_| Failure::Failed("the keystore thread ended".into()))??;
            let mut rows: Vec<Value> = identities
                .iter()
                .filter(|identity| args.all || identity.info().valid_now())
                .map(describe)
                .collect();
            rows.sort_by(|a, b| b["not_after"].as_str().cmp(&a["not_after"].as_str()));
            let json = args.output.chosen() == Format::Json;
            // No identities is no line at all in text; JSON still prints [].
            if json {
                print_line(&Value::Array(rows).to_string())
            } else if rows.is_empty() {
                Ok(())
            } else {
                print_line(&list_lines(&rows))
            }
        }
        CertCommand::Show(args) => show(args).await,
        CertCommand::Probe(args) => probe(args).await,
    }
}

async fn show(args: &ShowArgs) -> Outcome {
    let source = args.source.clone();
    let identities = tokio::task::spawn_blocking(move || {
        source
            .selector(false, None)
            .map(|selector| selector.identities())
    })
    .await
    .map_err(|_| Failure::Failed("the keystore thread ended".into()))??;
    let wanted: String = args
        .query
        .chars()
        .filter(|c| *c != ' ' && *c != ':')
        .collect::<String>()
        .to_ascii_uppercase();
    let needle = args.query.to_lowercase();
    let found: Vec<&Identity> = identities
        .iter()
        .filter(|identity| {
            let info = identity.info();
            wanted == hex(info.sha1())
                || wanted == hex(info.sha256())
                || info.subject().to_lowercase().contains(&needle)
        })
        .collect();
    if found.is_empty() {
        return Err(Failure::Failed(alloc::format!(
            "no identity matches {:?}",
            args.query
        )));
    }
    for identity in found {
        let info = identity.info();
        let mut row = describe(identity);
        let chain: Vec<String> = identity
            .chain()
            .iter()
            .map(|der| {
                CertificateInfo::from_chain(core::slice::from_ref(der)).map_or_else(
                    |error| alloc::format!("<unreadable: {error}>"),
                    |info| info.subject().to_owned(),
                )
            })
            .collect();
        if let Value::Object(map) = &mut row {
            map.insert("sha256".into(), json!(hex(info.sha256())));
            map.insert("serial".into(), json!(hex(info.serial())));
            map.insert("not_before".into(), json!(date_time(info.not_before())));
            map.insert("not_after".into(), json!(date_time(info.not_after())));
            map.insert("chain".into(), json!(chain));
        }
        print_line(&serde_json::to_string_pretty(&row).unwrap_or_default())?;
    }
    Ok(())
}

/// Records what each certificate request asked and got, then answers as the real resolver does.
struct Recording {
    inner: Arc<dyn ResolvesClientCert>,
    selector: Arc<Selector>,
    host: String,
    log: Arc<Mutex<Vec<Value>>>,
}

impl core::fmt::Debug for Recording {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("Recording").finish_non_exhaustive()
    }
}

impl ResolvesClientCert for Recording {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let request = CertificateRequest::new(
            Some(self.host.clone()),
            root_hint_subjects
                .iter()
                .map(|name| name.to_vec())
                .collect(),
            sigschemes.to_vec(),
        );
        let candidates = self.selector.candidates(&request);
        let sent = self.selector.select(&request);
        let mut key_types: Vec<String> = request
            .key_types()
            .iter()
            .map(|key_type| alloc::format!("{key_type:?}"))
            .collect();
        key_types.sort();
        let entry = json!({
            "host": self.host,
            "authorities": request.authority_names(),
            "key_types": key_types,
            "candidates": candidates.iter().map(describe).collect::<Vec<_>>(),
            "sent": sent.as_ref().map(describe),
        });
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(entry);
        self.inner.resolve(root_hint_subjects, sigschemes)
    }

    fn has_certs(&self) -> bool {
        self.inner.has_certs()
    }
}

fn terminal_chooser() -> coqui_sslcontext::Chooser {
    Arc::new(|request, candidates| {
        if !std::io::stdin().is_terminal() {
            return None;
        }
        eprintln!(
            "{} asks for a client certificate:",
            request.host().unwrap_or("The server")
        );
        for (number, identity) in candidates.iter().enumerate() {
            let info = identity.info();
            eprintln!(
                "  {}. {}  (issuer {}, until {})",
                number + 1,
                info.subject(),
                info.issuer(),
                date(info.not_after())
            );
        }
        eprint!("Send which (number, empty for none)? ");
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer).ok()?;
        let number: usize = answer.trim().parse().ok()?;
        (1..=candidates.len()).contains(&number).then(|| number - 1)
    })
}

struct Target {
    tls_only: bool,
    host: String,
    port: u16,
    path: String,
}

fn target(url: &str) -> Result<Target, Failure> {
    let (scheme, rest) = url.split_once("://").unwrap_or(("tls", url));
    if !matches!(scheme, "https" | "tls") {
        return Err(Failure::Usage(
            "probe speaks https:// or a bare host[:port]".into(),
        ));
    }
    let (authority, path) = match rest.find(['/', '?']) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        alloc::format!("/{path}")
    };
    let (host, port) = crate::rules::split_host_port(authority)?;
    if host.is_empty() {
        return Err(Failure::Usage(alloc::format!("no host in {url:?}")));
    }
    Ok(Target {
        tls_only: scheme == "tls",
        host: host.to_owned(),
        port: port.unwrap_or(443),
        path,
    })
}

async fn probe(args: &ProbeArgs) -> Outcome {
    let target = target(&args.url)?;
    let chooser = args.ask.then(terminal_chooser);
    let source = args.source.clone();
    let no_policy = args.no_policy;
    let selector = Arc::new(
        tokio::task::spawn_blocking(move || source.selector(!no_policy, chooser))
            .await
            .map_err(|_| Failure::Failed("the keystore thread ended".into()))??,
    );
    let trust = if args.insecure {
        Trust::Disabled
    } else if let Some(path) = &args.cafile {
        Trust::Bundle(path.clone())
    } else {
        Trust::System
    };
    let tls = Tls::builder()
        .trust(trust)
        .client_certificates(ClientCertificates::Selector(Arc::clone(&selector)))
        .build()
        .map_err(crate::Error::from)?;
    let mut config = (*tls
        .client_config(&target.host)
        .map_err(crate::Error::from)?)
    .clone();
    let log = Arc::new(Mutex::new(Vec::new()));
    config.client_auth_cert_resolver = Arc::new(Recording {
        inner: Arc::clone(&config.client_auth_cert_resolver),
        selector: Arc::clone(&selector),
        host: target.host.clone(),
        log: Arc::clone(&log),
    });
    let mut result = json!({"host": target.host, "port": target.port});
    let outcome = exchange(args, &target, Arc::new(config), &mut result).await;
    let requests = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    result["certificate_requests"] = Value::Array(requests);
    if let Err(message) = &outcome {
        result["error"] = json!(message);
    }
    match args.output.chosen() {
        Format::Json => print_line(&result.to_string())?,
        Format::Text => print_line(&probe_text(&result))?,
    }
    outcome.map_err(Failure::Failed)
}

async fn exchange(
    args: &ProbeArgs,
    target: &Target,
    config: Arc<rustls::ClientConfig>,
    result: &mut Value,
) -> Result<(), String> {
    let wait = args.timeout;
    let fail = |what: &str, error: &dyn core::fmt::Display| alloc::format!("{what}: {error}");
    let tcp = tokio::time::timeout(
        wait,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| "connect: timed out".to_owned())?
    .map_err(|error| fail("connect", &error))?;
    let name = ServerName::try_from(target.host.clone()).map_err(|error| fail("name", &error))?;
    let mut stream = tokio::time::timeout(wait, TlsConnector::from(config).connect(name, tcp))
        .await
        .map_err(|_| "tls: timed out".to_owned())?
        .map_err(|error| fail("tls", &error))?;
    {
        let connection = stream.get_ref().1;
        result["tls_version"] = json!(
            connection
                .protocol_version()
                .map(|version| alloc::format!("{version:?}"))
        );
        result["cipher"] = json!(
            connection
                .negotiated_cipher_suite()
                .map(|suite| alloc::format!("{:?}", suite.suite()))
        );
        if let Some(chain) = connection.peer_certificates()
            && let Ok(info) = CertificateInfo::from_chain(chain)
        {
            result["server"] = json!({
                "subject": info.subject(),
                "issuer": info.issuer(),
                "sha1": hex(info.sha1()),
            });
        }
    }
    if !target.tls_only {
        let authority = if target.port == 443 {
            target.host.clone()
        } else {
            alloc::format!("{}:{}", target.host, target.port)
        };
        let request = alloc::format!(
            "HEAD {} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: caguax-probe\r\nConnection: close\r\n\r\n",
            target.path
        );
        tokio::time::timeout(wait, stream.write_all(request.as_bytes()))
            .await
            .map_err(|_| "http: timed out".to_owned())?
            .map_err(|error| fail("http", &error))?;
        let mut reply = Vec::new();
        let mut chunk = [0_u8; 4096];
        while !reply.windows(2).any(|pair| pair == b"\r\n") {
            let read = tokio::time::timeout(wait, stream.read(&mut chunk))
                .await
                .map_err(|_| "http: timed out".to_owned())?
                .map_err(|error| fail("http", &error))?;
            if read == 0 {
                break;
            }
            reply.extend_from_slice(&chunk[..read]);
        }
        let line = reply.split(|byte| *byte == b'\r').next().unwrap_or(&[]);
        result["http"] = json!(String::from_utf8_lossy(line));
    }
    Ok(())
}

fn probe_text(result: &Value) -> String {
    let mut lines = vec![alloc::format!(
        "{}:{}",
        result["host"].as_str().unwrap_or(""),
        result["port"]
    )];
    if let Some(version) = result["tls_version"].as_str() {
        lines.push(alloc::format!(
            "  {version} {}",
            result["cipher"].as_str().unwrap_or("")
        ));
        if let Some(server) = result.get("server") {
            lines.push(alloc::format!(
                "  server: {}  (issuer {})",
                server["subject"].as_str().unwrap_or(""),
                server["issuer"].as_str().unwrap_or("")
            ));
        }
    }
    let requests = result["certificate_requests"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if requests.is_empty() {
        lines.push("  client certificate: not requested".into());
    }
    for request in &requests {
        let names: Vec<&str> = request["authorities"]
            .as_array()
            .map(|names| names.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let names = if names.is_empty() {
            "any CA".to_owned()
        } else {
            names.join(", ")
        };
        lines.push(alloc::format!(
            "  client certificate requested; accepted issuers: {names}"
        ));
        for candidate in request["candidates"].as_array().into_iter().flatten() {
            lines.push(alloc::format!(
                "    fits: {}  ({})",
                candidate["subject"].as_str().unwrap_or(""),
                candidate["sha1"].as_str().unwrap_or("")
            ));
        }
        let sent = request["sent"]["subject"].as_str().unwrap_or("none");
        lines.push(alloc::format!("  sent: {sent}"));
    }
    if let Some(status) = result["http"].as_str() {
        lines.push(alloc::format!("  http: {status}"));
    }
    if let Some(error) = result["error"].as_str() {
        lines.push(alloc::format!("  error: {error}"));
    }
    lines.join("\n")
}
