//! The command line: the definition, argument vectors through the real parser, and the built
//! binary run with real arguments.
#![cfg(feature = "cli")]

mod support;

use std::io::{BufRead as _, BufReader};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use caguax::cli::{Cli, Command as Cmd};
use clap::{CommandFactory as _, Parser as _};
use support::*;

const BINARY: &str = env!("CARGO_BIN_EXE_caguax");

#[test]
fn the_definition_is_consistent() {
    Cli::command().debug_assert();
    assert_eq!(caguax::cli::command().get_name(), "caguax");
}

fn parse(arguments: &[&str]) -> Cli {
    let mut all = vec!["caguax"];
    all.extend_from_slice(arguments);
    Cli::try_parse_from(all).unwrap_or_else(|error| panic!("{arguments:?}: {error}"))
}

fn refused(arguments: &[&str]) -> clap::error::ErrorKind {
    let mut all = vec!["caguax"];
    all.extend_from_slice(arguments);
    Cli::try_parse_from(all).unwrap_err().kind()
}

#[test]
fn argument_vectors_reach_their_fields() {
    let cli = parse(&[
        "-c",
        "my.cfg",
        "-vv",
        "-q",
        "--loglevel",
        "debug,caguax::traffic:info",
        "run",
    ]);
    assert_eq!(cli.config.as_deref(), Some(Path::new("my.cfg")));
    assert_eq!((cli.verbose, cli.quiet), (2, 1));
    assert_eq!(cli.loglevel.as_deref(), Some("debug,caguax::traffic:info"));
    assert!(matches!(cli.command, Cmd::Run(_)));

    // The global flags may come after the command.
    let cli = parse(&[
        "check",
        "https://a.example/x",
        "--config",
        "c.toml",
        "--listener",
        "tunnel:db",
        "--format",
        "json",
    ]);
    let Cmd::Check(check) = cli.command else {
        panic!()
    };
    assert_eq!(check.target, "https://a.example/x");
    assert_eq!(check.listener, "tunnel:db");
    assert_eq!(check.output.chosen(), caguax::cli::Format::Json);
    assert_eq!(cli.config.as_deref(), Some(Path::new("c.toml")));

    let Cmd::Check(check) = parse(&["check", "a.example:443", "--json"]).command else {
        panic!()
    };
    assert_eq!(check.listener, "proxy");
    assert_eq!(check.output.chosen(), caguax::cli::Format::Json);

    let Cmd::Pac(pac) = parse(&["pac", "--proxy", "127.0.0.1:3128"]).command else {
        panic!()
    };
    assert_eq!(pac.proxy.as_deref(), Some("127.0.0.1:3128"));

    let Cmd::Ca(caguax::cli::CaCommand::Init(init)) =
        parse(&["ca", "init", "--force", "--unconstrained"]).command
    else {
        panic!()
    };
    assert!(init.force && init.unconstrained);
    assert!(matches!(
        parse(&["ca", "show"]).command,
        Cmd::Ca(caguax::cli::CaCommand::Show)
    ));

    let Cmd::Cert(caguax::cli::CertCommand::List(list)) = parse(&[
        "cert", "list", "--all", "-b", "pkcs11", "--module", "m.so", "--token", "t", "--pin",
        "ask", "--json",
    ])
    .command
    else {
        panic!()
    };
    assert!(list.all);
    assert_eq!(list.source.pin, caguax::cli::PinChoice::Ask);
    assert_eq!(list.source.backend, caguax::cli::BackendChoice::Pkcs11);
    assert_eq!(list.source.token.as_deref(), Some("t"));
    assert_eq!(list.output.chosen(), caguax::cli::Format::Json);

    let Cmd::Cert(caguax::cli::CertCommand::Probe(probe)) = parse(&[
        "cert",
        "probe",
        "https://h.example/",
        "--cafile",
        "ca.pem",
        "-k",
        "--ask",
        "--no-policy",
        "--timeout",
        "2500ms",
        "--store",
        "ROOT",
        "--location",
        "local_machine",
    ])
    .command
    else {
        panic!()
    };
    assert!(probe.insecure && probe.ask && probe.no_policy);
    assert_eq!(probe.timeout.as_millis(), 2500);
    assert_eq!(probe.source.store, "ROOT");
    assert_eq!(
        probe.source.location,
        caguax::cli::LocationChoice::LocalMachine
    );

    let Cmd::Cert(caguax::cli::CertCommand::Show(show)) = parse(&["cert", "show", "AB:CD"]).command
    else {
        panic!()
    };
    assert_eq!(show.query, "AB:CD");
}

#[test]
fn a_wrong_invocation_is_refused() {
    use clap::error::ErrorKind::{InvalidValue, MissingRequiredArgument, UnknownArgument};
    assert_eq!(refused(&["check"]), MissingRequiredArgument);
    assert_eq!(refused(&["check", "x:1", "--format", "xml"]), InvalidValue);
    assert_eq!(refused(&["cert", "list", "--pin", "always"]), InvalidValue);
    assert_eq!(refused(&["run", "--bogus"]), UnknownArgument);
    assert_eq!(
        refused(&["cert", "probe", "h", "--timeout", "soon"]),
        clap::error::ErrorKind::ValueValidation
    );
    assert_eq!(
        refused(&[]),
        clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
}

fn run(arguments: &[&str]) -> Output {
    Command::new(BINARY)
        .args(arguments)
        .env_remove("CAGUAX_CONFIG")
        .env_remove("CAGUAX_LOG")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn the_binary_reports_its_version_and_help() {
    let version = run(&["--version"]);
    assert_eq!(code(&version), 0);
    assert!(text(&version.stdout).starts_with("caguax "));
    let help = run(&["--help"]);
    assert_eq!(code(&help), 0);
    let help = text(&help.stdout);
    for expected in [
        "CAGUAX_CONFIG",
        "CAGUAX_LOG",
        "CAGUAX_PKCS11_MODULE",
        "--loglevel",
        "run",
        "check",
        "pac",
        "ca",
        "cert",
    ] {
        assert!(help.contains(expected), "{expected} missing from --help");
    }
    assert_eq!(code(&run(&["cert", "probe", "--help"])), 0);
}

#[test]
fn a_missing_argument_is_status_2_and_a_bad_configuration_is_2_while_a_missing_file_is_1() {
    let missing = run(&["check"]);
    assert_eq!(code(&missing), 2);
    assert!(text(&missing.stderr).contains("TARGET"));
    let directory = tempfile::tempdir().unwrap();
    let bad = directory.path().join("bad.toml");
    std::fs::write(&bad, "[server]\nbogus = 1\n").unwrap();
    let output = run(&["-c", bad.to_str().unwrap(), "check", "a.example:443"]);
    assert_eq!(code(&output), 2);
    let stderr = text(&output.stderr);
    assert_eq!(stderr.trim().lines().count(), 1, "one line: {stderr}");
    assert!(stderr.starts_with("caguax: "), "{stderr}");
    assert!(output.stdout.is_empty());
    let output = run(&[
        "-c",
        directory.path().join("absent.toml").to_str().unwrap(),
        "check",
        "a.example:443",
    ]);
    assert_eq!(code(&output), 1);
}

#[test]
fn check_prints_a_route_without_network_access_in_text_and_json() {
    let output = run(&["check", "https://example.com/", "--format", "json"]);
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "destination": "https://example.com/",
            "rule": "default",
            "action": "direct",
            "credential": null,
            "upstream": null,
        })
    );
    assert!(output.stderr.is_empty());

    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("caguax.cfg");
    std::fs::write(
        &file,
        "[credentials.work]\nbackend = \"system\"\n[[rules]]\nmatch = \"*.corp.example\"\naction = \"tls\"\ncredential = \"work\"\nupstream = \"direct\"\nname = \"corp\"\n[[rules]]\nmatch = \"*.blocked.example\"\naction = \"reject\"\n",
    )
    .unwrap();
    let file = file.to_str().unwrap();
    let output = run(&["-c", file, "check", "api.corp.example:8443"]);
    assert_eq!(
        text(&output.stdout).trim(),
        "destination=https://api.corp.example:8443/ rule=corp action=tls credential=work upstream=direct"
    );
    let output = run(&["-c", file, "check", "http://a.blocked.example/p", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["rule"], "matched");
    assert_eq!(value["action"], "reject");
    let output = run(&[
        "-c",
        file,
        "check",
        "tunnel-listener-only.example:1",
        "--listener",
        "other",
    ]);
    assert_eq!(code(&output), 0);
}

#[test]
fn pac_prints_the_script_for_the_rules() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("caguax.cfg");
    std::fs::write(&file, "[server]\nlisten = \"127.0.0.1:3199\"\n[[rules]]\nmatch = \"*.blocked.example\"\naction = \"reject\"\n").unwrap();
    let output = run(&["-c", file.to_str().unwrap(), "pac"]);
    assert_eq!(code(&output), 0);
    let script = text(&output.stdout);
    assert!(
        script.contains("FindProxyForURL") && script.contains("PROXY 127.0.0.1:3199"),
        "{script}"
    );
    let output = run(&[
        "-c",
        file.to_str().unwrap(),
        "pac",
        "--proxy",
        "10.1.2.3:8080",
    ]);
    assert!(text(&output.stdout).contains("PROXY 10.1.2.3:8080"));
}

#[test]
fn the_ca_is_created_constrained_shown_and_not_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("caguax.cfg");
    std::fs::write(
        &file,
        "[server.ca]\ncertificate = \"pki/ca.pem\"\nkey = \"pki/ca.key\"\n[credentials.w]\nbackend = \"system\"\n[[rules]]\nmatch = \"*.corp.example\"\naction = \"tls\"\ncredential = \"w\"\n",
    )
    .unwrap();
    let file = file.to_str().unwrap();
    let created = run(&["-c", file, "ca", "init"]);
    assert_eq!(code(&created), 0, "{}", text(&created.stderr));
    let certificate = directory.path().join("pki/ca.pem");
    assert_eq!(
        text(&created.stdout).trim(),
        certificate.display().to_string()
    );
    assert!(directory.path().join("pki/ca.key").exists());
    assert!(
        text(&std::fs::read(directory.path().join("pki/ca.key")).unwrap()).contains("PRIVATE KEY")
    );
    let shown = run(&["-c", file, "ca", "show"]);
    assert_eq!(
        text(&shown.stdout),
        std::fs::read_to_string(&certificate).unwrap()
    );
    let again = run(&["-c", file, "ca", "init"]);
    assert_eq!(code(&again), 1);
    assert!(text(&again.stderr).contains("--force"));
    assert_eq!(code(&run(&["-c", file, "ca", "init", "--force"])), 0);

    // A configuration without [server.ca] is a wrong invocation.
    let plain = directory.path().join("plain.cfg");
    std::fs::write(&plain, "").unwrap();
    assert_eq!(
        code(&run(&["-c", plain.to_str().unwrap(), "ca", "init"])),
        2
    );

    // Rules no name constraint can cover need --unconstrained.
    let unbounded = directory.path().join("unbounded.cfg");
    std::fs::write(
        &unbounded,
        "[server.ca]\ncertificate = \"u.pem\"\nkey = \"u.key\"\n[credentials.w]\nbackend = \"system\"\n[[rules]]\nmatch = \"re:.*corp\"\naction = \"tls\"\ncredential = \"w\"\n",
    )
    .unwrap();
    let unbounded = unbounded.to_str().unwrap();
    assert_eq!(code(&run(&["-c", unbounded, "ca", "init"])), 2);
    assert_eq!(
        code(&run(&["-c", unbounded, "ca", "init", "--unconstrained"])),
        0
    );
}

struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts `caguax run` and reads its status lines until `until` matches one.
fn start(file: &Path, until: impl Fn(&str) -> bool) -> (Running, Vec<String>) {
    let mut child = Command::new(BINARY)
        .args(["-c", file.to_str().unwrap(), "run"])
        .env_remove("CAGUAX_CONFIG")
        .env_remove("CAGUAX_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.unwrap();
        let done = until(&line);
        lines.push(line);
        if done {
            break;
        }
    }
    (Running(child), lines)
}

/// The login `caguax run` wrote beside its configuration file.
fn login_in(directory: &std::path::Path) -> caguax::Login {
    let text = std::fs::read_to_string(directory.join("caguax.auth")).unwrap();
    let (user, password) = text.trim_end().split_once(':').unwrap();
    caguax::Login::new(user, password).unwrap()
}

#[tokio::test]
async fn run_serves_what_the_file_says_and_prints_its_addresses() {
    let origin = echo_origin(None).await;
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("caguax.cfg");
    std::fs::write(
        &file,
        "[server]\nlisten = \"127.0.0.1:0\"\nallow_remote = true\n[[tunnels]]\nlisten = \"127.0.0.1:0\"\ntarget = \"127.0.0.1:9\"\n",
    )
    .unwrap();
    let (child, lines) = start(&file, |line| line.starts_with("non-default"));
    assert!(lines[0].starts_with("proxy http://127.0.0.1:"), "{lines:?}");
    assert_eq!(
        lines[1],
        format!("login {}", directory.path().join("caguax.auth").display()),
        "{lines:?}"
    );
    assert!(
        lines[2].starts_with("tunnel 127.0.0.1:") && lines[2].ends_with("-> 127.0.0.1:9"),
        "{lines:?}"
    );
    assert_eq!(
        lines[3], "non-default server.allow_remote = true",
        "{lines:?}"
    );
    let password = login_in(directory.path()).password().to_owned();
    assert!(!lines.concat().contains(&password));
    let extra = format!(
        "Proxy-Authorization: {}\r\n",
        login_in(directory.path()).header_value()
    );
    let proxy = lines[0]
        .trim_start_matches("proxy http://")
        .parse()
        .unwrap();
    let (head, body) = get_through(
        proxy,
        &format!("127.0.0.1:{}/via-binary", origin.port()),
        &extra,
    )
    .await;
    assert_eq!(status(&head), 200, "{head}");
    assert!(body.starts_with("GET /via-binary"));
    // Without the login the request is refused.
    let (head, _) = exchange_raw(
        proxy,
        &format!(
            "GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: x\r\n\r\n",
            origin.port()
        ),
    )
    .await;
    assert_eq!(status(&head), 407, "{head}");
    drop(child);
}

#[tokio::test]
async fn a_configuration_the_server_cannot_start_with_exits_nonzero_with_one_line() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("caguax.cfg");
    std::fs::write(&file, "[server]\nlisten = \"0.0.0.0:0\"\n").unwrap();
    let output = tokio::task::spawn_blocking(move || run(&["-c", file.to_str().unwrap(), "run"]))
        .await
        .unwrap();
    assert_eq!(code(&output), 2, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("allow_remote"));
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_reads_the_configuration_again_and_a_bad_file_leaves_the_running_one() {
    use std::io::Read as _;
    let origin = echo_origin(None).await;
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("caguax.cfg");
    std::fs::write(
        &file,
        "[server]\nlisten = \"127.0.0.1:0\"\n[default]\naction = \"reject\"\n",
    )
    .unwrap();
    let (mut child, lines) = start(&file, |line| line.starts_with("proxy "));
    let proxy = lines[0]
        .trim_start_matches("proxy http://")
        .parse()
        .unwrap();
    let target = format!("127.0.0.1:{}/r", origin.port());
    let extra = format!(
        "Proxy-Authorization: {}\r\n",
        login_in(directory.path()).header_value()
    );
    let extra = extra.as_str();
    let (head, _) = get_through(proxy, &target, extra).await;
    assert_eq!(status(&head), 403);
    let hup = |child: &Running| {
        Command::new("kill")
            .args(["-HUP", &child.0.id().to_string()])
            .status()
            .unwrap();
    };
    std::fs::write(&file, "[server]\nlisten = \"127.0.0.1:0\"\n").unwrap();
    // The new document keeps the listen address only because 127.0.0.1:0 is what it was.
    hup(&child);
    for _ in 0..100 {
        let (head, _) = get_through(proxy, &target, extra).await;
        if status(&head) == 200 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let (head, _) = get_through(proxy, &target, extra).await;
    assert_eq!(status(&head), 200);
    std::fs::write(&file, "[server]\nbogus = 1\n").unwrap();
    hup(&child);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let (head, _) = get_through(proxy, &target, extra).await;
    assert_eq!(status(&head), 200, "the running configuration stays");
    let mut stderr = String::new();
    let _ = child.0.kill();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .ok();
}

#[tokio::test]
async fn cert_probe_reports_the_server_and_that_no_client_certificate_was_asked_for() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(false))).await;
    let directory = tempfile::tempdir().unwrap();
    let ca = directory.path().join("ca.pem");
    std::fs::write(&ca, pki.ca.certificate_pem()).unwrap();
    let url = format!("https://127.0.0.1:{}/", origin.port());
    let ca = ca.to_str().unwrap().to_owned();
    let output = tokio::task::spawn_blocking(move || {
        run(&[
            "cert",
            "probe",
            &url,
            "--cafile",
            &ca,
            "--no-policy",
            "--format",
            "json",
        ])
    })
    .await
    .unwrap();
    assert_eq!(
        code(&output),
        0,
        "{} {}",
        text(&output.stdout),
        text(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["host"], "127.0.0.1");
    assert!(
        value["tls_version"].as_str().unwrap().contains("TLS"),
        "{value}"
    );
    assert_eq!(value["http"], "HTTP/1.1 200 OK");
    assert_eq!(value["certificate_requests"], serde_json::json!([]));
    assert!(value["server"]["subject"].is_string());

    // A server the CA does not vouch for fails the probe, and the report says so.
    let url = format!("https://127.0.0.1:{}/", origin.port());
    let output = tokio::task::spawn_blocking(move || run(&["cert", "probe", &url, "--no-policy"]))
        .await
        .unwrap();
    assert_eq!(code(&output), 1);
    assert!(
        text(&output.stdout).contains("error:"),
        "{}",
        text(&output.stdout)
    );
    assert_eq!(code(&run(&["cert", "probe", "ftp://x.example/"])), 2);
}

#[test]
fn cert_show_with_no_match_is_status_1() {
    let output = run(&[
        "cert",
        "show",
        "no-such-subject-zzzzzzzz-caguax",
        "--pin",
        "none",
    ]);
    assert_eq!(code(&output), 1);
    assert!(text(&output.stderr).contains("no identity matches"));
}
