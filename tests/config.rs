//! Configuration files: formats, positions, building routers and servers.

mod support;

use std::path::Path;

use caguax::config::{
    BuildOptions, Format, LoadOptions, build_parts, build_router, build_server, default_path, load,
    load_server, loads,
};
use caguax::{Action, Connection, Error, Server};
use coqui_sslcontext::{CertificateAuthority, KeyPassword, Secret};
use support::*;

const DOCUMENT: &str = r#"
[server]
listen = "127.0.0.1:0"
timeout = 10

[credentials.work]
backend = "pem"
certificate = "client.pem"
key = "client.key"
cafile = "ca.pem"

[[rules]]
match = ["127.0.0.1", "*.corp.example"]
action = "tls"
credential = "work"
name = "corp"

[[rules]]
match = "*.blocked.example"
action = "reject"

[default]
action = "direct"
"#;

fn parse(text: &str) -> Result<caguax::config::Document, Error> {
    loads(text.as_bytes(), LoadOptions::default())
}

fn message(error: Error) -> String {
    match error {
        Error::Config(error) => error.to_string(),
        other => panic!("not a configuration error: {other}"),
    }
}

/// Writes a PKI the document refers to, and the document, into a directory.
fn config_dir(pki: &Pki, document: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let issued = pki
        .ca
        .leaf(["client.example"])
        .common_name("client-rsa")
        .issue()
        .unwrap();
    std::fs::write(
        directory.path().join("client.pem"),
        issued.certificate_pem(),
    )
    .unwrap();
    std::fs::write(directory.path().join("client.key"), issued.key_pem()).unwrap();
    std::fs::write(directory.path().join("ca.pem"), pki.ca.certificate_pem()).unwrap();
    std::fs::write(directory.path().join("caguax.toml"), document).unwrap();
    directory
}

#[test]
fn a_document_is_read_into_its_tables() {
    let document = parse(DOCUMENT).unwrap();
    assert_eq!(document.rules.len(), 2);
    assert_eq!(
        document.server.connect_timeout,
        std::time::Duration::from_secs(10)
    );
    assert!(document.credentials.contains_key("work"));
}

#[test]
fn malformed_documents_report_a_position_and_never_the_content() {
    for text in ["[server\nlisten = \"x\"", "a = 1\na = 2\n"] {
        let error = loads(text.as_bytes(), LoadOptions::default().path("bad.toml")).unwrap_err();
        let Error::Config(error) = error else {
            panic!("{error}")
        };
        assert_eq!(error.path(), Some("bad.toml"));
        assert!(error.line().is_some(), "{error}");
        assert!(!error.to_string().contains("listen"), "{error}");
    }
    let error = loads(b"\xff\xfe", LoadOptions::default().path("bad.toml")).unwrap_err();
    assert!(message(error).contains("UTF-8"));
}

#[test]
fn a_secret_looking_value_in_a_bad_document_appears_in_no_message() {
    let secret = "hunter2-do-not-print";
    let broken = [
        format!("[server]\nlisten = \"{secret}\"\n"),
        format!("[server]\ntimeout = \"{secret}\"\n"),
        format!("[credentials.c]\nbackend = \"{secret}\"\n"),
        format!("[server\nx = \"{secret}\""),
    ];
    for text in broken {
        let result = parse(&text)
            .and_then(|document| build_server(&document, BuildOptions::default()).map(|_| ()));
        let error = result.unwrap_err();
        assert!(!format!("{error} {error:?}").contains(secret), "{error}");
    }
}

#[test]
fn the_first_line_the_suffix_and_the_option_choose_the_format() {
    let expected = parse(DOCUMENT).unwrap();
    let json = serde_json::json!({
        "server": {"listen": "127.0.0.1:0", "timeout": 10},
        "credentials": {"work": {"backend": "pem", "certificate": "client.pem", "key": "client.key", "cafile": "ca.pem"}},
        "rules": [
            {"match": ["127.0.0.1", "*.corp.example"], "action": "tls", "credential": "work", "name": "corp"},
            {"match": "*.blocked.example", "action": "reject"},
        ],
        "default": {"action": "direct"},
    })
    .to_string();
    let same = |document: &caguax::config::Document| {
        assert_eq!(document.rules.len(), expected.rules.len());
        assert_eq!(
            document.server.connect_timeout,
            expected.server.connect_timeout
        );
        assert_eq!(document.credentials.len(), 1);
    };
    same(&parse(&format!("#!toml\n{DOCUMENT}")).unwrap());
    same(&parse(&format!("#!json\n{json}")).unwrap());
    same(&parse(&format!("#!/usr/bin/env json\n{json}")).unwrap());
    same(&parse(&format!("\u{feff}#!JSON\n{json}")).unwrap());
    same(&loads(json.as_bytes(), LoadOptions::default().format(Format::Json)).unwrap());
    same(
        &loads(
            json.as_bytes(),
            LoadOptions::default().path("settings.json"),
        )
        .unwrap(),
    );
    // A first line wins over the suffix and the option; a file with no known suffix is TOML.
    same(
        &loads(
            format!("#!json\n{json}").as_bytes(),
            LoadOptions::default().path("x.toml"),
        )
        .unwrap(),
    );
    same(
        &loads(
            DOCUMENT.as_bytes(),
            LoadOptions::default().path("caguax.cfg"),
        )
        .unwrap(),
    );
    same(
        &loads(
            DOCUMENT.as_bytes(),
            LoadOptions::default().path("caguax.conf"),
        )
        .unwrap(),
    );
    let error = parse("#!nosuch\nx = 1\n").unwrap_err();
    assert!(message(error).contains("known"));
    // Lines count from the first one, the removed one included.
    let Error::Config(error) = parse("#!json\n{\"server\": ").unwrap_err() else {
        panic!()
    };
    assert!(error.line().unwrap() >= 2, "{error}");
}

#[cfg(feature = "yaml")]
#[test]
fn yaml_documents_are_read() {
    let yaml = "#!yaml\nserver:\n  listen: 127.0.0.1:0\n  timeout: 10\nrules:\n  - match: [localhost, \"*.corp.example\"]\n    action: reject\n";
    let document = parse(yaml).unwrap();
    assert_eq!(document.rules.len(), 1);
    assert_eq!(document.server.connect_timeout.as_secs(), 10);
    let error = parse("#!yaml\nserver: [unclosed").unwrap_err();
    assert!(!message(error).contains("unclosed"));
}

#[cfg(feature = "ini")]
#[test]
fn ini_documents_nest_sections_and_type_their_values() {
    let ini = "#!ini\n[server]\nlisten = 127.0.0.1:0\ntimeout = 10\nallow_remote = no\n\n[credentials.work]\nbackend = system\n\n[rules.corp]\nmatch = [\"localhost\", \"*.corp.example\"]\naction = reject\n\n[rules.blocked]\nmatch = *.blocked.example\naction = reject\n\n[default]\naction = direct\n\n[server.ca]\ncertificate = ca.pem\nkey = ca.key\n";
    let document = parse(ini).unwrap();
    assert_eq!(document.server.connect_timeout.as_secs(), 10);
    assert!(!document.server.allow_remote);
    assert_eq!(document.rules.len(), 2);
    assert_eq!(
        document.server.ca.certificate.as_deref(),
        Some(Path::new("ca.pem"))
    );
    let router = build_router(&document, None).unwrap();
    assert_eq!(router.rules()[0].route().name(), "corp");
    assert_eq!(router.rules()[1].route().name(), "blocked");
    for (value, ok) in [
        ("true", true),
        ("Off", true),
        ("10", true),
        ("-2.5", false),
        ("\"10\"", false),
        ("127.0.0.1:0", false),
        ("[not json", false),
    ] {
        let result = parse(&format!("#!ini\n[server]\nallow_remote = {value}\n"));
        assert_eq!(
            result.is_ok() && matches!(value, "true" | "Off"),
            ok && matches!(value, "true" | "Off")
        );
    }
    for bad in [
        "#!ini\n[rules]\naction = tls\n",
        "#!ini\n[server]\n[server]\n",
        "#!ini\nkey = 1\n",
        "#!ini\n[server\nx = 1\n",
    ] {
        let error = parse(bad).unwrap_err();
        assert!(matches!(error, Error::Config(_)), "{bad}");
    }
    let Error::Config(error) = parse("#!ini\n[server]\nx = 1\n[rules]\n").unwrap_err() else {
        panic!()
    };
    assert!(error.message().contains("rules.<name>"), "{error}");
    assert_eq!(error.line(), Some(4));
}

#[test]
fn errors_name_the_place() {
    let cases = [
        ("[server]\nbogus = 1\n", "bogus"),
        (
            "[[rules]]\nmatch = \"x\"\naction = \"tls\"\ncredential = \"nope\"\n",
            "unknown credential",
        ),
        (
            "[[rules]]\nmatch = \"x\"\naction = \"teleport\"\n",
            "action must be",
        ),
        (
            "[credentials.c]\nbackend = \"cng\"\npin = \"1234\"\n",
            "pin_env",
        ),
        ("[credentials.c]\nbackend = \"nosuch\"\n", "backend must be"),
        ("[credentials.c]\nbackend = \"pem\"\n", "needs certificate"),
        ("[surprise]\n", "surprise"),
        ("[[rules]]\nmatch = \"x\"\nport = \"443\"\n", "port"),
        (
            "[[rules]]\nmatch = \"x\"\ncredential = \"c\"\n",
            "needs action",
        ),
        ("[[rules]]\nmatch = []\n", "match"),
        ("[server]\nconnect_timeout = 0\n", "above zero"),
        ("[server]\ntimeout = \"soon\"\n", "timeout"),
        ("[server]\nlisten = \"not an address\"\n", "listen"),
        ("[server.ca]\ncertificate = \"ca.pem\"\n", "both needed"),
        (
            "[[tunnels]]\nlisten = \"127.0.0.1:0\"\ntarget = \"no-port\"\n",
            "port",
        ),
    ];
    for (text, expected) in cases {
        let error = parse(text)
            .and_then(|document| build_server(&document, BuildOptions::default()).map(|_| ()))
            .unwrap_err();
        let text = message(error);
        assert!(text.contains(expected), "{expected}: {text}");
    }
}

#[test]
fn durations_are_seconds_or_text_with_a_unit() {
    let document = parse(
        "[server]\nconnect_timeout = \"500ms\"\nidle_timeout = 1.5\nclose_timeout = \"2m\"\n",
    )
    .unwrap();
    assert_eq!(document.server.connect_timeout.as_millis(), 500);
    assert_eq!(document.server.idle_timeout.unwrap().as_millis(), 1500);
    assert_eq!(document.server.close_timeout.as_secs(), 120);
    assert_eq!(
        caguax::settings::parse_duration("7d").unwrap().as_secs(),
        7 * 86_400
    );
    assert!(caguax::settings::parse_duration("-1").is_err());
    assert!(caguax::settings::parse_duration("1 fortnight").is_err());
}

#[test]
fn the_router_alone_can_be_built_and_tunnels_with_a_credential_are_tls() {
    let pki = Pki::new();
    let directory = config_dir(&pki, DOCUMENT);
    let text = format!(
        "{DOCUMENT}\n[[tunnels]]\nlisten = \"127.0.0.1:0\"\ntarget = \"db.corp.example:5432\"\ncredential = \"work\"\n"
    );
    let document = parse(&text).unwrap();
    let router = build_router(&document, Some(directory.path())).unwrap();
    let explanation = router.explain(&Connection::new("api.corp.example", 443).unwrap());
    assert_eq!(explanation.route.action(), Action::Tls);
    assert_eq!(explanation.route.name(), "corp");
    // Any local process could use the tunnel's client certificate: the load is refused.
    let refused = build_parts(
        &document,
        BuildOptions::default().base_dir(directory.path()),
    )
    .unwrap_err();
    assert!(
        message(refused).contains("allow_any_local"),
        "the refusal names the opt-in"
    );
    let document = parse(&format!("{text}allow_any_local = true\n")).unwrap();
    let parts = build_parts(
        &document,
        BuildOptions::default().base_dir(directory.path()),
    )
    .unwrap();
    assert_eq!(parts.tunnels.len(), 1);
    assert_eq!(parts.tunnels[0].route().unwrap().action(), Action::Tls);
    assert!(parts.tunnels[0].allow_any_local());
}

#[test]
fn the_listener_login_is_none_generated_a_password_file_or_an_environment_variable() {
    let auth =
        |text: &str| parse(&format!("[server]\n{text}\n")).map(|document| document.server.auth);
    assert!(auth("auth = \"none\"").unwrap().is_none());
    assert!(matches!(
        auth("").unwrap(),
        caguax::Auth::Generated { file: None, .. }
    ));
    assert!(matches!(
        auth("auth = \"generated\"").unwrap(),
        caguax::Auth::Generated { .. }
    ));
    assert!(matches!(
        auth("auth = { user = \"bob\", password_env = \"BOB_PASSWORD\" }").unwrap(),
        caguax::Auth::Env { user, name } if user == "bob" && name == "BOB_PASSWORD"
    ));
    assert!(matches!(
        auth("auth = { password_file = \"pw\" }").unwrap(),
        caguax::Auth::File { user, .. } if user == "caguax"
    ));
    assert!(matches!(
        auth("auth = { file = \"where.auth\" }").unwrap(),
        caguax::Auth::Generated { file: Some(_), .. }
    ));
    for bad in [
        "auth = \"required\"",
        "auth = { password_env = \"A\", password_file = \"b\" }",
        "auth = { password_env = \"A\", file = \"b\" }",
        "auth = { user = \"a:b\" }",
        "auth = { password = \"in-the-file\" }",
    ] {
        assert!(auth(bad).is_err(), "{bad}");
    }
    // `Debug` never shows the password.
    let login = caguax::Login::new("bob", "hunter2-secret").unwrap();
    assert!(!format!("{login:?} {:?}", caguax::Auth::Login(login.clone())).contains("hunter2"));
}

#[tokio::test]
async fn a_configuration_file_drives_the_server() {
    let pki = Pki::new();
    let origin = echo_origin(Some(pki.server_config(true))).await;
    let directory = config_dir(
        &pki,
        &DOCUMENT.replace(
            "timeout = 10\n",
            "timeout = 10\nauth = { user = \"alice\", password_file = \"proxy.pw\" }\n",
        ),
    );
    std::fs::write(directory.path().join("proxy.pw"), "file-secret\n").unwrap();
    let server = load_server(directory.path().join("caguax.toml"))
        .unwrap()
        .start()
        .await
        .unwrap();
    let proxy = server.addresses()[0];
    // The password file is relative to the configuration file.
    let login = caguax::Login::new("alice", "file-secret").unwrap();
    assert_eq!(server.proxy_login().unwrap().userinfo(), login.userinfo());
    let (head, _) = get_through(proxy, "a.blocked.example/", "").await;
    assert_eq!(status(&head), 407, "{head}");
    let (head, body) = get_through(
        proxy,
        &format!("127.0.0.1:{}/c", origin.port()),
        &format!("Proxy-Authorization: {}\r\n", login.header_value()),
    )
    .await;
    assert_eq!(status(&head), 200, "{head} {body}");
    assert!(body.contains("client-subject: CN=client-rsa"), "{body}");
    let (head, _) = get_through(
        proxy,
        "a.blocked.example/",
        &format!("Proxy-Authorization: {}\r\n", login.header_value()),
    )
    .await;
    assert_eq!(status(&head), 403);
    server.shutdown().await;
}

#[tokio::test]
async fn recording_settings_build_recorders_with_paths_relative_to_the_file() {
    let pki = Pki::new();
    let directory = config_dir(
        &pki,
        &DOCUMENT.replace(
            "timeout = 10\n",
            "timeout = 10\nlog_traffic = true\nkeylog = \"keys.log\"\n",
        ),
    );
    let server = load_server(directory.path().join("caguax.toml"))
        .unwrap()
        .start()
        .await
        .unwrap();
    assert_eq!(server.recorders().len(), 1);
    assert!(directory.path().join("keys.log").exists());
    assert_eq!(
        server.settings().keylog.as_deref(),
        Some(directory.path().join("keys.log").as_path())
    );
    assert!(
        server
            .non_defaults()
            .iter()
            .any(|entry| entry.contains("keylog"))
    );
    server.shutdown().await;
    #[cfg(feature = "pcap")]
    {
        let document = parse(&DOCUMENT.replace(
            "timeout = 10\n",
            "timeout = 10\nrecord = \"out/proxy.pcapng\"\n",
        ))
        .unwrap();
        std::fs::create_dir(directory.path().join("out")).unwrap();
        let server = build_server(
            &document,
            BuildOptions::default().base_dir(directory.path()),
        )
        .unwrap()
        .start()
        .await
        .unwrap();
        server.shutdown().await;
        assert!(directory.path().join("out/proxy.pcapng").exists());
    }
}

#[tokio::test]
async fn an_encrypted_key_takes_its_password_from_a_file_or_an_environment_variable() {
    // A CA's own certificate and encrypted key stand in for any password-protected identity.
    let ca = CertificateAuthority::builder("Locked").create().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let encrypted = ca
        .private_key_pem(&KeyPassword::Secret(Secret::new("open sesame")))
        .unwrap();
    std::fs::write(directory.path().join("c.pem"), ca.certificate_pem()).unwrap();
    std::fs::write(directory.path().join("c.key"), encrypted.as_bytes()).unwrap();
    std::fs::write(directory.path().join("pass"), "open sesame\nsecond line\n").unwrap();
    let template = |password: &str| {
        format!(
            "[credentials.c]\nbackend = \"pem\"\ncertificate = \"c.pem\"\nkey = \"c.key\"\n{password}\n[[rules]]\nmatch = \"x\"\naction = \"tls\"\ncredential = \"c\"\n"
        )
    };
    let build = |password: &str| {
        let document = parse(&template(password)).unwrap();
        let router = build_router(&document, Some(directory.path())).unwrap();
        router.rules()[0].route().clone()
    };
    let credential = |route: &caguax::Route| match route.tls() {
        Some(caguax::TlsSource::Credential(credential)) => credential.clone(),
        _ => panic!("no credential"),
    };
    let from_file = credential(&build("password_file = \"pass\""));
    from_file.tls_config("x.example").await.unwrap();
    let wrong = credential(&build("password_env = \"CAGUAX_TEST_UNSET_PASSWORD\""));
    let error = wrong.tls_config("x.example").await.unwrap_err();
    assert!(matches!(error, Error::CredentialUnavailable(_)), "{error}");
    let none = credential(&build(""));
    assert!(none.tls_config("x.example").await.is_err());
    let both = parse(&template("password_file = \"pass\"\npassword_env = \"X\"")).unwrap();
    assert!(message(build_router(&both, Some(directory.path())).unwrap_err()).contains("not both"));
    // The secrets are in no message.
    assert!(!format!("{error:?}").contains("open sesame"));
}

#[test]
fn a_pin_is_a_variable_name_or_the_keystore_and_never_a_value() {
    let document = parse(
        "[credentials.card]\nbackend = \"pkcs11\"\npin_env = \"CAGUAX_TEST_CARD_PIN\"\noptions = { module = \"/missing.so\", slot = 2 }\n[credentials.os]\nbackend = \"system\"\npin = \"keystore\"\nquery = { subject = \"alice\", valid_only = false }\n[[rules]]\nmatch = \"x\"\naction = \"tls\"\ncredential = \"card\"\n",
    )
    .unwrap();
    let router = build_router(&document, None).unwrap();
    let Some(caguax::TlsSource::Credential(card)) = router.rules()[0].route().tls() else {
        panic!("no credential");
    };
    assert_eq!(card.backend(), Some(caguax::Backend::Pkcs11));
    assert_eq!(card.options().unwrap().slot, Some(2));
    assert!(matches!(
        card.options().unwrap().pin,
        coqui_sslcontext::Pin::Callback(_)
    ));
    assert!(!format!("{card:?}").contains("CAGUAX_TEST_CARD_PIN"));
    let unknown =
        parse("[credentials.c]\nbackend = \"pkcs11\"\noptions = { surprise = 1 }\n").unwrap();
    assert!(message(build_router(&unknown, None).unwrap_err()).contains("unknown option"));
}

#[test]
fn a_credential_with_no_verification_is_a_non_default() {
    let document = parse("[credentials.lax]\nbackend = \"system\"\nverify = false\n[[rules]]\nmatch = \"x\"\naction = \"tls\"\ncredential = \"lax\"\n").unwrap();
    let router = build_router(&document, None).unwrap();
    assert_eq!(
        caguax::config::router_non_defaults(&router),
        vec!["credentials.lax.verify = false".to_owned()]
    );
}

#[test]
fn the_default_path_is_the_variable_else_the_user_configuration_directory() {
    // SAFETY: this is the only test that touches the process environment.
    unsafe { std::env::set_var("CAGUAX_CONFIG", "/somewhere/else.cfg") };
    assert_eq!(default_path(), Path::new("/somewhere/else.cfg"));
    unsafe { std::env::remove_var("CAGUAX_CONFIG") };
    let path = default_path();
    assert!(
        path.ends_with(Path::new("caguax").join("caguax.cfg")),
        "{path:?}"
    );
}

#[test]
fn a_missing_file_is_an_io_error() {
    let error = load(
        "/nonexistent-directory-for-caguax/caguax.toml",
        LoadOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Io(_)));
    let _ = Server::direct;
}
