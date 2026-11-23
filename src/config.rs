//! Configuration files: read a document, then build a server from it.
//!
//! The file is `caguax.cfg`. Its first line may name its format (`#!toml`, `#!yaml`, `#!json`,
//! `#!ini`, also `#!/usr/bin/env yaml`; the line is not part of the document); without one the
//! format is [`LoadOptions::format`], else the one the file name's suffix selects (`.toml`,
//! `.yaml`/`.yml`, `.json`, `.ini`; `.cfg` and no suffix select none), else TOML. YAML needs
//! feature `yaml` and INI feature `ini`.
//!
//! The dialects: TOML keeps its own rules (duplicate keys are errors, datetimes become text); in
//! JSON a repeated key is the last one; YAML is read by `serde-saphyr`; a number too large for the
//! type it is read into is an error. The text is strict UTF-8 and one leading byte-order mark is
//! ignored. Every failure is a [`ConfigError`] naming the table and key (`table.key: problem`)
//! and, when the parser knows, the line and column; it never quotes the document. Unknown tables
//! and keys are errors. Relative paths resolve against the file's directory. Secrets never live
//! in the file: PINs and key passwords are named by environment variable (`pin_env`,
//! `password_env`) or file (`password_file`), read when first needed.
//!
//! In INI a dotted section nests (`[credentials.work]`, `[server.ca]`), `[rules.<name>]` and
//! `[tunnels.<name>]` are list entries in file order whose `name` defaults to `<name>`, and values
//! are typed: `true`/`false`/`yes`/`no`/`on`/`off`, integers, decimals, JSON lists, objects and
//! quoted strings; anything else is a string.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::FromStr;
use std::path::{Path, PathBuf};

use anycfg::{Callbacks, CodecError, Formats, Options};
use coqui_sslcontext::{IdentityQuery, KeyPassword, Pin, PinAnswer, Secret, TlsVersion};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::connection::Connection;
use crate::credential::{Backend, Credential, KeystoreOptions, StoreLocation};
use crate::error::{ConfigError, Error, Result};
use crate::route::{Action, Route, Router, Rule, TlsSource};
use crate::rules::Matcher;
use crate::server::{Server, ServerBuilder, Tunnel};
use crate::settings::ServerSettings;
use crate::upstream::Egress;

/// The environment variable naming the configuration file.
pub const CONFIG_VARIABLE: &str = "CAGUAX_CONFIG";

/// A configuration document format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// TOML, the default.
    Toml,
    /// JSON.
    Json,
    /// YAML. Needs feature `yaml`.
    Yaml,
    /// INI with dotted sections. Needs feature `ini`.
    Ini,
}

impl Format {
    /// The lower-case name a `#!` line uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Json => "json",
            Self::Yaml => "yaml",
            Self::Ini => "ini",
        }
    }
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        match text.to_ascii_lowercase().as_str() {
            "toml" => Ok(Self::Toml),
            "json" => Ok(Self::Json),
            "yaml" | "yml" => Ok(Self::Yaml),
            "ini" => Ok(Self::Ini),
            _ => Err(config_error(
                "unknown format; the known ones are toml, json, yaml and ini",
            )),
        }
    }
}

fn config_error(message: impl Into<String>) -> Error {
    ConfigError::new(message).into()
}

/// How a document is read.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct LoadOptions {
    path: Option<String>,
    format: Option<Format>,
}

impl LoadOptions {
    /// Labels errors with this path; its suffix may name the format.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// The format to read (a `#!` first line still wins).
    pub fn format(mut self, format: Format) -> Self {
        self.format = Some(format);
        self
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

/// A `[credentials.<name>]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct CredentialSpec {
    /// `system`, `cng`, `keychain`, `pkcs11` or `pem`.
    pub backend: Option<String>,
    /// The keystore's options (`store`, `location`, `keychain`, `module`, `token`, `slot`).
    pub options: Map<String, Value>,
    /// The identity query (`subject`, `issuer`, `thumbprint`, `label`, `valid_only`).
    pub query: Map<String, Value>,
    /// The environment variable holding the PIN, read when first needed.
    pub pin_env: Option<String>,
    /// `keystore`: the operating system's dialog or PIN pad asks.
    pub pin: Option<String>,
    /// A `pem` credential's certificate (PEM, DER, or a PKCS#12 bundle with no key).
    pub certificate: Option<PathBuf>,
    /// A `pem` credential's key.
    pub key: Option<PathBuf>,
    /// The environment variable holding the key's or bundle's password.
    pub password_env: Option<String>,
    /// A file whose first line is the key's or bundle's password.
    pub password_file: Option<PathBuf>,
    /// Verify the destination's certificate (default true).
    pub verify: Option<bool>,
    /// Trust the roots in this PEM file instead of the system's.
    pub cafile: Option<PathBuf>,
    /// Trust the roots in every file of this directory.
    pub capath: Option<PathBuf>,
    /// Trust these roots (PEM text).
    pub cadata: Option<String>,
    /// `1.2` or `1.3`.
    pub minimum_version: Option<String>,
}

/// The decision keys shared by `[default]`, `[[rules]]` and `[[tunnels]]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct RouteSpec {
    /// `direct` (default), `tls` or `reject`.
    pub action: Option<String>,
    /// The credential's name; required with `tls`, an error with `direct`.
    pub credential: Option<String>,
    /// `direct`, a proxy URL, a PAC result or `pac:<location>`.
    pub upstream: Option<String>,
    /// The route's label.
    pub name: Option<String>,
}

/// A `[[rules]]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RuleSpec {
    /// A pattern, or a list of them (any of).
    #[serde(rename = "match")]
    matches: OneOrMany<String>,
    /// A port or a list of ports.
    #[serde(default)]
    port: Option<OneOrMany<u16>>,
    /// A regular expression over the request path (forwarded HTTP only).
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    upstream: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// A `[[tunnels]]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TunnelSpec {
    /// Where the tunnel accepts.
    listen: String,
    /// `host:port`.
    target: String,
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    upstream: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// A configuration document: the `[server]`, `[credentials.*]`, `[[rules]]`, `[default]` and
/// `[[tunnels]]` tables, every one optional.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct Document {
    /// The server's settings.
    pub server: ServerSettings,
    /// The named credentials.
    pub credentials: BTreeMap<String, CredentialSpec>,
    /// The rules, first match wins.
    pub rules: Vec<RuleSpec>,
    /// The route when no rule matches.
    pub default: RouteSpec,
    /// The tunnel listeners.
    pub tunnels: Vec<TunnelSpec>,
}

fn formats() -> core::result::Result<Formats<Value>, anycfg::Error> {
    let mut formats = Formats::new();
    formats.register(
        "toml",
        ["toml"],
        Callbacks::new(decode_toml, |value: &Value| {
            toml::to_string_pretty(value)
                .map(String::into_bytes)
                .map_err(|_| CodecError::new().message("the value has no TOML form"))
        }),
    )?;
    formats.register(
        "json",
        ["json"],
        Callbacks::new(decode_json, |value: &Value| {
            serde_json::to_vec_pretty(value)
                .map_err(|_| CodecError::new().message("the value has no JSON form"))
        }),
    )?;
    #[cfg(feature = "yaml")]
    formats.register(
        "yaml",
        ["yaml", "yml"],
        Callbacks::new(decode_yaml, |value: &Value| {
            serde_saphyr::to_string(value)
                .map(String::into_bytes)
                .map_err(|_| CodecError::new().message("the value has no YAML form"))
        }),
    )?;
    #[cfg(feature = "ini")]
    formats.register(
        "ini",
        ["ini"],
        Callbacks::new(ini::decode, |_: &Value| {
            Err(CodecError::new().message("a document is not written as INI"))
        }),
    )?;
    formats.set_default("toml")?;
    Ok(formats)
}

fn utf8(bytes: &[u8]) -> core::result::Result<&str, CodecError> {
    core::str::from_utf8(bytes).map_err(|error| {
        CodecError::at_offset(bytes, error.valid_up_to()).message("not valid UTF-8")
    })
}

fn decode_toml(bytes: &[u8]) -> core::result::Result<Value, CodecError> {
    let text = utf8(bytes)?;
    let table: toml::Table = toml::from_str(text).map_err(|error| {
        let failure = error.span().map_or_else(CodecError::new, |span| {
            CodecError::at_offset(bytes, span.start)
        });
        // `message()` is the parser's text without the excerpt its `Display` adds.
        failure.message(error.message())
    })?;
    Ok(toml_value(toml::Value::Table(table)))
}

/// Datetimes become text; the parser has already bounded the nesting this recurses over.
fn toml_value(value: toml::Value) -> Value {
    match value {
        toml::Value::String(text) => Value::String(text),
        toml::Value::Integer(number) => Value::from(number),
        toml::Value::Float(number) => Value::from(number),
        toml::Value::Boolean(flag) => Value::Bool(flag),
        toml::Value::Datetime(datetime) => Value::String(datetime.to_string()),
        toml::Value::Array(items) => Value::Array(items.into_iter().map(toml_value).collect()),
        toml::Value::Table(table) => Value::Object(
            table
                .into_iter()
                .map(|(key, value)| (key, toml_value(value)))
                .collect(),
        ),
    }
}

fn decode_json(bytes: &[u8]) -> core::result::Result<Value, CodecError> {
    serde_json::from_slice::<Value>(bytes).map_err(|error| {
        // serde_json's text is a fixed syntax message followed by the position.
        let text = error.to_string();
        let position = alloc::format!(" at line {} column {}", error.line(), error.column());
        CodecError::new()
            .line(error.line())
            .column(error.column())
            .message(text.strip_suffix(&position).unwrap_or(&text))
    })
}

#[cfg(feature = "yaml")]
fn decode_yaml(bytes: &[u8]) -> core::result::Result<Value, CodecError> {
    // `Display` prints the source lines and several variants quote a scalar: the position only.
    serde_saphyr::from_slice(bytes).map_err(|error| {
        let failure = match error.location() {
            Some(location) => CodecError::new()
                .line(location.line() as usize)
                .column(location.column() as usize),
            None => CodecError::new(),
        };
        failure.message("the YAML document is malformed")
    })
}

#[cfg(feature = "ini")]
mod ini {
    //! The INI dialect: `[a.b]` nests, `[rules.<name>]` and `[tunnels.<name>]` are list entries,
    //! values are typed.

    use anycfg::CodecError;
    use serde_json::{Map, Value};

    use super::utf8;

    fn typed(text: &str) -> Value {
        let text = text.trim();
        match text.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" => return Value::Bool(true),
            "false" | "no" | "off" => return Value::Bool(false),
            _ => {}
        }
        let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
        if !digits.is_empty()
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && let Ok(number) = text.parse::<i64>()
        {
            return Value::from(number);
        }
        let decimal = digits
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '.')
            && digits.contains('.')
            && digits
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'));
        if decimal && let Ok(number) = text.parse::<f64>() {
            return Value::from(number);
        }
        if text.starts_with(['[', '{', '"'])
            && let Ok(value) = serde_json::from_str::<Value>(text)
        {
            return value;
        }
        Value::String(text.into())
    }

    struct Section {
        name: String,
        line: usize,
        values: Map<String, Value>,
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Value, CodecError> {
        let text = utf8(bytes)?;
        let mut sections: Vec<Section> = Vec::new();
        let mut pending: Option<String> = None;
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let at = |message: &str| CodecError::new().line(line).message(message);
            if raw.trim().is_empty() {
                continue;
            }
            let indented = raw.starts_with([' ', '\t']);
            let trimmed = raw.trim();
            if trimmed.starts_with(['#', ';']) {
                continue;
            }
            if indented && let Some(key) = &pending {
                let Some(section) = sections.last_mut() else {
                    return Err(at("a value outside a section"));
                };
                if let Some(Value::String(existing)) = section.values.get_mut(key) {
                    existing.push('\n');
                    existing.push_str(trimmed);
                    let joined = typed(existing);
                    section.values.insert(key.clone(), joined);
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix('[') {
                let Some(name) = rest.strip_suffix(']') else {
                    return Err(at("a section header is missing its ]"));
                };
                if name.is_empty() {
                    return Err(at("a section needs a name"));
                }
                if sections.iter().any(|section| section.name == name) {
                    return Err(at("a section appears twice"));
                }
                sections.push(Section {
                    name: name.into(),
                    line,
                    values: Map::new(),
                });
                pending = None;
                continue;
            }
            let Some(section) = sections.last_mut() else {
                return Err(at("a value outside a section"));
            };
            let split = trimmed
                .find(['=', ':'])
                .ok_or_else(|| at("a line is a section, a comment or key = value"))?;
            let key = trimmed[..split].trim().to_ascii_lowercase();
            if key.is_empty() {
                return Err(at("a key is not empty"));
            }
            if section.values.contains_key(&key) {
                return Err(at("a key appears twice in its section"));
            }
            section.values.insert(
                key.clone(),
                Value::String(trimmed[split + 1..].trim().into()),
            );
            pending = Some(key);
        }
        // A value is typed once it is complete, continuation lines included.
        for section in &mut sections {
            for value in section.values.values_mut() {
                if let Value::String(text) = value {
                    *value = typed(text);
                }
            }
        }
        shape(sections)
    }

    fn shape(sections: Vec<Section>) -> Result<Value, CodecError> {
        let mut out = Map::new();
        for section in sections {
            let at = |message: &str| CodecError::new().line(section.line).message(message);
            let parts: Vec<&str> = section.name.split('.').collect();
            let mut values = section.values.clone();
            if matches!(parts[0], "rules" | "tunnels") {
                if parts.len() != 2 || parts[1].is_empty() {
                    return Err(at(
                        "a rules or tunnels section is [rules.<name>] or [tunnels.<name>]",
                    ));
                }
                values
                    .entry("name")
                    .or_insert_with(|| Value::String(parts[1].into()));
                match out
                    .entry(parts[0])
                    .or_insert_with(|| Value::Array(Vec::new()))
                {
                    Value::Array(list) => list.push(Value::Object(values)),
                    _ => return Err(at("a section's table is not a list")),
                }
                continue;
            }
            let mut table = &mut out;
            for part in &parts[..parts.len() - 1] {
                let entry = table
                    .entry(*part)
                    .or_insert_with(|| Value::Object(Map::new()));
                let Value::Object(next) = entry else {
                    return Err(at("a section's parent is not a table"));
                };
                table = next;
            }
            let last = parts[parts.len() - 1];
            match table.get_mut(last) {
                Some(Value::Object(existing)) => existing.extend(values),
                Some(_) => return Err(at("a section's name is already a value")),
                None => {
                    table.insert(last.into(), Value::Object(values));
                }
            }
        }
        Ok(Value::Object(out))
    }
}

fn declared_format(text: &str) -> core::result::Result<Option<(Format, &str)>, ConfigError> {
    let Some(rest) = text.strip_prefix("#!") else {
        return Ok(None);
    };
    let (line, body) = rest.split_once('\n').unwrap_or((rest, ""));
    let word = line
        .trim()
        .rsplit(|c: char| c.is_whitespace() || c == '/' || c == '\\')
        .next()
        .unwrap_or("");
    let format = word.parse::<Format>().map_err(|_| {
        ConfigError::new("the first line names a format that is not known")
            .at_position(Some(1), None)
    })?;
    Ok(Some((format, body)))
}

fn format_for(path: &str) -> Option<Format> {
    let extension = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
    extension.parse().ok()
}

fn locate(path: Option<&str>, error: ConfigError) -> Error {
    match path {
        Some(path) => error.at_path(path).into(),
        None => error.into(),
    }
}

/// Reads a document from `text`.
///
/// # Errors
///
/// [`Error::Config`] for text that is not UTF-8, a format that is not known or not built in, a
/// syntax error or a table or key that is not part of the document.
pub fn loads(text: &[u8], options: LoadOptions) -> Result<Document> {
    let path = options.path.as_deref();
    let fail = |error: ConfigError| locate(path, error);
    let text = match core::str::from_utf8(text) {
        Ok(text) => text,
        Err(error) => {
            return Err(fail(ConfigError::new(alloc::format!(
                "not UTF-8 at byte {}",
                error.valid_up_to()
            ))));
        }
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let (declared, body, removed) = match declared_format(text).map_err(fail)? {
        Some((format, body)) => (Some(format), body, 1),
        None => (None, text, 0),
    };
    let format = declared
        .or(options.format)
        .or_else(|| path.and_then(format_for))
        .unwrap_or(Format::Toml);
    let formats = formats().map_err(|error| fail(ConfigError::new(error.to_string())))?;
    let registered = |name: &str| formats.detect(b"", Options::new().format(name)).is_ok();
    if !registered(format.as_str()) {
        return Err(fail(ConfigError::new(alloc::format!(
            "the {} format needs the `{}` feature",
            format.as_str(),
            format.as_str()
        ))));
    }
    formats
        .from_slice_typed::<Document>(body.as_bytes(), Options::new().format(format.as_str()))
        .map_err(|error| fail(from_anycfg(&error, removed)))
}

fn from_anycfg(error: &anycfg::Error, removed: usize) -> ConfigError {
    match error {
        anycfg::Error::Parse {
            line,
            column,
            message,
            ..
        } => ConfigError::new(
            message
                .clone()
                .unwrap_or_else(|| "the document is malformed".into()),
        )
        .at_position(line.map(|line| line + removed), *column),
        anycfg::Error::Conversion { path, message } => {
            let what = message
                .clone()
                .unwrap_or_else(|| "the value is not valid".into());
            match path {
                Some(path) if !path.is_empty() => {
                    ConfigError::new(alloc::format!("{path}: {what}"))
                }
                _ => ConfigError::new(what),
            }
        }
        anycfg::Error::TooLarge { .. } => ConfigError::new("the document is too large"),
        anycfg::Error::TooDeep { .. } => ConfigError::new("the document nests too deeply"),
        other => ConfigError::new(other.to_string()),
    }
}

/// Reads and parses the configuration file at `path`.
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be read, otherwise as [`loads`].
pub fn load(path: impl AsRef<Path>, options: LoadOptions) -> Result<Document> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)?;
    let options = if options.path.is_some() {
        options
    } else {
        options.path(path.display().to_string())
    };
    loads(&bytes, options)
}

/// `CAGUAX_CONFIG`, else `caguax/caguax.cfg` in the platform's configuration directory
/// (`%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or `~/.config` elsewhere).
pub fn default_path() -> PathBuf {
    if let Some(configured) = std::env::var_os(CONFIG_VARIABLE).filter(|value| !value.is_empty()) {
        return PathBuf::from(configured);
    }
    anycfg::user_config_path(Some(Path::new("caguax/caguax.cfg")))
        .unwrap_or_else(|_| PathBuf::from("caguax.cfg"))
}

/// How a document becomes objects.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BuildOptions {
    /// Relative paths in the document resolve against this directory (default the current one).
    pub base_dir: Option<PathBuf>,
    /// Names the document in error messages (default `<document>`).
    pub label: String,
}

impl BuildOptions {
    /// Relative paths in the document resolve against this directory.
    #[must_use]
    pub fn base_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        self.base_dir = Some(directory.into());
        self
    }

    /// Names the document in error messages.
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            base_dir: None,
            label: "<document>".into(),
        }
    }
}

struct Builder<'a> {
    document: &'a Document,
    base: PathBuf,
    label: String,
}

impl Builder<'_> {
    fn fail(&self, where_: &str, message: impl core::fmt::Display) -> Error {
        ConfigError::new(alloc::format!("{where_}: {message}"))
            .at_path(self.label.clone())
            .into()
    }

    fn path(&self, path: &Path) -> PathBuf {
        let expanded = match path.strip_prefix("~") {
            Ok(rest) => {
                std::env::home_dir().map_or_else(|| path.to_path_buf(), |home| home.join(rest))
            }
            Err(_) => path.to_path_buf(),
        };
        if expanded.is_absolute() {
            expanded
        } else {
            self.base.join(expanded)
        }
    }

    fn read(&self, where_: &str, path: &Path) -> Result<Vec<u8>> {
        std::fs::read(self.path(path))
            .map_err(|error| self.fail(where_, alloc::format!("cannot read: {}", error.kind())))
    }

    fn password(&self, where_: &str, spec: &CredentialSpec) -> Result<KeyPassword> {
        match (&spec.password_env, &spec.password_file) {
            (Some(_), Some(_)) => {
                Err(self.fail(where_, "give password_env or password_file, not both"))
            }
            (Some(name), None) => Ok(env_password(name)),
            (None, Some(file)) => Ok(KeyPassword::File(self.path(file))),
            (None, None) => Ok(KeyPassword::None),
        }
    }

    fn credential(&self, name: &str, spec: &CredentialSpec) -> Result<Credential> {
        let where_ = alloc::format!("credentials.{name}");
        let builder = if spec.backend.as_deref() == Some("pem") {
            let certificate = spec
                .certificate
                .as_ref()
                .ok_or_else(|| self.fail(&where_, "a pem credential needs certificate"))?;
            let certificate = self.read(&alloc::format!("{where_}.certificate"), certificate)?;
            let key = match &spec.key {
                Some(key) => Some(self.read(&alloc::format!("{where_}.key"), key)?),
                None => None,
            };
            Credential::from_pem(certificate, key, self.password(&where_, spec)?)
        } else {
            let backend = spec
                .backend
                .as_deref()
                .ok_or_else(|| {
                    self.fail(
                        &where_,
                        "backend must be \"system\", \"cng\", \"keychain\", \"pkcs11\" or \"pem\"",
                    )
                })?
                .parse::<Backend>()
                .map_err(|error| self.fail(&where_, error))?;
            let pin = match (&spec.pin_env, spec.pin.as_deref()) {
                (Some(_), Some(_)) => {
                    return Err(self.fail(&where_, "give pin_env or pin, not both"));
                }
                (Some(name), None) => env_pin(name),
                (None, Some("keystore")) => Pin::Keystore,
                (None, Some(_)) => {
                    return Err(
                        self.fail(&where_, "pin may only be \"keystore\"; put PINs in pin_env")
                    );
                }
                (None, None) => Pin::None,
            };
            let options = self.keystore_options(&where_, &spec.options, pin)?;
            let query = self.query(&where_, &spec.query)?;
            Credential::keystore(backend)
                .keystore_options(options)
                .query(query)
        };
        let mut builder = builder.name(name);
        if let Some(verify) = spec.verify {
            builder = builder.verify(verify);
        }
        if let Some(path) = &spec.cafile {
            builder = builder.cafile(self.path(path));
        }
        if let Some(path) = &spec.capath {
            builder = builder.capath(self.path(path));
        }
        if let Some(data) = &spec.cadata {
            builder = builder.cadata(data.clone().into_bytes());
        }
        if let Some(version) = &spec.minimum_version {
            builder = builder.minimum_version(match version.as_str() {
                "1.2" => TlsVersion::Tls12,
                "1.3" => TlsVersion::Tls13,
                _ => return Err(self.fail(&where_, "minimum_version is \"1.2\" or \"1.3\"")),
            });
        }
        Ok(builder.build())
    }

    fn keystore_options(
        &self,
        where_: &str,
        table: &Map<String, Value>,
        pin: Pin,
    ) -> Result<KeystoreOptions> {
        let here = alloc::format!("{where_}.options");
        let mut options = KeystoreOptions {
            pin,
            ..KeystoreOptions::default()
        };
        let text = |key: &str, value: &Value| -> Result<String> {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| self.fail(&here, alloc::format!("{key} is a string")))
        };
        for (key, value) in table {
            match key.as_str() {
                "store" => options.store = Some(text(key, value)?),
                "location" => {
                    options.location = text(key, value)?
                        .parse::<StoreLocation>()
                        .map_err(|error| self.fail(&here, error))?;
                }
                "keychain" => options.keychain = Some(self.path(Path::new(&text(key, value)?))),
                "module" => options.module = Some(self.path(Path::new(&text(key, value)?))),
                "token" => options.token = Some(text(key, value)?),
                "slot" => {
                    options.slot = Some(
                        value
                            .as_u64()
                            .ok_or_else(|| self.fail(&here, "slot is a number"))?,
                    );
                }
                _ => return Err(self.fail(&here, "an unknown option")),
            }
        }
        Ok(options)
    }

    fn query(&self, where_: &str, table: &Map<String, Value>) -> Result<IdentityQuery> {
        let here = alloc::format!("{where_}.query");
        let mut query = IdentityQuery::builder();
        for (key, value) in table {
            let text = || {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| self.fail(&here, alloc::format!("{key} is a string")))
            };
            query = match key.as_str() {
                "subject" => query.subject(text()?),
                "issuer" => query.issuer(text()?),
                "thumbprint" => query.thumbprint(text()?),
                "label" => query.label(text()?),
                "valid_only" => query.valid_only(
                    value
                        .as_bool()
                        .ok_or_else(|| self.fail(&here, "valid_only is true or false"))?,
                ),
                _ => return Err(self.fail(&here, "an unknown query key")),
            };
        }
        Ok(query.build())
    }

    fn credentials(&self) -> Result<BTreeMap<String, Arc<Credential>>> {
        self.document
            .credentials
            .iter()
            .map(|(name, spec)| Ok((name.clone(), Arc::new(self.credential(name, spec)?))))
            .collect()
    }

    fn route(
        &self,
        where_: &str,
        spec: &RouteSpec,
        credentials: &BTreeMap<String, Arc<Credential>>,
    ) -> Result<Route> {
        self.route_of(
            where_,
            spec.action.as_deref(),
            spec.credential.as_deref(),
            spec.upstream.as_deref(),
            spec.name.as_deref(),
            credentials,
        )
    }

    fn route_of(
        &self,
        where_: &str,
        action: Option<&str>,
        credential: Option<&str>,
        upstream: Option<&str>,
        name: Option<&str>,
        credentials: &BTreeMap<String, Arc<Credential>>,
    ) -> Result<Route> {
        let action = action
            .unwrap_or("direct")
            .parse::<Action>()
            .map_err(|error| self.fail(where_, error))?;
        let upstream = match upstream {
            Some(text) => Some(
                text.parse::<Egress>()
                    .map_err(|error| self.fail(where_, error))?,
            ),
            None => None,
        };
        let name = name.unwrap_or("");
        let builder = match action {
            Action::Reject => Route::reject(),
            Action::Tls => {
                let found = credential.and_then(|name| credentials.get(name));
                let Some(found) = found else {
                    return Err(self.fail(
                        where_,
                        alloc::format!("unknown credential {:?}", credential.unwrap_or("")),
                    ));
                };
                Route::with_tls(TlsSource::Credential(Arc::clone(found)))
            }
            _ => {
                if credential.is_some() {
                    return Err(self.fail(where_, "credential needs action = \"tls\""));
                }
                Route::direct()
            }
        };
        let mut builder = builder.name(name);
        if let (Some(upstream), true) = (upstream, action != Action::Reject) {
            builder = builder.upstream(upstream);
        }
        Ok(builder.build())
    }

    fn matcher(&self, where_: &str, spec: &RuleSpec) -> Result<Matcher> {
        let patterns = spec.matches.clone().into_vec();
        if patterns.is_empty() {
            return Err(self.fail(where_, "match must be a pattern or a list of patterns"));
        }
        let mut parts = Vec::new();
        for pattern in &patterns {
            parts.push(
                pattern
                    .parse::<Matcher>()
                    .map_err(|error| self.fail(where_, error))?,
            );
        }
        let mut matcher = if parts.len() == 1 {
            parts.remove(0)
        } else {
            Matcher::AnyOf(parts)
        };
        if let Some(ports) = &spec.port {
            matcher = matcher
                & Matcher::port(ports.clone().into_vec())
                    .map_err(|error| self.fail(where_, error))?;
        }
        if let Some(path) = &spec.path {
            #[cfg(feature = "regex")]
            {
                matcher =
                    matcher & Matcher::path(path).map_err(|error| self.fail(where_, error))?;
            }
            #[cfg(not(feature = "regex"))]
            {
                let _ = path;
                return Err(self.fail(where_, "a path rule needs the `regex` feature"));
            }
        }
        Ok(matcher)
    }

    fn router(&self, credentials: &BTreeMap<String, Arc<Credential>>) -> Result<Router> {
        let mut router = Router::builder().default_route(self.route(
            "default",
            &self.document.default,
            credentials,
        )?);
        for (index, spec) in self.document.rules.iter().enumerate() {
            let where_ = alloc::format!("rules[{index}]");
            let route = self.route_of(
                &where_,
                spec.action.as_deref(),
                spec.credential.as_deref(),
                spec.upstream.as_deref(),
                spec.name.as_deref(),
                credentials,
            )?;
            router = router.rule(Rule::new(self.matcher(&where_, spec)?, route));
        }
        Ok(router.build())
    }

    fn tunnels(&self, credentials: &BTreeMap<String, Arc<Credential>>) -> Result<Vec<Tunnel>> {
        let mut built = Vec::new();
        for (index, spec) in self.document.tunnels.iter().enumerate() {
            let where_ = alloc::format!("tunnels[{index}]");
            let action = spec
                .action
                .as_deref()
                .or_else(|| spec.credential.is_some().then_some("tls"));
            let mut builder = Tunnel::builder(&spec.listen, &spec.target)
                .map_err(|error| self.fail(&where_, error))?;
            if action.is_some() || spec.upstream.is_some() {
                builder = builder.route(self.route_of(
                    &where_,
                    action,
                    spec.credential.as_deref(),
                    spec.upstream.as_deref(),
                    None,
                    credentials,
                )?);
            }
            if let Some(name) = &spec.name {
                builder = builder.name(name.clone());
            }
            built.push(builder.build());
        }
        Ok(built)
    }

    fn settings(&self) -> Result<ServerSettings> {
        let mut settings = self.document.server.clone();
        for slot in [&mut settings.keylog, &mut settings.record] {
            if let Some(path) = slot.take() {
                *slot = Some(self.path(&path));
            }
        }
        for slot in [&mut settings.ca.certificate, &mut settings.ca.key] {
            if let Some(path) = slot.take() {
                *slot = Some(self.path(&path));
            }
        }
        if settings.ca.is_configured()
            && (settings.ca.certificate.is_none() || settings.ca.key.is_none())
        {
            return Err(self.fail("server.ca", "certificate and key are both needed"));
        }
        settings
            .validate()
            .map_err(|error| ConfigError::new(error.to_string()).at_path(self.label.clone()))?;
        Ok(settings)
    }
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(one) => alloc::vec![one],
            Self::Many(many) => many,
        }
    }
}

fn env_password(name: &str) -> KeyPassword {
    let name = name.to_owned();
    KeyPassword::callback(move || {
        std::env::var(&name)
            .ok()
            .filter(|value| !value.is_empty())
            .map(Secret::new)
    })
}

fn env_pin(name: &str) -> Pin {
    let name = name.to_owned();
    Pin::callback(move |_| match std::env::var(&name) {
        Ok(value) if !value.is_empty() => PinAnswer::Secret(Secret::new(value)),
        _ => PinAnswer::Decline,
    })
}

/// The router a document's rules and default describe.
///
/// # Errors
///
/// [`Error::Config`] naming the table and key at fault.
pub fn build_router(document: &Document, base_dir: Option<&Path>) -> Result<Router> {
    let builder = Builder {
        document,
        base: base_dir.map_or_else(|| PathBuf::from("."), Path::to_path_buf),
        label: BuildOptions::default().label,
    };
    builder.router(&builder.credentials()?)
}

/// A server builder for `document`: its settings, router and tunnels. Nothing is bound until
/// [`ServerBuilder::start`].
///
/// # Errors
///
/// [`Error::Config`] naming the table and key at fault.
pub fn build_server(document: &Document, options: BuildOptions) -> Result<ServerBuilder> {
    let parts = build_parts(document, options)?;
    Ok(Server::builder(parts.router)
        .settings(parts.settings)
        .tunnels(parts.tunnels))
}

/// What a document describes, before a server exists: for building one, or for reloading a
/// running one.
#[derive(Debug)]
#[non_exhaustive]
pub struct Parts {
    /// The server's settings, paths resolved.
    pub settings: ServerSettings,
    /// The routing rules.
    pub router: Router,
    /// The tunnel listeners.
    pub tunnels: Vec<Tunnel>,
}

/// The settings, router and tunnels of `document`.
///
/// # Errors
///
/// [`Error::Config`] naming the table and key at fault.
pub fn build_parts(document: &Document, options: BuildOptions) -> Result<Parts> {
    let builder = Builder {
        document,
        base: options.base_dir.unwrap_or_else(|| PathBuf::from(".")),
        label: options.label,
    };
    let credentials = builder.credentials()?;
    let router = builder.router(&credentials)?;
    let tunnels = builder.tunnels(&credentials)?;
    let settings = builder.settings()?;
    Ok(Parts {
        settings,
        router,
        tunnels,
    })
}

/// [`load`] then [`build_server`], paths relative to the file.
///
/// # Errors
///
/// As [`load`] and [`build_server`].
pub fn load_server(path: impl AsRef<Path>) -> Result<ServerBuilder> {
    let path = path.as_ref();
    let document = load(path, LoadOptions::default())?;
    build_server(
        &document,
        BuildOptions {
            base_dir: path.parent().map(Path::to_path_buf),
            label: path.display().to_string(),
        },
    )
}

/// What the router's credentials have loosened from the strict defaults.
pub fn router_non_defaults(router: &Router) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let routes = router
        .rules()
        .iter()
        .map(Rule::route)
        .chain(core::iter::once(router.default_route()));
    for route in routes {
        if let Some(TlsSource::Credential(credential)) = route.tls() {
            for entry in credential.non_defaults() {
                if !found.contains(&entry) {
                    found.push(entry);
                }
            }
        }
    }
    found
}

/// Which connection `target` (a URL, or `HOST:PORT` for a `CONNECT` destination) is, as the HTTP
/// proxy listener sees it, for `caguax check`.
///
/// # Errors
///
/// [`Error::Config`] for text that is neither.
pub fn connection_for_target(target: &str, listener: &str) -> Result<Connection> {
    use crate::connection::Scheme;
    if let Some((scheme, rest)) = target.split_once("://") {
        let scheme: Scheme = scheme.parse()?;
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
        let port = port.unwrap_or(if scheme == Scheme::Http { 80 } else { 443 });
        return Connection::builder(host, port)
            .scheme(scheme)
            .path(path)
            .listener(listener)
            .build();
    }
    let (host, port) = crate::rules::split_host_port(target)?;
    Connection::builder(host, port.unwrap_or(443))
        .listener(listener)
        .build()
}
