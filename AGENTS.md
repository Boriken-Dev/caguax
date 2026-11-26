# `caguax` — API header

Header-file-style reference for the `caguax` crate: every public item with its signature, contract
and gotchas, so the crate can be used without reading its source. It ships inside the package and
is self-contained. Development documentation lives with the source at
<https://github.com/Boriken-Dev/caguax>.

MSRV Rust 1.89, edition 2024. A default build depends on `tokio`, `hyper` (HTTP/1 server and
client), `hyper-util`, `http-body-util`, `bytes`, `rustls` and `tokio-rustls`, `coqui-proxy`,
`coqui-sslcontext`, `coqui-net-acl`, `anycfg`, `serde`, `serde_json`, `toml`, `thiserror`,
`tracing`, and with the default features `clap`, `tracing-subscriber`, `rpassword` and `regex`.

| Feature | Adds | Default |
| --- | --- | --- |
| `cli` | the `caguax` binary and `caguax::cli` (`clap`, `tracing-subscriber`, `rpassword`) | yes |
| `regex` | `Matcher::HostRegex`, `Matcher::Path`, `rules::RegexMatcher`, the `re:` spelling and the `path` rule key | yes |
| `pcap` | `record::PcapRecorder`, `record::PcapFormat`, `server.record` (`pcap-file`) | no |
| `yaml` | `config::Format::Yaml` (`serde-saphyr`) | no |
| `ini` | `config::Format::Ini` (the reader is this crate's own) | no |
| `pkcs11` | `Backend::Pkcs11` credentials and `caguax cert --backend pkcs11` | no |
| `negotiate` | Negotiate and NTLM login to upstream proxies (`coqui-proxy/negotiate`) | no |

Imports: the root re-exports `Server`, `ServerBuilder`, `Tunnel`, `TunnelBuilder`, `OpenOptions`,
`RelaySession`, `Router`, `RouterBuilder`, `Routing`, `Route`, `RouteBuilder`, `Rule`, `Action`,
`TlsSource`, `UpstreamSpec`, `Explanation`, `Matcher`, `PortSpec`, `CustomMatcher`, `Connection`,
`ConnectionBuilder`, `Scheme`, `LISTENER`, `Credential`, `CredentialBuilder`, `Backend`,
`KeystoreOptions`, `StoreLocation`, `Egress`, `ConnectOptions`, `UpstreamStream`, `Interceptor`,
`CaOptions`, `create_ca`, `permitted_names`, `generate_pac`, `Recorder`, `Session`, `ListenAddr`,
`ServerSettings`, `CaSettings`, `InterceptSettings`, `Error`, `ConfigError`, `UpstreamError`,
`CredentialUnavailableError`, `RejectedError`, `Result`, `VERSION`, and the module `blocking`.
Public modules: `cli` (feature `cli`), `config`, `connection`, `credential`, `error`, `intercept`,
`keylog`, `listen`, `pac`, `record`, `route`, `rules`, `server` (with `blocking`), `settings`,
`upstream`.

No `unsafe` (`#![forbid(unsafe_code)]`), no `static`, no `thread_local!`, no process-wide state. The
library prints nothing and never exits (only `cli` does) and installs no logger; it emits
`tracing` events under the targets `caguax` and `caguax::traffic`. It reads no environment variable:
`config::default_path` reads `CAGUAX_CONFIG`, the command line reads the others, and a credential's
`pin_env` / `password_env` variable is read when the secret is first needed.

## Connections (`caguax::connection`)

```rust
Connection::new(host: &str, port: u16) -> Result<Connection>           // scheme Https
Connection::builder(host, port) -> ConnectionBuilder
ConnectionBuilder::{scheme(Scheme), path(impl Into<String>), client(SocketAddr), listener(impl Into<String>), build() -> Result<Connection>}
Connection::{host, port, scheme, path, client, listener, authority, url}
enum Scheme { Https, Http, Tcp }   // non_exhaustive; as_str, FromStr, Display
const LISTENER: &str = "proxy"     // the listener name of the HTTP proxy
```

`host` is normalised: lower case, no `[]`, no trailing dot. An empty host or port 0 is
`Error::Config`. `authority()` is `host:port` with IPv6 bracketed; `url()` is the key an upstream is
asked: the scheme (`tcp` counts as `https`), the host with the default port left out, then the path
or `/`. `scheme` is `Https` for a `CONNECT`, `Http` or `Https` for a forwarded request, `Tcp` for a
tunnel.

## Rules and routes (`caguax::rules`, `caguax::route`)

```rust
enum Matcher { All, Host(Vec<String>), HostRegex(RegexMatcher), Port(Vec<PortSpec>), Scheme(Vec<Scheme>),
               Network(Vec<IpNet>), Path(RegexMatcher), Listener(Vec<String>), AllOf(Vec<Matcher>),
               AnyOf(Vec<Matcher>), Not(Box<Matcher>), Custom(CustomMatcher) }   // non_exhaustive
Matcher::{host(patterns), host_regex(pattern, case_insensitive), path(pattern), port(ports), scheme(schemes),
          network(nets), listener(names), custom(Fn(&Connection) -> bool)}      // validating constructors
Matcher::matches(&self, &Connection) -> bool
impl BitAnd, BitOr, Not for Matcher     // flatten AllOf / AnyOf; !!m == m
impl FromStr for Matcher
enum PortSpec { Single(u16), Range(RangeInclusive<u16>) }   // From<u16>, From<RangeInclusive<u16>>, contains
RegexMatcher::{pattern, case_insensitive}                    // feature regex
```

Host patterns ignore case; `*` is any run of characters (dots too), `?` one, every other character
(`[` included) literal; a leading `.` matches the domain and its subdomains. `HostRegex` must match
the whole host (case-insensitive by default), `Path` the path from its start. `Network` matches
address literals only; names are never resolved. `FromStr` reads `re:<regex>`, an address or CIDR
network, `*` (`All`), `host[:port]`, `[v6]:port`, and adds `& Port` for a trailing `:port`; empty
text, a bad port or a bad regex is `Error::Config`.

```rust
enum Action { Direct, Tls, Reject }              // non_exhaustive; as_str, FromStr, Display
enum TlsSource { Config(Arc<rustls::ClientConfig>), Credential(Arc<Credential>) }   // From each
type UpstreamSpec = Egress
Route::direct() | Route::reject() | Route::with_tls(impl Into<TlsSource>) -> RouteBuilder
RouteBuilder::{upstream(impl Into<Egress>), name(impl Into<String>), build() -> Route}
Route::{action, tls, upstream, name}              // Default: direct, named "default"
Rule::new(matcher, route) / Rule::parse(pattern: &str, route) -> Result<Rule>; .named(name); {matcher, route, name}
Router::{new(), builder() -> RouterBuilder, add(Rule), add_match(matcher, route), rules(), default_route(),
         route(&Connection) -> &Route, explain(&Connection) -> Explanation { rule: Option<&Rule>, route: &Route }}
RouterBuilder::{rule(Rule), rules(iter), default_route(impl Into<Route>), build()}
trait Routing: Send + Sync { fn route(&self, &Connection) -> Route; fn router(&self) -> Option<&Router> { None } }
```

`Action::Tls` means the proxy owns the TLS to the destination: a forwarded `http://` request is
upgraded to HTTPS, a `CONNECT` is intercepted (the client's TLS ends at the proxy, which needs a
CA). A route's `upstream` overrides the server's egress. `Routing::router` lets the server answer
`/proxy.pac` and report credentials; a router that is not a `Router` has no PAC form.

## Reaching destinations (`caguax::upstream`)

```rust
enum Egress { System, Environment, Auto, Direct, Pac(String), Proxy(String), Resolver(coqui_proxy::Resolver) }   // non_exhaustive
Egress::{resolver() -> Result<Resolver>, spelling() -> Option<String>}; FromStr; From<Resolver>
async fn connect(&Connection, &Route, &ConnectOptions) -> Result<UpstreamStream>
async fn resolve_upstream(&Connection, &Route, Option<&Egress>) -> Result<Vec<Option<Proxy>>>   // None = direct
ConnectOptions::default().{egress(Egress), timeout(Duration), happy_eyeballs_delay(Duration), forward_http(bool),
                           keylog(Arc<dyn rustls::KeyLog>), warm_up().await}
UpstreamStream::{via, tls, forward, proxy_authorization, server, from_io}     // AsyncRead + AsyncWrite
```

`FromStr for Egress` reads `system`, `env`, `auto`, `direct`, `pac:<location>`, anything else a
proxy URL or PAC result (`PROXY a:3128; DIRECT`). `System` is the operating system's settings
whatever the environment says, `Environment` the proxy variables only, `Auto` the variables when
any is set, else the system. `connect` tries each answer in order (a PAC result fails over);
`None` means direct. HTTP, HTTPS and SOCKS proxies are reached through `coqui-proxy`'s
asynchronous connector (Basic from the proxy URL, Negotiate with the `negotiate` feature). With
`forward_http` and an HTTP or HTTPS proxy answer, the stream goes to the proxy itself
(`forward() == true`, absolute-form requests, `proxy_authorization()` set), since proxies often
refuse `CONNECT` to port 80. A TLS route then upgrades the stream with SNI = the connection's host
(a `Credential` is built on a blocking thread). The error lists every attempt and never proxy
credentials. A PAC location is downloaded when the egress is first used (`warm_up`, which
`ServerBuilder::start` calls, finds a mistake early).

## Credentials (`caguax::credential`)

```rust
Credential::identity(Identity) | identity_with(Fn() -> Result<Identity>) | from_pem(cert: impl Into<Vec<u8>>, key: Option<Vec<u8>>, KeyPassword)
          | keystore(Backend) -> CredentialBuilder
CredentialBuilder::{name, verify(bool), cafile(path), capath(path), cadata(bytes), minimum_version(TlsVersion),
                    keystore_options(KeystoreOptions), query(IdentityQuery), build() -> Credential}
Credential::{name, backend, options, query, tls_config(&self, host).await -> Result<Arc<ClientConfig>>, invalidate().await, non_defaults}
enum Backend { System, Cng, Keychain, Pkcs11 }       // FromStr: system|cng|keychain|pkcs11
KeystoreOptions { store, location: StoreLocation, keychain, module, token, slot, pin: Pin }   // non_exhaustive, Default
```

Nothing is read until the first `tls_config`; it builds on a blocking thread and caches the result,
and a failure (`Error::CredentialUnavailable`) is not cached. `from_pem` takes PEM or DER; with no
`key` the certificate bytes hold both (combined PEM) or are a PKCS#12 bundle. `verify(false)`
accepts any server certificate and is listed by `non_defaults()`; `cafile`, `capath` and `cadata`
replace the system roots. `Backend::System` leaves the choice to the system selector; `Cng` opens a
store, `Keychain` the Keychain, `Pkcs11` a module (default: the system's), each on its platform.

## Interception (`caguax::intercept`)

```rust
Interceptor::new(CertificateAuthority, InterceptSettings) -> Result<Interceptor>
Interceptor::{with_keylog, ca, keylog, settings, server_config(host) -> Result<Arc<ServerConfig>>,
              accept(self: &Arc<Self>, host, client, timeout).await, non_defaults}
permitted_names(&Router) -> Option<Vec<String>>
create_ca(&Router, CaOptions) -> Result<CertificateAuthority>
CaOptions { common_name: "caguax local CA", constrain: true, validity: 3650 days }   // non_exhaustive
load_ca(&CaSettings) -> Result<CertificateAuthority>; is_name_constrained(&CertificateAuthority) -> bool
```

A `CONNECT` whose route is `Tls` is intercepted: the proxy connects to the destination first (a
failure is `502` before any TLS), answers `200`, completes the client's handshake with a leaf for
the `CONNECT` host (ALPN `http/1.1` only) and relays the plaintext. Leaves are minted once and
cached, the least recently used going first. `permitted_names` lists the `Host` patterns and
`Network`s that bound the TLS rules, or `None` when a TLS rule or the default is not bounded that
way (a regex, a path, a custom predicate); `create_ca` then refuses unless `constrain` is false.

## Recording (`caguax::record`)

```rust
trait Recorder: Send + Sync { opened(&Session), data(&Session, Sender, &[u8]), ended(&Session, Sender), closed(&Session) }   // each -> Result<(), RecordError>, default Ok
enum Sender { Client, Server }
Session::{id, connection, route, client, server, started}
LogRecorder::{new, with_target(&'static str), with_level(tracing::Level), target, level}   // events under `caguax::traffic`
PcapRecorder::{create(path, PcapFormat) -> Result<Self>, mss(usize), close(self)}          // feature pcap
enum PcapFormat { Pcap, Pcapng }
Recording::{start, session, data, ended, closed}; RecordedStream<S>
```

A recorder sees what crossed the proxy's upstream side: the plaintext of a TLS route and the HTTP
heads as rewritten, the ciphertext of a tunnel it only relayed. Calls come in order per session
and return quickly. A recorder that returns an error is logged and gets nothing more of that
session; traffic is never affected. `PcapRecorder` writes each session as a TCP connection between
the client and `session.server()` (Wireshark: *Decode As* HTTP for a TLS route's plaintext).
Recorded plaintext is as sensitive as the credentials that opened the sessions.

## PAC (`caguax::pac`)

`generate_pac(&Router, proxy: &str, Option<&Egress>) -> String`, also `Router::pac_script`. The
script sends `PROXY <proxy>` for every request the router would not send straight to its
destination; a route is `DIRECT` only if the proxy itself would connect directly (`Direct` route
with upstream `Egress::Direct`, or none and no egress). A rule with no PAC form (a path, an IPv6
network, a custom predicate) sends everything not yet decided to the proxy. The server serves it
at `GET /proxy.pac`.

## Server (`caguax::server`)

```rust
Server::builder(impl Routing + 'static) -> ServerBuilder      // Server::direct() = Router::new()
ServerBuilder::{settings(ServerSettings), listen(iter of ListenAddr), auth(Auth), allow_remote(bool), egress(Egress), ca(CertificateAuthority) -> Result<Self>,
                interceptor(Interceptor), recorder(impl Recorder), tunnel(impl Into<Tunnel>), tunnels(iter), start().await -> Result<Server>}
Server::{addresses, port, tunnels, tunnel_address(&Tunnel), settings, router, interceptor, recorders, non_defaults,
         proxy_login() -> Option<Login>,
         open_upstream(&Connection, &Route, OpenOptions).await, start_recording(..), relay_session(.., RelaySession).await,
         reload(ServerSettings, impl Routing).await, serve().await, shutdown(self).await}
Tunnel::builder(listen: &str, target: &str) -> Result<TunnelBuilder>; TunnelBuilder::{route, name, allow_any_local(bool), build}
Tunnel::{listen, target, target_host_port, route, name, allow_any_local}    // name defaults to "tunnel:<target>"
server::relay(client, upstream, RelayOptions), IdleRead<S>
blocking::Server::builder(router) -> blocking::ServerBuilder::{with(Fn(ServerBuilder) -> ServerBuilder), worker_threads(n), start()}
blocking::Server::{server, addresses, port, tunnel_address, shutdown(self)}
```

The HTTP proxy listener asks for a login first (`ServerSettings::auth`, below): without
`Proxy-Authorization: Basic` for it, every request (`CONNECT`, forwarded and `/proxy.pac`
included) is answered `407` with `Proxy-Authenticate: Basic realm="caguax"` and
`Connection: close`, compared in constant time, and nothing is routed. The client's
`Proxy-Authorization` is never forwarded. A tunnel (raw TCP) cannot be asked: `start` and
`reload` refuse a tunnel whose route carries a credential (a `tls` credential, an upstream proxy
URL with a user, or any proxy answer with feature `negotiate`) unless `allow_any_local(true)`.

The HTTP proxy listener:

- **`CONNECT host:port`** (default port 443): `Direct` routes answer `200` and tunnel bytes;
  `Tls` routes are intercepted (`502` without a CA).
- **Absolute-form requests** (`GET http://host/path`): routed as scheme `http` or `https` with the
  path set. The request goes out in origin form, with `Host` rewritten and hop-by-hop headers (and
  the ones `Connection` lists) dropped, on a connection of its own to the destination; a `Tls`
  route upgrades `http://` to HTTPS with its credential, an `https://` request on a `Direct`
  route is verified by the system roots. Through an upstream HTTP proxy plain HTTP is sent in
  absolute form with the upstream's `Proxy-Authorization`. `Upgrade` (WebSocket) traffic is
  relayed as bytes. Several requests share a client connection (`keep_alive`), each routed on its
  own; 1xx interim responses other than `101` are not passed on.
- **`GET /proxy.pac`** (origin form, to the proxy itself): the PAC script; other local paths `404`.
- Statuses: `407` no valid listener login, `400` malformed request or head over `max_head_bytes`, `403` rejected, `502`
  destination or upstream unreachable or credential unavailable (the body says which, never a
  secret), `504` timeout waiting for the destination's answer.

`start` binds (`Error::Io` when an address is taken); listening beyond loopback is `Error::Config`
unless `allow_remote`. `shutdown` stops listening, cancels every connection and waits for them;
dropping a `Server` stops its tasks without waiting. `reload` builds the new state (egress,
credentials, interceptor, recorders, timeouts) beside the old and swaps; listener addresses and
tunnels do not change, a different `listen` is `Error::Config`, and a state that fails to build
leaves the running one. `blocking::*` must not be called from inside an async task.

## Settings (`caguax::settings`)

`ServerSettings`, `CaSettings` and `InterceptSettings` are `#[non_exhaustive]`: start from
`Default` and assign fields. They are also the `[server]` table of a configuration file (unknown
keys are errors; a duration is seconds or `"500ms"`, `"30s"`, `"2m"`, `"1h"`, `"7d"`).
`ServerSettings::{validate, non_defaults}`; `settings::parse_duration`.

| Field (`[server]` key) | Default |
| --- | --- |
| `listen` | `127.0.0.1:0`; `[]` means no HTTP proxy listener |
| `auth` | required: a login generated at start (user `caguax`, 256-bit password); see below |
| `allow_remote` | false |
| `connect_timeout` (alias `timeout`) | 30 s; also bounds the head read, TLS handshakes and the upstream `CONNECT` reply |
| `idle_timeout` | 5 minutes (`ServerSettings::DEFAULT_IDLE_TIMEOUT`); `0` in a file or `None` in code disables it |
| `close_timeout` | 2 s (waiting for a TLS shutdown to be answered) |
| `listen_backlog` | 128 |
| `max_connections` | 1024; a connection beyond it is closed |
| `max_head_bytes`, `max_headers` | 64 KiB, 100 |
| `egress` | none (direct) |
| `record`, `log_traffic`, `keylog` | none, false, none |
| `ca.certificate`, `ca.key`, `ca.password_env`, `ca.validity` | none, none, none, 3650 days |
| `intercept.leaf_cache_capacity`, `intercept.leaf_validity` | 256, 7 days |
| `relay_buffer` | 64 KiB |
| `keep_alive` | true |
| `happy_eyeballs_delay` | 250 ms |
| `warn_interval`, `accept_error_delay` | 10 s, 100 ms |

`validate` refuses a zero timeout, count or size (those mean nothing). `non_defaults()` lists
`allow_remote`, `auth = none`, `idle_timeout = none` and `keylog`; `Server::non_defaults()` adds a
CA that is not name-constrained, credentials with `verify = false` and each
`tunnels.<name>.allow_any_local = true`.

```rust
enum Auth { Generated { user, file: Option<PathBuf> }, Env { user, name }, File { user, path }, Login(Login), None }  // non_exhaustive; Default = Generated { "caguax", None }
Login::{new(user, password) -> Result<Login>, user, password, userinfo() -> "user:password", header_value() -> "Basic ..."}   // Debug shows the user only
const auth::DEFAULT_USER: &str = "caguax"
```

`[server] auth` is `"none"`, `"generated"` (the default) or a table: `user` (default `caguax`) with
one of `password_env` (variable read when the settings are applied), `password_file` (first line)
or, for a generated password, `file` (where `user:password` is written: replaced whole, mode `0600`
on Unix, missing directories `0700`; the library writes nothing when `file` is unset, and
`caguax run` defaults it to `caguax.auth` beside the configuration file). A reload keeps a
generated login; the password is never logged or put in an error.

## Configuration (`caguax::config`)

```rust
loads(&[u8], LoadOptions) -> Result<Document>;  load(path, LoadOptions) -> Result<Document>
LoadOptions::default().{path(impl Into<String>), format(Format)};  enum Format { Toml, Json, Yaml, Ini }
default_path() -> PathBuf                  // CAGUAX_CONFIG, else <config dir>/caguax/caguax.cfg
build_router(&Document, Option<&Path>) -> Result<Router>
build_parts(&Document, BuildOptions) -> Result<Parts { settings, router, tunnels }>
build_server(&Document, BuildOptions) -> Result<ServerBuilder>;  load_server(path) -> Result<ServerBuilder>
BuildOptions::default().{base_dir(path), label(text)};  connection_for_target(&str, listener) -> Result<Connection>
router_non_defaults(&Router) -> Vec<String>;  const CONFIG_VARIABLE = "CAGUAX_CONFIG"
Document { server, credentials, rules, default, tunnels }  // serde, deny_unknown_fields
```

The format is a `#!<format>` first line (`#!toml`, `#!yaml`, `#!json`, `#!ini`, also
`#!/usr/bin/env yaml`; the line is not part of the document), else `LoadOptions::format`, else the
file name's suffix (`.toml`, `.yaml`/`.yml`, `.json`, `.ini`; `.cfg` and anything else select
none), else TOML. Text is strict UTF-8 and one leading BOM is ignored. Dialects: TOML keeps its
rules (duplicate keys are errors, datetimes become text); JSON takes the last of a repeated key;
YAML is read by `serde-saphyr`. Errors are `ConfigError` with `table.key: problem`, the path and,
when the parser knows it, the line and column (counted from the first line, a `#!` line
included); they never quote a value (a refused key is named). Tables, in TOML:

```toml
[server]                         # ServerSettings, plus nothing else
[credentials.<name>]             # backend = "system|cng|keychain|pkcs11|pem"; options = { store, location, keychain, module, token, slot };
                                 # query = { subject, issuer, thumbprint, label, valid_only }; pin_env | pin = "keystore";
                                 # pem: certificate, key, password_env | password_file; verify, cafile, capath, cadata, minimum_version
[[rules]]                        # match = pattern or list (any of); port = int or list; path = regex; action, credential, upstream, name
[default]                        # action, credential, upstream, name
[[tunnels]]                      # listen, target = "host:port", credential (implies action = "tls"), action, upstream, name, allow_any_local
```

`action` defaults to `direct`; `credential` is required with `tls` and an error with `direct`;
`upstream` is `direct`, `pac:<location>`, a proxy URL or a PAC result. Relative paths resolve
against the file's directory (`~/` is the home directory). In INI a dotted section nests
(`[credentials.work]`, `[server.ca]`), `[rules.<name>]` and `[tunnels.<name>]` are list entries in
file order whose `name` defaults to `<name>` (`[rules]` alone is an error), and values are typed:
`true`/`false`/`yes`/`no`/`on`/`off`, integers, decimals, JSON lists, objects and quoted strings;
anything else is a string. Keys are lower-cased.

## Errors

`Error` (non_exhaustive): `Config(ConfigError)`, `Upstream(UpstreamError)`,
`CredentialUnavailable(CredentialUnavailableError)`, `Rejected(RejectedError)`,
`Proxy(coqui_proxy::Error)`, `Tls(coqui_sslcontext::Error)`, `Timeout(&'static str)`,
`Io(std::io::Error)`. `ConfigError::{path, line, column, message}`;
`UpstreamError::attempts()`; `CredentialUnavailableError::credential()`. A message names what
failed and never quotes a document, key, PIN, password or proxy credential.

## Command line (`caguax`, feature `cli`)

```text
caguax [-c FILE] [-v|-q]... [--loglevel [NAME:]LEVEL[,...]] <command>
  run                                         serve until Ctrl-C (SIGTERM on Unix); SIGHUP (Unix) reads the configuration again
  check TARGET [--listener NAME] [--format text|json] [--json]
  pac [--proxy HOST:PORT]
  ca init [--force] [--unconstrained] | ca show
  cert list [--all] | cert show QUERY | cert probe URL [--cafile FILE] [-k|--insecure] [--ask] [--no-policy] [--timeout 15s]
       each with [-b|--backend system|cng|keychain|pkcs11] [--store MY] [--location current_user|local_machine]
                 [--module PATH] [--token LABEL] [--pin none|ask|keystore] and, for list and probe, [--format text|json] [--json]
```

`run` prints `proxy http://HOST:PORT` per listener, `login FILE` (where a generated listener login
was written: never the password), `tunnel HOST:PORT -> TARGET` per tunnel and
`non-default <setting>` per setting looser than the defaults, then waits; a configuration that
cannot start is exit status 2 (or 1 for an address in use). `check` prints
`destination=URL rule=NAME action=ACTION [credential=NAME] [upstream=TEXT]` (`rule` is the route's
name, `matched` for an unnamed route, `default` when no rule matched) or, with `--format json`, one
object with the keys `destination`, `rule`, `action`, `credential`, `upstream` (null when absent).
`pac` prints the script; without `--proxy` it points at the first `listen` address (port 3128 when
that asks for a free one). `ca init` writes the CA key (owner-only on Unix) and certificate
beside their final names and prints the certificate path; it refuses to overwrite without
`--force`, and exits 2 when the rules cannot bound a name constraint unless `--unconstrained`.
`cert list` prints the identities whose key is usable (valid ones unless `--all`): SHA-1, expiry,
key, `client`/`no-client`, subject, issuer; `show` prints one in full as JSON by SHA-1, SHA-256
or a subject substring (none: exit 1); `probe` connects like a browser and reports the server's
certificate, each certificate request, the candidates and what was sent, and for `https://` the
HEAD status; a failed connection is reported and exits 1. `--ask` and `--pin ask` prompt only on a
terminal. With no configuration file the defaults apply. Results go to standard output, one-line
errors (`caguax: ...`) to standard error. Exit status: `0` done, `1` failed (a closed standard
output included), `2` the invocation or configuration is wrong, `130` interrupted (`run` stops on
Ctrl-C with `0`). `--format json` output is stable.

## Environment variables

| Variable | Read by | Effect |
| --- | --- | --- |
| `CAGUAX_CONFIG` | `config::default_path`, `--config` | the configuration file |
| `CAGUAX_LOG` | `caguax` | the log filter (`info`, `caguax=debug`); `-v`, `-q` and `--loglevel` override it; default `warn` |
| `CAGUAX_PKCS11_MODULE` | `caguax cert --module` | the PKCS#11 module |
| `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (and lowercase), `REQUEST_METHOD` | `Egress::Environment`, `Egress::Auto` | the proxy variables, as `coqui-proxy` reads them |
| `NO_COLOR` | `caguax` | no colour in logs |
| the names a configuration gives to `pin_env` and `password_env` | when the secret is first needed | a PIN, a key or CA password; unset means none |
| `CAGUAX_TEST_CURL`, `CAGUAX_TEST_SQUID` (`CAGUAX_SQUID`) | tests | opt in to the real-peer tests |

## Gotchas

- Loopback destinations bypass every upstream proxy, because `coqui-proxy`'s resolver exempts
  them. To proxy them, give the egress a `coqui_proxy::Resolver` whose bypass rules include
  `<-loopback>` (`Egress::Resolver`).
- A CA name-constrained to an IP address only was refused by curl on Windows (schannel); one
  constrained to a DNS name was accepted. rustls clients accept both.
- `idle_timeout` (5 minutes by default) ends a relayed direction (tunnels, upgrades) and a forwarded exchange that is
  silent that long; it does not close an idle keep-alive client connection (`connect_timeout`
  does).
- Bytes a client sends right after `CONNECT`, before the `200`, are handshake input for an
  intercepted tunnel, not an error.
- A recorder sees the upstream side only: a forwarded request's response head is recorded as the
  destination sent it, not as the proxy rewrote it for the client.
- `Server::reload` does not rebind: listener addresses, `max_connections` accounting of open
  connections and tunnels stay as they were.
- The PAC download for an `Egress::Pac` happens at first use on a blocking thread (and at
  `start`), so an unreachable location is an error before the first connection.
- `blocking::Server` blocks the calling thread on its own runtime; do not call it from an async
  task.
