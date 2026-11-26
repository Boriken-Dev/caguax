# caguax

[![Version](https://img.shields.io/crates/v/caguax.svg)](https://crates.io/crates/caguax)
[![Rust version](https://img.shields.io/crates/msrv/caguax.svg)](https://crates.io/crates/caguax)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Boriken-Dev/caguax/blob/main/LICENSE)
[![Docs](https://img.shields.io/docsrs/caguax)](https://docs.rs/caguax)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/caguax/test.yaml)](https://github.com/Boriken-Dev/caguax/actions/workflows/test.yaml)

**A local proxy that routes each request the way you say.** Rules decide, per request, whether it
goes direct, through the system's proxy or a named upstream, with the proxy owning the TLS (a
client certificate from a keystore, or interception), or is rejected. The library embeds the
server; the `caguax` command runs it from a configuration file. See the
[API header](https://github.com/Boriken-Dev/caguax/blob/main/AGENTS.md) for every item.

## Features

- HTTP proxy listener: `CONNECT`, forwarded requests with keep-alive, WebSocket upgrades and
  `/proxy.pac`; tunnel listeners that give a plain TCP client mutual TLS to a fixed target.
- Rules on host (glob, regex, `.domain`), network, port, scheme, path and listener, combined with
  `&`, `|` and `!`; the first match decides.
- Upstreams: the system's settings, the proxy variables, a PAC file, a proxy URL or a PAC result
  (HTTP, HTTPS and SOCKS proxies, Negotiate with the `negotiate` feature), failing over across
  answers.
- Client certificates from the operating system's keystores (Windows CNG, macOS Keychain, PKCS#11)
  or PEM and PKCS#12 files; PINs and passwords only from the environment, a file or the keystore.
- TLS interception from a name-constrained CA the proxy makes for the hosts its rules intercept.
- Recording of every relayed session to the log or to a pcap capture; a key log for Wireshark.
- Configuration in TOML, JSON, YAML or INI, read again on `SIGHUP`.
- Every bound, timeout, count and size is a setting with a default.

## Installation

```sh
cargo add --git https://github.com/Boriken-Dev/caguax caguax
```

| Feature | Adds | Default |
| --- | --- | --- |
| `cli` | the `caguax` command (`clap`, `tracing-subscriber`, `rpassword`) | yes |
| `regex` | `Matcher::HostRegex`, `Matcher::Path` and the `re:` rule spelling | yes |
| `pcap` | `record::PcapRecorder` and `record = "file.pcap"` | no |
| `yaml` | YAML configuration files | no |
| `ini` | INI configuration files | no |
| `pkcs11` | PKCS#11 credentials and `caguax cert --backend pkcs11` | no |
| `negotiate` | Negotiate and NTLM login to upstream proxies | no |

A library user turns the default features off: `default-features = false, features = ["regex"]`.

## Quick start

A proxy on a free loopback port that sends everything direct except one blocked domain:

```rust
use caguax::{Route, Router, Rule, Server};

# #[tokio::main]
# async fn main() -> Result<(), caguax::Error> {
let router = Router::builder()
    .rule(Rule::parse("*.blocked.example", Route::reject())?)
    .build();
let server = Server::builder(router).start().await?;
println!("proxy on http://{}", server.addresses()[0]);
server.shutdown().await;
# Ok(())
# }
```

The listener asks every client for a login (`Proxy-Authorization: Basic`): `caguax run` writes a
generated one, as `user:password`, to `caguax.auth` beside the configuration file (owner-only on
Unix) and prints its path as `login FILE`, so a client is pointed at the proxy with:

```sh
curl -x http://127.0.0.1:3128 -U "$(cat caguax.auth)" https://example.com/
```

`HTTPS_PROXY=http://user:password@127.0.0.1:3128` works the same for tools that read the
variables. Library code gets the login from `Server::proxy_login()`. A refused request is
`407 Proxy Authentication Required` with `Connection: close`, and nothing reaches the destination.

From synchronous code, the same server owns a runtime of its own:

```rust
use caguax::{Router, blocking};

# fn main() -> Result<(), caguax::Error> {
let server = blocking::Server::builder(Router::new()).start()?;
let port = server.port();
server.shutdown();
# assert!(port > 0);
# Ok(())
# }
```

## Command line

```sh
caguax --version
caguax check https://example.com/ --format json
caguax -c caguax.cfg check api.corp.example:443
caguax -c caguax.cfg pac
caguax -c caguax.cfg ca init
caguax -c caguax.cfg ca show
```

| Command | Does |
| --- | --- |
| `caguax run` | serve until Ctrl-C (`SIGHUP` reads the configuration again); prints `proxy http://HOST:PORT` per listener and `tunnel HOST:PORT -> TARGET` per tunnel |
| `caguax check TARGET [--listener NAME] [--format text\|json]` | which rule and route a URL or `HOST:PORT` gets, without connecting |
| `caguax pac [--proxy HOST:PORT]` | the PAC script for the rules |
| `caguax ca init [--force] [--unconstrained]` | create the interception CA at `[server.ca]`'s paths, name-constrained to the TLS rules |
| `caguax ca show` | the CA certificate clients must trust |
| `caguax cert list\|show\|probe` | the client certificates the keystores hold, and a probe of a server with them |

Every command takes `-c/--config FILE` (else `CAGUAX_CONFIG`, else `caguax/caguax.cfg` in the
user's configuration directory; with no file the defaults apply), `-v`, `-q` and
`--loglevel [NAME:]LEVEL[,...]` (the log filter is also `CAGUAX_LOG`). Results go to standard
output, one-line errors to standard error. Exit status: `0` done, `1` failed, `2` the invocation or
the configuration is wrong, `130` interrupted (`caguax run` stops on Ctrl-C with `0`).

## Configuration

`caguax.cfg` is TOML unless its first line names another format (`#!yaml`, `#!json`, `#!ini`).
Unknown tables and keys are errors; relative paths are relative to the file.

```toml
[server]
listen = "127.0.0.1:3128"
# auth = "none"              # no listener login: any local process uses the proxy's credentials
# auth = { user = "me", password_env = "CAGUAX_PROXY_PASSWORD" }   # or password_file = "proxy.pw"
# auth = { file = "/run/user/1000/caguax.auth" }                   # where a generated login goes
egress = "system"            # "system" | "env" | "auto" | "direct" | "pac:<location>" | a proxy URL
connect_timeout = "30s"      # also accepted as `timeout`
idle_timeout = "5m"          # the default; 0 never ends a silent connection
log_traffic = true

[server.ca]
certificate = "pki/ca.pem"
key = "pki/ca.key"
password_env = "CAGUAX_CA_PASSWORD"

[credentials.work]
backend = "system"           # "system" | "cng" | "keychain" | "pkcs11" | "pem"
query = { subject = "alice" }
pin = "keystore"             # or pin_env = "NAME_OF_A_VARIABLE"; a PIN is never in the file

[[rules]]
match = ["*.corp.example", "10.0.0.0/8"]
port = 443
action = "tls"               # "tls" | "direct" | "reject"
credential = "work"
name = "corp"

[[rules]]
match = "*.blocked.example"
action = "reject"

[default]
action = "direct"

[[tunnels]]
listen = "127.0.0.1:15432"
target = "db.corp.example:5432"
credential = "work"
allow_any_local = true       # required with a credential: a tunnel is raw TCP, no login can be asked
```

The listener login protects the HTTP proxy port. A `[[tunnels]]` port is raw TCP, so it cannot ask
for one: a tunnel whose route carries a credential (a client certificate, or a login to an
upstream proxy) is refused when the configuration is loaded unless it says `allow_any_local =
true`, which `caguax run` lists as `non-default tunnels.<name>.allow_any_local = true`. Both
`auth = "none"` and `idle_timeout = 0` are listed the same way (`non-default server.auth = none`).

The settings, with their defaults, are listed in the
[API header](https://github.com/Boriken-Dev/caguax/blob/main/AGENTS.md).

## API overview

| Module | Purpose |
| --- | --- |
| `caguax` | the root re-exports: `Server`, `Router`, `Route`, `Rule`, `Matcher`, `Credential`, `Egress` |
| `caguax::rules`, `route`, `connection` | matchers, routes and the router; what a rule sees |
| `caguax::upstream` | reaching a destination through an `Egress`, with the route's TLS |
| `caguax::credential` | client credentials for mutual TLS |
| `caguax::intercept` | the interceptor, `create_ca`, `permitted_names` |
| `caguax::record` | recorders: `LogRecorder`, `PcapRecorder` |
| `caguax::pac` | PAC script generation |
| `caguax::config` | configuration documents and building a server from one |
| `caguax::server` | the server, tunnels, relaying; `caguax::blocking` for synchronous code |
| `caguax::settings` | `ServerSettings` and its tables |
| `caguax::cli` | the command line (feature `cli`) |

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Real-peer tests are opt-in: `CAGUAX_TEST_CURL=1` and `CAGUAX_TEST_SQUID=1` with
`cargo test --all-features -- --include-ignored`.

### Building without a network, and in a container

The `deps` branch holds every crate `Cargo.lock` names as text, and `tools/sdk.lock` records the toolchains, `rustup` and the
`deps` commit a build is made with. `tools/build.py` (Python 3.11, standard library only; `python3 tools/build.py --help`)
holds them to the repository and builds from them:

```text
python3 tools/build.py sdk check                  # the lock, the Containerfile's pins and the deps commit agree
python3 tools/build.py container build --tag caguax   # the image: sdk, build and test offline, then the runtime
python3 tools/build.py container test             # `cargo test --all-features` offline, in the same container
python3 tools/build.py container build --print    # the overrides and the engine command, nothing run
```

The image holds only the `caguax` command, runs as a fixed non-root user, publishes no port and reads its configuration
from `/etc/caguax/caguax.cfg`: mount a file there read-only, set `listen = "0.0.0.0:3128"` in it, and publish the port you
mean to with `-p`. `packaging/container/Containerfile` has the whole recipe. Where a build gets its toolchain, mirrors, base
images or Visual Studio paths from is set in `.env` or `.env.local` (both ignored by git; `.env.example` lists every key and
`python3 tools/build.py help env` explains them). A pin changes in `tools/sdk.lock` first; `sdk check` fails until the
Containerfile follows. To change `Cargo.lock`, refresh the branch on a clean checkout of main with
`python3 tools/build.py deps refresh` and push `deps` before `main`.

### Releasing

No release is cut yet; the crate is consumed by git revision.

## License

MIT OR Apache-2.0, at your option. See [LICENSE](https://github.com/Boriken-Dev/caguax/blob/main/LICENSE).
