# netproxy

[![Version](https://img.shields.io/crates/v/netproxy.svg)](https://crates.io/crates/netproxy)
[![Rust version](https://img.shields.io/crates/msrv/netproxy.svg)](https://crates.io/crates/netproxy)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Boriken-Dev/netproxy-rs/blob/main/LICENSE)
[![Docs](https://img.shields.io/docsrs/netproxy)](https://docs.rs/netproxy)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/netproxy-rs/test.yaml)](https://github.com/Boriken-Dev/netproxy-rs/actions/workflows/test.yaml)

**A local proxy that routes each request the way you say.** A local proxy server that routes each request by rules, through the system's proxy, an upstream proxy or directly, and the netproxy command line.

## Features

- Under construction.

## Installation

```sh
cargo add --git https://github.com/Boriken-Dev/netproxy-rs netproxy
```

| Feature | Adds | Default |
| --- | --- | --- |

## Quick start

Under construction.

## Command line

The `netproxy` command (feature `cli`).

## API overview

See [AGENTS.md](https://github.com/Boriken-Dev/netproxy-rs/blob/main/AGENTS.md).

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

### Releasing

No release is cut yet; the crate is consumed by git revision.

## License

MIT OR Apache-2.0, at your option. See [LICENSE](https://github.com/Boriken-Dev/netproxy-rs/blob/main/LICENSE).
