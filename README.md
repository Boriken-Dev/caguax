# caguax

[![Version](https://img.shields.io/crates/v/caguax.svg)](https://crates.io/crates/caguax)
[![Rust version](https://img.shields.io/crates/msrv/caguax.svg)](https://crates.io/crates/caguax)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Boriken-Dev/caguax/blob/main/LICENSE)
[![Docs](https://img.shields.io/docsrs/caguax)](https://docs.rs/caguax)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/caguax/test.yaml)](https://github.com/Boriken-Dev/caguax/actions/workflows/test.yaml)

**A local proxy that routes each request the way you say.** A local proxy server that routes each request by rules, through the system's proxy, an upstream proxy or directly, and the caguax command line.

## Features

- Under construction.

## Installation

```sh
cargo add --git https://github.com/Boriken-Dev/caguax caguax
```

| Feature | Adds | Default |
| --- | --- | --- |

## Quick start

Under construction.

## Command line

The `caguax` command (feature `cli`).

## API overview

See [AGENTS.md](https://github.com/Boriken-Dev/caguax/blob/main/AGENTS.md).

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

### Releasing

No release is cut yet; the crate is consumed by git revision.

## License

MIT OR Apache-2.0, at your option. See [LICENSE](https://github.com/Boriken-Dev/caguax/blob/main/LICENSE).
