# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The `caguax` library and command: a local proxy server in which rules decide, per request,
  whether it goes direct, through the system's proxy, a proxy URL, a PAC file or the proxy
  variables, with the proxy owning the TLS (client certificates from keystores or PEM and
  PKCS#12 files, interception from a name-constrained CA), or is rejected.
- `CONNECT`, forwarded requests with keep-alive, WebSocket upgrades, `/proxy.pac`, and tunnel
  listeners that give a plain TCP client mutual TLS to a fixed target.
- Configuration in TOML, JSON, YAML and INI, strict keys, positioned errors that never quote the
  document; every bound is a `ServerSettings` field with a default; live reload on `SIGHUP`.
- Recorders: `LogRecorder` and, with `pcap`, `PcapRecorder`; a TLS key log for Wireshark.
- `caguax run`, `check`, `pac`, `ca init`, `ca show`, `cert list`, `cert show` and `cert probe`.
- `tools/sdk.lock` and the `deps` branch's pin in it; `packaging/container/Containerfile` builds the `caguax` image (a
  non-root user, no published port, configuration mounted at `/etc/caguax/caguax.cfg`) and runs the tests from the `deps`
  branch with no network, through `python3 tools/build.py container build|test`; `.env.example` lists the overrides.
