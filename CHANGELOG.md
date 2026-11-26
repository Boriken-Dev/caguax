# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- The HTTP proxy listener requires `Proxy-Authorization: Basic` by default (`407` otherwise, nothing is
  routed): a login generated when the server starts (written owner-only to `caguax.auth` beside the
  configuration by `caguax run`), or one named by `server.auth` (`password_env`, `password_file`).
  `server.auth = "none"` turns it off and is listed as `non-default`.
- A tunnel whose route carries a credential (a client certificate, an upstream login) is refused at load
  unless it sets `allow_any_local = true`, which is listed as `non-default`.
- `server.idle_timeout` defaults to 5 minutes, so a silent connection cannot hold a slot for ever; `0`
  disables it and is listed as `non-default`.
- The key log and the capture file are created owner-only (`0600`) on Unix, and `ca init` writes the CA
  key through a new randomly named `0600` file renamed into place instead of a fixed `.new` name.
  `server.record` and a CA key with no `password_env` (also reported by `ca init`) are listed as
  `non-default`.
- `/proxy.pac` is answered only when `Host` is an IP literal, `localhost` or a name in the new
  `server.pac_hosts` (listed as `non-default` when set), else `421`.
- A reload logs every `non-default setting` it leaves in force, as the start does.

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
