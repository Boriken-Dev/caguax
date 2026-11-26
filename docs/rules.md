# Credential rules and proxy rules

Three kinds of table decide what caguax does with a destination. They share one pattern grammar,
the one `[[rules]]` already uses, so a pattern written once means the same everywhere.

| Table | Decides | First match wins | Matches on |
| --- | --- | --- | --- |
| `[[rules]]` | direct, TLS owned by the proxy, or reject | yes | host, `port`, `path` |
| `[[credential_rule]]` | which credential goes to a host | yes, per kind | host only |
| `[[proxy_rule]]` | which proxy serves a destination | yes | host, `port`, `path` |

## Patterns

`match` is one pattern or a list (any of them). Matching ignores case.

| Pattern | Matches |
| --- | --- |
| `api.corp.example` | that host |
| `*.corp.example` | any host ending `.corp.example` (`*` is any run of characters, dots included) |
| `.corp.example` | `corp.example` and every subdomain |
| `10.0.0.0/8`, `192.0.2.7` | address literals in that network (names are never resolved) |
| `re:^db[0-9]+\.corp\.example$` | a regular expression over the whole host (feature `regex`) |
| `*` | every host |

`[[rules]]` and `[[proxy_rule]]` also take `port` (a number or a list) and `path` (a regular
expression over the request path of a forwarded `http://` request). A `[[credential_rule]]` takes
neither, and a pattern that carries a port (`host:8443`) is refused: a client certificate request
names a host, not a port or a path.

## `[[credential_rule]]`: which credential goes where

```toml
[credentials.work]
backend = "system"
query = { subject = "alice" }

[credentials.lab]
backend = "pem"
certificate = "lab.pem"
key = "lab.key"
password_env = "LAB_KEY_PASSWORD"

[[rules]]
match = ["*.corp.example", "*.lab.example"]
action = "tls"
credential = "work"

# No certificate to the partner and public-facing hosts, even though the route above names one.
[[credential_rule]]
match = ["*.partner.example", "www.corp.example", "*.cdn.corp.example", "10.99.0.0/16"]
use = "none"
name = "keep-out"

# The lab hosts take the lab credential, not the one the route names.
[[credential_rule]]
match = [".lab.example", "build1.corp.example", "build2.corp.example", "build3.corp.example"]
use = { pin = "lab" }

# Anywhere else under corp.example, the first identity the keystore finds.
[[credential_rule]]
match = "*.corp.example"
use = "first"

# The gateways are logged in to with the logon session's Kerberos or NTLM identity ...
[[credential_rule]]
match = "gw*.corp.example"
for = "proxy_login"
use = "default"

# ... and the DMZ proxy gets no login at all.
[[credential_rule]]
match = "*.dmz.example"
for = "proxy_login"
use = "none"
```

`use` is one of:

| `use` | Client certificate | Proxy login |
| --- | --- | --- |
| `"none"` | send no certificate (no keystore is opened, no PIN is asked) | no Negotiate or NTLM login |
| `"default"` | the route's credential as configured | the system's default credentials |
| `"first"` | the first identity a keystore query finds; listed as `non-default` | refused |
| `{ pin = "<credential>" }` | that credential, whatever the route names | refused |

`for` is `"client_certificate"`, `"proxy_login"` or a list of them. Left out, a rule covers client
certificates when `use` is `first` or `pin`, and both kinds when it is `none` or `default`.

How each kind is decided:

- **Client certificate.** Matched against the destination's host when caguax opens the TLS
  connection of a `tls` route. The first `[[credential_rule]]` that covers client certificates and
  matches wins. With no matching rule the route's own credential is used as configured, and a
  route with no credential sends none. A keystore query never sends a certificate it was not told to
  send.
- **Proxy login.** Matched against the upstream proxy's host (not the destination). With no matching
  rule the answer is `default`: with feature `negotiate`, a proxy that asks for Negotiate or NTLM is
  answered with the system's credentials. Without the feature there is no such login.
- caguax performs no login to origin servers, so there is no origin kind.

A tunnel (`[[tunnels]]`, raw TCP) cannot ask its clients for a login, so one whose route would send
a credential needs `allow_any_local = true`. A `none` rule for the tunnel's target withholds the
credential, and the tunnel then needs no opt-in.

## `[[proxy_rule]]`: which proxy serves which destination

```toml
[server]
egress = "system"            # what applies when no rule below does

# Internal names never leave through a proxy.
[[proxy_rule]]
match = [".corp.example", ".lab.example", "10.0.0.0/8", "172.16.0.0/12", "*.internal"]
use = "none"

# These two SaaS hosts go through the cloud proxy.
[[proxy_rule]]
match = ["*.saas1.example", "*.saas2.example", "api.partner.example"]
port = 443
use = { proxy = "http://cloud-proxy.example:3128" }

# Everything else under example takes the operating system's proxy settings or PAC.
[[proxy_rule]]
match = ".example"
use = "system"
```

| `use` | Means |
| --- | --- |
| `"system"` | the operating system's proxy settings or PAC |
| `"none"` | direct, no proxy |
| `{ proxy = "<URL>" }` | that proxy (`http://`, `https://`, `socks5://`; a login in the URL is Basic) |

Order of precedence for the proxy of one destination:

1. the `upstream` of the `[[rules]]` entry (or `[default]`) that routes it, when it has one;
2. the first matching `[[proxy_rule]]`;
3. `server.egress`;
4. direct.

So an explicit `upstream` on a route always wins, and `[[proxy_rule]]` is the place for the many
hosts that share a decision without a route of their own. `/proxy.pac` and `caguax pac` are built
from `[[rules]]` and `server.egress` and do not include `[[proxy_rule]]`.

## Reloading and `non-default`

Both rule lists are part of the configuration a reload swaps. `caguax run` lists a rule that may
send any certificate a keystore holds as `non-default credential_rule.<name or index>.use = first`.
Every refusal names its table and index (`credential_rule[2]: pin names no credential: lab`) and
stops the configuration from loading.
