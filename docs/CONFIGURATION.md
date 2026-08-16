# Server configuration reference

## Client HTTPS proxy settings

The `ntwire` client uses `HTTPS_PROXY`/`HTTP_PROXY` and `NO_PROXY` by default
for HTTPS control traffic. Set `https_proxy: http://proxy.example:8080` in
`~/.ntwire/config.yaml`, or pass `--https-proxy URL`, to use one explicit
HTTP(S) proxy instead. Set `no_system_proxy: true` or pass
`--no-system-proxy` to connect directly and ignore those environment
variables. An explicit `https_proxy` takes precedence over `no_system_proxy`.

Run `ntwire-server --config path/to/ntwire.yaml`; the default path is
`ntwire.yaml`. Use `ntwire-server --print-sample-config > ntwire.yaml` to
write a complete, extensively commented template for every available option.
At least one of `auth.authorized_keys_dir` or `auth.oidc.issuers` is required.

Before releasing a configuration or protocol-affecting change, run the
repository release gate and retain its result with the deployment record; it
verifies that legacy-compatible configuration and transport paths still build
and pass their Docker smoke test. See [RELEASE.md](RELEASE.md).

See [../README.md](../README.md) for a minimal working example. The
following is the complete currently parsed configuration:

```yaml
listen:
  https: ":8443"                        # TLS control API (auth, renew, disconnect) and WebSocket fallback
  wireguard: ":51820"                   # UDP listener for the userspace WireGuard data plane; default shown
  metrics: "127.0.0.1:9090"              # optional plaintext metrics and token-protected dashboard listener; empty disables it
  name: ""                              # friendly label shown in the client's local status UI and logs, to tell apart several ntwire clients running locally; empty falls back to the host:port the client connected to
tls:
  cert_file: ""                         # PEM certificate; empty generates an in-memory self-signed cert (see SECURITY.md)
  key_file: ""                          # PEM private key; required together with cert_file
  state_dir: ""                         # directory for a generated self-signed certificate and key; empty uses this YAML file's directory
  ephemeral: false                       # generate a new in-memory self-signed certificate on every start instead of persisting it in state_dir
auth:
  authorized_keys_dir: /etc/ntwire/keys  # one public key per file; optional if oidc.issuers is set
  oidc:
    issuers:
      - name: google                    # stable id; shown to clients and selected with --provider
        issuer: https://accounts.google.com  # OIDC issuer URL; its /.well-known/openid-configuration and JWKS are fetched
        client_id: 1234-abc.apps.googleusercontent.com  # public OAuth client id registered at the issuer (PKCE; most IdPs need no client_secret)
        scopes: [openid, email, profile] # requested OAuth scopes; default shown
        groups_claim: ""                 # ID-token claim holding group membership, e.g. "groups"; empty disables group: grants
        require_verified_email: true     # reject tokens without email_verified=true; default true, see SECURITY.md
  session_ttl: 15m                       # bearer-token session lifetime before renewal is required; default: 15m
  max_sessions_per_key: 5                # concurrent-session cap per identity (ssh fingerprint or oidc email); 0 = unlimited
admin:
  web_ui_token: ""                       # optional secret: enables the server dashboard on listen.metrics at http://server:9090/?token=...; leave empty to disable it
network:
  tunnel_cidr: 100.64.0.0/16             # private IPv4 range or an IPv6 prefix peer addresses are allocated from (pick one; a deployment is single-family); default shown; for IPv6 use /64 or no shorter than /112
  advertised_endpoint: ""                # host:port returned to clients as udp_endpoint, for when it differs from listen.wireguard (e.g. NAT/port-forward); host may be a hostname, resolved fresh on every client connect/renew
authorizer:
  webhook_url: ""                        # POST request JSON to this URL for a per-connection allow/deny decision; takes precedence when both hook options are set
  exec: ""                               # path to an executable that reads the same JSON on stdin and returns a decision when webhook_url is empty
  timeout: 5s                            # deadline for the webhook call or executable run; a timeout denies the request; default: 5s
tunnels:
  - name: reports                       # unique identifier; shown to clients in grant listings
    target: reports.internal:8080       # host:port the server proxies to over the ordinary network, once a client's WireGuard traffic reaches it
    description: Reporting service      # free-text, shown to clients; optional
    virtual_port: 18080                 # port the server listens on inside the WireGuard tunnel for this target; required, 1-65535
    local_port: 58080                   # loopback port ntwire connect prefers for this tunnel's local listener; optional, falls back to any free port if occupied
    local_host: ""                      # loopback address ntwire connect prefers for this tunnel's local listener, e.g. "127.70.0.1"; optional, must be 127.0.0.0/8 or ::1, falls back to 127.0.0.1 if it can't be bound -- see "Tunnel local address and port" below
    docs_url: https://wiki/reports      # absolute http(s) link offered as "See more" in the client status UI; optional
    instructions: |                     # Markdown setup guidance shown in the client status UI; optional, see "Tunnel instructions" below
      Fetch the latest report:

      ```sh
      curl -sS http://{{.LocalHost}}:{{.LocalPort}}/reports/latest
      ```
    allow:
      - "*"                             # any authenticated identity, either method
      - "SHA256:..."                    # ssh: key fingerprint (preferred; see grant-matching note below)
      - "alice@laptop"                  # ssh: authorized_keys comment (the bundled client never sends one; see note below)
      - "alice@corp.com"                # oidc: exact verified email
      - "@corp.com"                     # oidc: email domain
      - "group:engineering"             # oidc: groups_claim membership
  - name: egress                        # a tunnel can instead be an embedded SOCKS4/5 proxy; see "SOCKS proxy tunnels" below
    target: socks                       # sentinel value that selects the SOCKS target type instead of a fixed host:port
    virtual_port: 11080
    allow: ["group:engineering"]
    socks:
      only_local: false                 # true restricts to private ranges only and ignores every other socks.* filter
      filters: []                       # destination CIDR allow-list, e.g. ["10.0.0.0/8", "fc00::/7"]
      domain_filters: []                # destination hostname-suffix allow-list, e.g. [".svc.cluster.local"]
      asn_filters: []                   # destination ASN allow-list (IPv4 only), e.g. [15169]
      reverse_filters: false            # invert the above from an allow-list into a deny-list
      dns_timeout: 10s                  # timeout for resolving SOCKS5 domain requests
      allow_all: false                  # required to permit every destination when no filters above are set
      allow_bind: false                 # explicitly allow SOCKS4/5 BIND (opens a temporary inbound server listener)
log:
  format: text                          # text or json (Logstash-format); container images default to json
  level: info                           # debug, info, warn, or error
audit:
  log_file: ""                          # optional path for a dedicated JSON-lines audit log; events also still go to the main log
```

See [LOGGING.md](LOGGING.md) for the full `log:` reference, including the
`-log-format`/`-log-level` flags and env vars, and their precedence.

`audit.log_file`, when set, additionally writes every `audit` event
(`auth_allowed`, `authentication_failed`, `session_renewed`, `session_disconnected`, `session_expired`,
`session_revoked`, `authorization_denied`, `authorization_revoked`,
`tunnel_grant_revoked`, `authorization_hook_denied`)
as a Logstash-format JSON line to that file, regardless of `log.format`. This
is additive: audit events keep appearing in the main log too, so existing
log-based monitoring is unaffected. The file is opened append-only with mode
`0600` and is not rotated by ntwire-server; pair it with `logrotate` or an
equivalent if it needs to be bounded.

Every readable non-directory file in `authorized_keys_dir` is treated as a
public key. Tunnel names must be unique and each tunnel requires `name` and
`target`. ntwire-server never authenticates itself to an IdP. A
`client_secret` is not supported in server configuration and is never exposed
by `/v1/info`; if a provider requires it for a public client, configure it in
that client's `NTWIRE_OIDC_CLIENT_SECRET` environment variable. See the
Google/Entra/Keycloak registration notes in [OIDC-SETUP.md](OIDC-SETUP.md).

## SOCKS proxy tunnels

Setting a tunnel's `target: socks` turns it into an embedded SOCKS4/SOCKS5
CONNECT proxy instead of a fixed-destination forward: once a client's traffic
reaches the tunnel's `virtual_port`, the server speaks the SOCKS protocol on
that connection and dials whatever destination the client's SOCKS request
names, gated by the tunnel's `socks:` block. This re-implements the
filter/feature set of [socksd](https://github.com/nmaguiar/socksd) natively
(socksd is a JVM/OpenAF stack, not a Go library, so nothing is vendored) —
same CIDR/domain/ASN/only-local/reverse filter semantics, but see the default
below, which intentionally differs. Session auth, grant matching (`allow:`),
the `authorizer:` webhook/exec hook, per-source rate limiting, and
`audit.log_file` all still apply exactly as they do to a fixed-target tunnel;
`socks:` only adds a second, per-destination filtering layer inside it.

A SOCKS tunnel is a general-purpose egress proxy: whatever it's allowed to
reach, every session holding its grant can reach. **Unlike socksd, which
defaults to allowing every destination when no filters are configured, an
ntwire SOCKS tunnel with no `socks.filters`/`domain_filters`/`asn_filters`/
`only_local`/`reverse_filters` denies every destination** — set
`allow_all: true` to opt into socksd's original behavior. A tunnel that would
otherwise silently deny everything logs a warning at startup.

`socks.filters` (CIDR) and `socks.asn_filters` gate the *resolved* destination
IP; `socks.domain_filters` gates the hostname the client asked to connect to
(SOCKS5 domain requests only — SOCKS4 and SOCKS5 IP-literal requests have no
hostname to match). When both a CIDR/ASN filter and a domain filter are
configured, a CIDR/ASN miss denies immediately without consulting the domain
filter, but a CIDR/ASN hit does not by itself allow the connection: the
domain filter is still checked and is decisive. `socks.only_local` (a
hardcoded private-range allow-list: `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `fc00::/7`) overrides every other `socks.*` filter when
set. `socks.reverse_filters` inverts the whole result, turning the configured
filters from an allow-list into a deny-list.

`socks.asn_filters` and periodic ASN index refresh require the server itself
to reach the internet (default index: `https://openaf.io/asnidx.json.gz`,
overridable with `socks.asn_url`); the index is IPv4-only, so ASN filters
never match an IPv6 destination. Both the CONNECT and BIND commands are
proxied (SOCKS4 and SOCKS5), with the same destination filtering applied to
a BIND request's target address as to a CONNECT one. BIND opens a real,
unfiltered-by-NAT listener on the server host and is a best-effort
implementation with no NAT traversal, matching upstream: it exists for
legacy protocols like active-mode FTP and is rarely needed otherwise. UDP
ASSOCIATE is recognized by the handshake but refused — it needs UDP to
traverse the ntwire tunnel, which the client and `wgnet` don't yet support.

SOCKS BIND is separately disabled by default even when CONNECT and
`allow_all` are enabled. Set `socks.allow_bind: true` only for a tunnel that
needs legacy active-mode behavior: BIND opens a temporary host-network
listener, so the peer is not limited to the WireGuard tunnel.

## Tunnel local address and port

`local_port` and `local_host` are preferences for the loopback listener
`ntwire connect` opens for a tunnel, not guarantees: ntwire is entirely
user-space, so it can only ask the OS for an address, never reserve one in
advance. Both fall back independently when the preferred value can't be
used:

- `local_port` (optional, `0`-`65535`, default any free port): if occupied,
  the client falls back to an ephemeral port on the same host.
- `local_host` (optional, must be `127.0.0.0/8` or `::1`, default
  `127.0.0.1`): if it can't be bound, the client falls back to `127.0.0.1`.
  A value outside `127.0.0.0/8`/`::1` fails config validation at the server
  and is additionally ignored by the client if it somehow arrives anyway —
  a server operator cannot use `local_host` to move a client's listener
  onto a LAN-reachable interface; only the client's own `--bind` can do
  that (see [SECURITY.md](SECURITY.md)).

`local_host` exists so distinct tunnels can share a memorable port instead
of colliding on `127.0.0.1`, e.g.:

```yaml
tunnels:
  - name: primary-db
    local_port: 5432
    local_host: 127.70.0.1
  - name: replica-db
    local_port: 5432
    local_host: 127.71.0.1
```

**Linux** binds every address in `127.0.0.0/8` by default, so this works with
no extra setup. **macOS** assigns only `127.0.0.1` to the loopback interface
(`lo0`); any other address in `127.0.0.0/8` needs an alias added first, or
the client silently falls back to `127.0.0.1` (logging a warning that names
the requested and actual address):

```sh
sudo ifconfig lo0 alias 127.70.0.1 up
sudo ifconfig lo0 alias 127.71.0.1 up
```

The alias does not survive a reboot; add it to a login script or
`launchd` job if it needs to persist.

A user can always override either value from the client side: `--port
name=local-port` or `--port name=host:local-port` (repeatable; IPv6 as
`name=[::1]:local-port`) on `ntwire connect`, a same-shaped `hosts:`/`ports:`
pair in `~/.ntwire/config.yaml`, or `ntwire port name=host:local-port`
against a running connection. An explicit client override is itself a soft
preference for the host (it still falls back to `127.0.0.1` if unbindable)
but a strict requirement for the port (an occupied explicit port fails the
command rather than silently moving to another one) — `--bind` remains the
one setting that is strict for the host too, since choosing it is a
deliberate decision to expose tunnels beyond loopback.

## Tunnel instructions

`instructions` is optional Markdown that `ntwire connect` shows under each
tunnel in its local status UI, so users are told how to point their tools at a
tunnel instead of having to work it out from a port number. `docs_url` adds a
"See more" link beside it, and must be an absolute `http(s)` URL — the server
refuses to start otherwise.

The text is expanded as a [Go template](https://pkg.go.dev/text/template) **on
the client**, because only the client knows which loopback address it
actually bound: the server's `local_port`/`local_host` are preferences (see
"Tunnel local address and port" above), an unusable one falls back to
another, and the user can change either at runtime from the status UI. These
fields are available:

| Field | Value |
| --- | --- |
| `{{.Name}}` | tunnel name |
| `{{.Description}}` | the `description` above |
| `{{.LocalAddress}}` | bound loopback address, e.g. `127.0.0.1:58080` |
| `{{.LocalHost}}` | host part of `LocalAddress` |
| `{{.LocalPort}}` | bound loopback port |
| `{{.VirtualPort}}` | the `virtual_port` above |
| `{{.TargetHint}}` | the `target` above |
| `{{.TunnelIP}}` | the client's address inside the tunnel |
| `{{.ServerTunnelIP}}` | the server's address inside the tunnel |
| `{{.Server}}` | control-plane URL the client is connected to |

Supported Markdown is headings, paragraphs, bullet and numbered lists, fenced
code blocks, inline code, emphasis, and `http(s)` links. Fenced code blocks get
a copy-to-clipboard button, which is the point of templating the port into
them. Anything outside that subset is shown verbatim rather than interpreted,
as is the raw text of a template that fails to parse or execute — a typo in
`instructions` degrades to unrendered text rather than an empty card.

Instructions never become markup: the client parses them into a block tree and
the status UI builds DOM nodes from it, and links whose target is not an
absolute `http(s)` URL stay literal text.

### Loading instructions from a file

A single-line `instructions` value (no `\n`) that names an existing, readable
file is read at config-load time and its content used in place of the
literal string, resolved the same way as `auth.authorized_keys_dir` (relative
to the current working directory `ntwire-server` was started from, or
absolute). This is a convenience for longer instructions, so they can live in
their own Markdown file instead of an inline YAML block scalar:

```yaml
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    instructions: examples/instructions/socks-client.md
```

A multi-line value is always used as literal Markdown, since a real file path
cannot contain a newline — the short inline form keeps working unchanged. A
single-line value that does not name a real file (the common case: a short
sentence like `See the team wiki.`) is likewise kept as literal text, and a
file larger than 64KiB is skipped the same way, as a guard against
accidentally naming the wrong file. Editing the instructions file takes
effect on the next config reload, which requires touching the YAML file
itself — [hot reload](#hot-reload) only watches the config file (and
`authorized_keys_dir`), not files named by `instructions`.

[`examples/instructions/`](../examples/instructions/) has ready-to-adapt
files, all using the template fields above:

| File | For a tunnel that... |
| --- | --- |
| [`ssh.md`](../examples/instructions/ssh.md) | forwards to an SSH server |
| [`kubectl.md`](../examples/instructions/kubectl.md) | forwards directly to a Kubernetes API server |
| [`socks-client.md`](../examples/instructions/socks-client.md) | is a `target: socks` proxy (curl, browsers, database clients incl. Oracle, and `kubectl`/other tools via `HTTPS_PROXY`) |

## Grant matching

Grant matching stays scoped to how the caller authenticated: an SSH request is
only ever matched against `allow` entries by fingerprint or `authorized_keys`
comment, and an OIDC request only by email, `@domain`, or `group:`. `alice@laptop`
and `alice@corp.com` can therefore share one `allow` list without one method
ever being able to satisfy the other's grant — an SSH key commented
`alice@corp.com` cannot pass as the OIDC identity `alice@corp.com`, and vice
versa. In practice the bundled `ntwire` client never sends a key comment (a
private key file has none), so comment-based SSH `allow` entries only match
requests built to include one; prefer fingerprints for SSH grants.

## Hot reload

The server watches the configuration file's directory (and, when set, the
authorized-keys directory). Writing, replacing, or renaming the file reloads
runtime configuration; sending `SIGHUP` does the same. The listener address
and tunnel CIDR stay unchanged until restart. Existing sessions are
re-evaluated against their authentication method — SSH sessions against
authorized keys, OIDC sessions against the configured issuers — and current
YAML grants; sessions that lose access are terminated. Changing
`auth.oidc.issuers` rebuilds OIDC verification in the background without
dropping unrelated sessions.

Adding, removing, or changing a tunnel's `target` takes effect immediately on
the server, on the same virtual port, so an already-connected client picks it
up transparently: the affected data-plane listener is recycled without a
restart, and a session keeps its existing grant across the change. A
connection already in flight keeps proxying to its original target until it
closes; only new connections observe the new one. Changing a tunnel's
`virtual_port` also recycles the server-side listener immediately, but an
already-connected client resolved that port once at connect time and will not
pick up the new one until it reconnects (`ntwire connect` again, or
`ntwire logout` for an SSO session that should stop auto-reauthenticating);
new connections after the reload use the new port right away. When
`tls.cert_file`/`tls.key_file` are set, the files are re-read from disk on
every reload, so a renewed certificate is served without a restart — an
in-memory self-signed certificate is never regenerated this way, since that
would invalidate every client's TOFU pin.

## Server dashboard

Set a long random `admin.web_ui_token` to enable the operator dashboard on the
metrics listener. Open `http://server:9090/?token=TOKEN` (using the address in
`listen.metrics`) to see every
currently granted tunnel, its authenticated identity, tunnel address, expiry,
target, live connection/traffic counters, client-observed control-plane
latency, and reconnect counts. Each tunnel entry's `session_id` can be passed
to `POST /v1/admin/sessions/{id}/revoke?token=TOKEN` (same listener, same
token) to immediately end that session — the one way to revoke a live
session without waiting for its `session_ttl` or a config reload; see
[SECURITY.md](SECURITY.md#oidc-threat-model) for why that matters for OIDC
deprovisioning specifically. The dashboard and revoke endpoint are disabled by
default and return 404 without the exact token because they expose
operational and identity data (and, for revoke, session control); bind the
metrics listener to loopback or place it behind a trusted TLS reverse proxy.
The JSON form at `GET /v1/dashboard?token=TOKEN` also includes a
`security_capabilities` array, listing enabled high-risk configuration classes
without exposing tunnel names or credentials. See
[SECURITY.md](SECURITY.md#operator-visible-risk-capabilities) for the stable
values and their meaning.

## See also

- [../README.md](../README.md) — quick start and everyday client/server usage
- [SECURITY.md](SECURITY.md) — TLS trust model and OIDC threat model
- [OIDC-SETUP.md](OIDC-SETUP.md) — per-IdP registration steps
- [RELAY.md](RELAY.md) — the `relay:` block for servers behind NAT
- [AUTHORIZATION.md](AUTHORIZATION.md) — the `authorizer:` block
