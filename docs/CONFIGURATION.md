# Server configuration reference

Run `ntwire-server --config path/to/ntwire.yaml`; the default path is
`ntwire.yaml`. Use `ntwire-server --print-sample-config > ntwire.yaml` to
write a complete, extensively commented template for every available option.
At least one of `auth.authorized_keys_dir` or `auth.oidc.issuers` is required.

See [../README.md](../README.md) for a minimal working example. The
following is the complete currently parsed configuration:

```yaml
listen:
  https: ":8443"                        # TLS control API (auth, renew, disconnect) and WebSocket fallback
  wireguard: ":51820"                   # UDP listener for the userspace WireGuard data plane; default shown
  metrics: "127.0.0.1:9090"              # optional plaintext metrics and token-protected dashboard listener; empty disables it
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
        client_id: 1234-abc.apps.googleusercontent.com  # public OAuth client id registered at the issuer (PKCE, no secret)
        scopes: [openid, email, profile] # requested OAuth scopes; default shown
        groups_claim: ""                 # ID-token claim holding group membership, e.g. "groups"; empty disables group: grants
        require_verified_email: true     # reject tokens without email_verified=true; default true, see SECURITY.md
  session_ttl: 15m                       # bearer-token session lifetime before renewal is required; default: 15m
  max_sessions_per_key: 5                # concurrent-session cap per identity (ssh fingerprint or oidc email); 0 = unlimited
admin:
  web_ui_token: ""                       # optional secret: enables the server dashboard on listen.metrics at http://server:9090/?token=...; leave empty to disable it
network:
  tunnel_cidr: 100.64.0.0/16             # private IPv4 range or an IPv6 prefix peer addresses are allocated from (pick one; a deployment is single-family); default shown; for IPv6 use /64 or no shorter than /112
  advertised_endpoint: ""                # host:port returned to clients as udp_endpoint, for when it differs from listen.wireguard (e.g. NAT/port-forward)
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
    allow:
      - "*"                             # any authenticated identity, either method
      - "SHA256:..."                    # ssh: key fingerprint (preferred; see grant-matching note below)
      - "alice@laptop"                  # ssh: authorized_keys comment (the bundled client never sends one; see note below)
      - "alice@corp.com"                # oidc: exact verified email
      - "@corp.com"                     # oidc: email domain
      - "group:engineering"             # oidc: groups_claim membership
log:
  format: text                          # text or json (Logstash-format); container images default to json
  level: info                           # debug, info, warn, or error
audit:
  log_file: ""                          # optional path for a dedicated JSON-lines audit log; events also still go to the main log
```

See [LOGGING.md](LOGGING.md) for the full `log:` reference, including the
`-log-format`/`-log-level` flags and env vars, and their precedence.

`audit.log_file`, when set, additionally writes every `audit` event
(`auth_allowed`, `session_disconnected`, `session_expired`, `session_revoked`)
as a Logstash-format JSON line to that file, regardless of `log.format`. This
is additive: audit events keep appearing in the main log too, so existing
log-based monitoring is unaffected. The file is opened append-only with mode
`0600` and is not rotated by ntwire-server; pair it with `logrotate` or an
equivalent if it needs to be bounded.

Every readable non-directory file in `authorized_keys_dir` is treated as a
public key. Tunnel names must be unique and each tunnel requires `name` and
`target`. `ntwire-server` is a public OAuth client (PKCE, no client secret) and
never stores IdP credentials; see the Google/Entra/Keycloak registration
notes in [OIDC-SETUP.md](OIDC-SETUP.md).

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

## See also

- [../README.md](../README.md) — quick start and everyday client/server usage
- [SECURITY.md](SECURITY.md) — TLS trust model and OIDC threat model
- [OIDC-SETUP.md](OIDC-SETUP.md) — per-IdP registration steps
- [RELAY.md](RELAY.md) — the `relay:` block for servers behind NAT
- [AUTHORIZATION.md](AUTHORIZATION.md) — the `authorizer:` block
