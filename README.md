# ntwire

ntwire is a userspace WireGuard multi-tunnel service. An SSH key or an SSO
(OIDC) login authenticates a session, then a per-session WireGuard peer and
gVisor netstack forward only the YAML-granted TCP targets to local
`127.0.0.1` listeners. No host network interface or elevated privilege is
needed.

## What works today

| Available | Operational limit |
| --- | --- |
| Ed25519 key generation, SSH request signing, and TOFU | Listener address and tunnel-CIDR changes require a restart; tunnel additions/removals/repoints and an explicit TLS cert/key file pair reload live. |
| SSO login (Auth Code + PKCE, with an OAuth device-flow fallback) against any generic OIDC issuer | ntwire-server never becomes an OAuth client; it only verifies ID tokens against the issuer's JWKS. |
| HTTPS control API, WireGuard netstack, TCP forwarding, and WebSocket transport | |
| Session renewal, rate limits, reaping, persistent configuration, and status UI | |
| YAML/key-directory hot reload and Compose/Kubernetes deployment assets | |
| Optional webhook or executable authorization hook | |

## Quick start

This local example starts a TLS control server and a userspace WireGuard data
plane. The client asks to pin the default self-signed certificate on first use.

Requirements: Go 1.26 or later.

```sh
git clone https://github.com/nmaguiar/ntwire.git
cd ntwire
go test ./...
go build -o bin/ntwire ./cmd/ntwire
go build -o bin/ntwire-server ./cmd/ntwire-server

mkdir -p .local/ntwire/keys
./bin/ntwire keygen -o .local/ntwire/id_ed25519
cp .local/ntwire/id_ed25519.pub .local/ntwire/keys/local.pub
```

Create `.local/ntwire/ntwire.yaml`:

```yaml
listen:
  https: "127.0.0.1:8443"
  wireguard: "127.0.0.1:51820"
auth:
  authorized_keys_dir: .local/ntwire/keys
  session_ttl: 15m
network:
  tunnel_cidr: 100.64.0.0/16
  advertised_endpoint: "127.0.0.1:51820"
tunnels:
  - name: demo-http
    target: example.internal:8080
    description: Example grant
    virtual_port: 18080
    local_port: 58080 # Preferred client loopback port; falls back if occupied
    allow: ["*"]
```

Start the server in one terminal:

```sh
./bin/ntwire-server --config .local/ntwire/ntwire.yaml
```

In another terminal, authenticate and print the authorized grants:

```sh
./bin/ntwire connect -i .local/ntwire/id_ed25519 https://127.0.0.1:8443
```

The output contains a `demo-http` row and loopback listener. Connections to it
are forwarded to the configured target through WireGuard.

## Client usage

| Command | Current behavior |
| --- | --- |
| `ntwire keygen [-o path]` | Writes a PKCS#8 Ed25519 private key and an OpenSSH `.pub` key. The default private key is `ntwire_ed25519`. |
| `ntwire list [-i key \| --sso] URL` | Authenticates once and prints server grants. Without `-i` or `identity_file`, uses the first conventional key found in `~/.ssh`, or falls back to SSO when the server advertises it. Do not add a trailing `/` to `URL`. |
| `ntwire connect [-i key \| --sso] URL [--port name=15432] [--websocket]` | Starts local listeners, renews its session, and prints a token-protected status URL. A tunnel's YAML `local_port` is preferred when available; `--port` is a strict client-side override. Same key/SSO selection as `list`; `--websocket` selects fallback transport. |
| `ntwire port name=15432` | Replaces the local loopback listener for a running tunnel. The same action is available in the status UI. |
| `ntwire logout URL` | Clears cached SSO tokens for a server, so the next connection reopens the browser (or device flow) instead of silently refreshing. |
| `ntwire version` | Prints the build version (`dev` for an ordinary source build). |

Use an `https://` URL, for example `https://127.0.0.1:8443`. The first use of
a self-signed server prompts to store its fingerprint in `~/.ntwire/known_servers`.
That fingerprint changes on every server restart unless the server is given a
persistent certificate; see
[Avoiding repeated re-trust prompts](docs/SECURITY.md#tls-trust-model-and-avoiding-repeated-re-trust-prompts)
for the tradeoffs.

### SSO login

When a server advertises one or more OIDC issuers, `connect`/`list` use SSO by
default whenever no SSH key is found (an explicit `-i`, or a key present in
`~/.ssh`, is always preferred). Pass `--sso` to force SSO even when a key is
available, and `--provider name` to pick an issuer if the server advertises
more than one. The default flow opens the system browser for an Auth Code +
PKCE login on a loopback redirect; `--no-browser` (or a machine with no
browser available) falls back to the OAuth device flow, which prints a URL
and code to enter on another device.

A successful login caches a refresh token in `~/.ntwire/tokens.json` (mode
`0600`), keyed by server URL and issuer, so a long-running `connect` and
future invocations reauthenticate silently until `ntwire logout` clears it or
the server revokes access (see [docs/SECURITY.md](docs/SECURITY.md)).

## Server configuration

Run `ntwire-server --config path/to/ntwire.yaml`; the default path is
`ntwire.yaml`. Use `ntwire-server --print-sample-config > ntwire.yaml` to
write a complete, extensively commented template for every available option.
At least one of `auth.authorized_keys_dir` or `auth.oidc.issuers` is required.
The following is the complete currently parsed configuration:

```yaml
listen:
  https: ":8443"                        # TLS control API (auth, renew, disconnect) and WebSocket fallback
  wireguard: ":51820"                   # UDP listener for the userspace WireGuard data plane; default shown
  metrics: "127.0.0.1:9090"              # optional plaintext metrics and token-protected dashboard listener; empty disables it
tls:
  cert_file: ""                         # PEM certificate; empty generates an in-memory self-signed cert (see docs/SECURITY.md)
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
        require_verified_email: true     # reject tokens without email_verified=true; default true, see docs/SECURITY.md
  session_ttl: 15m                       # bearer-token session lifetime before renewal is required; default: 15m
  max_sessions_per_key: 5                # concurrent-session cap per identity (ssh fingerprint or oidc email); 0 = unlimited
admin:
  web_ui_token: ""                       # optional secret: enables the server dashboard on listen.metrics at http://server:9090/?token=...; leave empty to disable it
network:
  tunnel_cidr: 100.64.0.0/16             # private IPv4 range peer addresses are allocated from; default shown
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
```

Every readable non-directory file in `authorized_keys_dir` is treated as a
public key. Tunnel names must be unique and each tunnel requires `name` and
`target`. `ntwire-server` is a public OAuth client (PKCE, no client secret) and
never stores IdP credentials; see the Google/Entra/Keycloak registration
notes in [deploy/OIDC-SETUP.md](deploy/OIDC-SETUP.md).

Grant matching stays scoped to how the caller authenticated: an SSH request is
only ever matched against `allow` entries by fingerprint or `authorized_keys`
comment, and an OIDC request only by email, `@domain`, or `group:`. `alice@laptop`
and `alice@corp.com` can therefore share one `allow` list without one method
ever being able to satisfy the other's grant — an SSH key commented
`alice@corp.com` cannot pass as the OIDC identity `alice@corp.com`, and vice
versa. In practice the bundled `ntwire` client never sends a key comment (a
private key file has none), so comment-based SSH `allow` entries only match
requests built to include one; prefer fingerprints for SSH grants.

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

### Server dashboard

Set a long random `admin.web_ui_token` to enable the operator dashboard on the
metrics listener. Open `http://server:9090/?token=TOKEN` (using the address in
`listen.metrics`) to see every
currently granted tunnel, its authenticated identity, tunnel address, expiry,
target, live connection/traffic counters, client-observed control-plane
latency, and reconnect counts. The dashboard is disabled by
default and returns 404 without the exact token because it exposes operational
and identity data; bind the metrics listener to loopback or place it behind a
trusted TLS reverse proxy.

## Authorization hooks

With no `authorizer` configured, YAML grants are accepted directly. A webhook
or executable can deny a request, narrow its tunnel list, and shorten its
session lifetime. Errors, timeouts, malformed responses, non-2xx webhook
responses, and non-zero executable exits deny the request.

The hook receives JSON by HTTP POST or standard input:

```json
{
  "source_ip": "127.0.0.1:50123",
  "key_fingerprint": "SHA256:...",
  "key_comment": "alice@laptop",
  "auth_method": "ssh",
  "client_info": {"os": "darwin", "arch": "arm64"},
  "granted_tunnels_by_yaml": ["reports"],
  "requested_at": "2026-07-17T12:00:00Z"
}
```

An OIDC session sends `auth_method: "oidc"` with `key_fingerprint`/`key_comment`
empty and adds `identity` (the verified email), `issuer` (the configured issuer
name), and `groups` (from `groups_claim`, when configured):

```json
{
  "source_ip": "127.0.0.1:50123",
  "auth_method": "oidc",
  "identity": "alice@corp.com",
  "issuer": "google",
  "groups": ["engineering"],
  "client_info": {"os": "darwin", "arch": "arm64"},
  "granted_tunnels_by_yaml": ["reports"],
  "requested_at": "2026-07-17T12:00:00Z"
}
```

A successful response is, for example:

```json
{"allow": true, "allowed_tunnels": ["reports"], "ttl_seconds": 300}
```

Set `allowed_tunnels` to `"*"` to preserve all YAML grants. An array can only
narrow them. `ttl_seconds` applies only when it is shorter than the configured
session TTL.

## Control API

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/info` | Returns the protocol version, advertised capabilities, and (when configured) the OIDC issuer list. |
| `POST /v1/auth` | Validates a signed SSH-key request and creates a session. |
| `POST /v1/auth/oidc` | Validates a verified ID token against a configured issuer and creates a session. |
| `POST /v1/renew` | Re-authorizes a bearer-token session and replaces its token. |
| `POST /v1/disconnect` | Deletes a bearer-token session and returns `204 No Content`. |
| `GET /v1/wg` | Carries WireGuard datagrams over token-authenticated WebSocket messages. |

Use `Authorization: Bearer TOKEN` for bearer-token endpoints. The signing
format and response schemas are specified in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Development and deployment

```sh
go test ./...
go build ./cmd/...
```

## Release binaries and containers

Each versioned GitHub Release includes direct-download archives for both the
`ntwire` client and the `ntwire-server` executable on Linux, macOS, and
Windows (amd64 and arm64). Download and unpack the archive that matches the
host running that component; use the client archive for a workstation and the
server archive for the host that accepts connections.

The server and client Docker images are published alongside those release
assets. They are optional deployment alternatives and do not replace the
release binaries.

The Docker Compose example is runnable from `deploy/docker` and exposes HTTPS
and UDP. Create `deploy/docker/keys/` and place an authorized `.pub` key in it
before `docker compose up --build`; the `example` tunnel forwards to the echo
service. Kubernetes manifests mount config and keys and expose both protocols.

The matching client image is built from `deploy/docker/Dockerfile.client` and
is published as `ghcr.io/nmaguiar/ntwire-client`. It keeps certificate pins,
local status, and (for `--sso`) the token cache in `/home/nonroot/.ntwire`;
mount a named volume there to preserve that state. The image runs as an
unprivileged user. When bind-mounting a host private key, run it as your host
UID and bind-mount a host-owned state directory as shown below. Use
`--insecure` only for a disposable development server; for an interactive
first connection, omit it so the client can pin the server certificate. SSO
login inside a container has no browser to open, so pass `--sso --no-browser`
to use the device flow.

```sh
docker build -f deploy/docker/Dockerfile.client -t ntwire-client .
mkdir -p .local/ntwire/client-state
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/.local/ntwire/id_ed25519:/keys/id_ed25519:ro" \
  -v "$PWD/.local/ntwire/client-state:/home/nonroot/.ntwire" \
  ntwire-client connect --no-browser -i /keys/id_ed25519 https://host.docker.internal:8443
```

## Security

Keep private keys, session tokens, signatures, and ID/refresh tokens out of
logs and source control. The protocol uses canonical signed payloads,
timestamp validation, nonce replay protection, and constant-time public-key
comparison for SSH; OIDC ID tokens are verified server-side against the
issuer's JWKS with an audience check bound to the configured `client_id`. It
encrypts the control plane with TLS and the data plane with WireGuard. See
[docs/SECURITY.md](docs/SECURITY.md).

## License

[Apache-2.0](LICENSE)
# Client quickstart (connecting to an existing server)

1. Run `ntwire keygen`.
2. Send `~/.ntwire/id_ed25519.pub` to the server administrator.
3. Run `ntwire connect server.example`. Confirm the first certificate pin with
   the administrator; future runs can simply use `ntwire connect`.
