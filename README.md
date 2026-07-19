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
`ntwire.yaml`. At least one of `auth.authorized_keys_dir` or `auth.oidc.issuers`
is required. The following is the complete currently parsed configuration:

```yaml
listen:
  https: ":8443"                       # TLS control API and WebSocket fallback
tls:
  cert_file: ""                         # empty generates a self-signed certificate
  key_file: ""
auth:
  authorized_keys_dir: /etc/ntwire/keys  # one public key per file; optional if oidc.issuers is set
  oidc:
    issuers:
      - name: google                    # stable id; shown to clients and in --provider
        issuer: https://accounts.google.com
        client_id: 1234-abc.apps.googleusercontent.com
        scopes: [openid, email, profile] # default shown
        groups_claim: ""                 # e.g. "groups"; empty disables group: grants
        require_verified_email: true     # default true
  session_ttl: 15m                       # default: 15m
  max_sessions_per_key: 5                # applies per identity: ssh fingerprint or oidc email
network:
  tunnel_cidr: 100.64.0.0/16             # default: 100.64.0.0/16
  advertised_endpoint: ""                # returned as udp_endpoint only
authorizer:
  webhook_url: ""                        # use this or exec
  exec: ""                               # executable reads JSON from stdin
  timeout: 5s                            # default: 5s
tunnels:
  - name: reports
    target: reports.internal:8080
    description: Reporting service
    virtual_port: 18080
    allow:
      - "*"                             # any authenticated identity, either method
      - "SHA256:..."                    # ssh: key fingerprint
      - "alice@laptop"                  # ssh: authorized_keys comment
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
