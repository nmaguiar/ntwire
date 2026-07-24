# ntwire

ntwire is a userspace WireGuard multi-tunnel service. An SSH key or an SSO
(OIDC) login authenticates a session, then a per-session WireGuard peer and
gVisor netstack forward only the YAML-granted TCP targets to local
`127.0.0.1` listeners. No host network interface or elevated privilege is
needed.

This README covers installation and everyday client/server usage. For
configuration reference, relay mode, deployment, and security details, see
the [documentation index](docs/README.md).

## What works today

| Available | Operational limit |
| --- | --- |
| Ed25519 key generation, SSH request signing, and TOFU | |
| SSO login (Auth Code + PKCE, with an OAuth device-flow fallback) against any generic OIDC issuer | ntwire-server never becomes an OAuth client; it only verifies ID tokens against the issuer's JWKS. |
| HTTPS control API, WireGuard netstack, TCP forwarding, and WebSocket transport | |
| Session renewal, rate limits, reaping, persistent configuration, and status UI | |
| Per-tunnel Markdown setup instructions in the client status UI, templated with the port the client actually bound, with copy-to-clipboard commands and a "See more" link | Instructions are rendered from a Markdown subset (headings, lists, fenced code, inline code, emphasis, `http(s)` links); anything else is shown verbatim. |
| YAML/key-directory hot reload and Compose/Kubernetes deployment assets | Listener address and tunnel-CIDR changes require a restart; tunnel additions/removals/repoints and an explicit TLS cert/key file pair reload live. |
| Optional webhook or executable authorization hook | |
| `target: socks` tunnels: an embedded SOCKS4/5 CONNECT and BIND proxy with CIDR/domain/ASN/only-local/reverse destination filters | UDP ASSOCIATE is recognized but refused. Unfiltered SOCKS tunnels deny all destinations unless `allow_all: true` is set. |
| `ntwire-relay`: lets an ntwire-server behind NAT (no inbound connectivity) dial out to a public relay instead of listening directly | Relay mode is TCP-only: WireGuard always rides the WebSocket fallback, never UDP. |

## Quick start

This local example starts a TLS control server and a userspace WireGuard data
plane on one machine, so you can see the whole flow end to end before
deploying for real. The client asks to pin the default self-signed
certificate on first use.

Requirements: Go 1.26 or later.

### 1. Build

```sh
git clone https://github.com/nmaguiar/ntwire.git
cd ntwire
go test ./...
go build -o bin/ntwire ./cmd/ntwire
go build -o bin/ntwire-server ./cmd/ntwire-server
```

### 2. Generate a key

```sh
mkdir -p .local/ntwire/keys
./bin/ntwire keygen -o .local/ntwire/id_ed25519
cp .local/ntwire/id_ed25519.pub .local/ntwire/keys/local.pub
```

### 3. Configure a tunnel

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

This is a minimal config; the complete option reference is in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### 4. Start the server

```sh
./bin/ntwire-server --config .local/ntwire/ntwire.yaml
```

Leave this running in its own terminal.

### 5. Connect

In another terminal, authenticate and print the authorized grants:

```sh
./bin/ntwire connect -i .local/ntwire/id_ed25519 https://127.0.0.1:8443
```

The output contains a `demo-http` row and loopback listener. Connections to it
are forwarded to the configured target through WireGuard.

### Connecting to an existing server

If someone else already runs the server, you only need the client:

1. Run `ntwire keygen`.
2. Send `~/.ntwire/id_ed25519.pub` to the server administrator.
3. Run `ntwire connect server.example`. Confirm the first certificate pin with
   the administrator; future runs can simply use `ntwire connect`.

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
See [docs/SECURITY.md#tls-trust-model-and-avoiding-repeated-re-trust-prompts](docs/SECURITY.md#tls-trust-model-and-avoiding-repeated-re-trust-prompts)
for how that fingerprint stays stable across restarts and what to do if it
doesn't.

If the private key (found or given via `-i`) is encrypted, `connect`/`list`
prompt for its passphrase on the terminal (input is hidden, and a wrong
passphrase can be retried); a non-interactive run without a terminal fails
with a clear error instead of hanging.

`-h`/`--help` output (for `ntwire`, `ntwire-server`, and `ntwire-relay`) is
colorized with UTF-8 symbols on a capable terminal, and falls back to plain
ASCII automatically when piped, redirected, or when `NO_COLOR` is set; pass
`--no-color` to disable it explicitly. See [docs/LOGGING.md](docs/LOGGING.md)
for log format/color details.

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

The Quick start config above is a minimal example. The full option reference —
listeners, TLS, OIDC issuers, session limits, the operator dashboard, tunnel
grants, grant matching, per-tunnel client instructions, hot-reload behavior,
and `target: socks` proxy tunnels — is in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md#socks-proxy-tunnels).
`ntwire-server` is a public
OAuth client (PKCE, no client secret) and never stores IdP credentials; see
the Google/Entra/Keycloak registration notes in
[docs/OIDC-SETUP.md](docs/OIDC-SETUP.md).

The server watches its configuration file (and, when set, the
authorized-keys directory) and reloads on change or `SIGHUP`; most settings
take effect without a restart. See
[docs/CONFIGURATION.md#hot-reload](docs/CONFIGURATION.md#hot-reload) for
exactly what does and doesn't.

## Relay mode

A server with no inbound connectivity (behind NAT, or on a home/lab network)
can still be reached by dialing out to a public `ntwire-relay` instead of
listening directly:

```
ntwire-server (behind NAT, no inbound) --outbound--> ntwire-relay (public) <--inbound-- ntwire client
```

The relay never terminates the client's TLS session — it only routes on the
TLS ClientHello's SNI and splices raw bytes, so it cannot see or modify
tunnel traffic (see
[docs/SECURITY.md#the-relays-trust-model](docs/SECURITY.md#the-relays-trust-model)).
Clients connect exactly as they would to a directly reachable server, using
the relay's wildcard hostname:

```sh
ntwire connect https://home.relay.example.com
```

See [docs/RELAY.md](docs/RELAY.md) for running a relay and pointing a server
at one.

## Authorization hooks

With no `authorizer` configured, YAML grants are accepted directly. A webhook
or executable can additionally deny a request, narrow its tunnel list, or
shorten its session lifetime. See
[docs/AUTHORIZATION.md](docs/AUTHORIZATION.md) for the request/response
schema and a runnable example.

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

builds and tests the client, server, and relay together. Prebuilt container
images are also published to Docker Hub as `nmaguiar/ntwire-server`,
`nmaguiar/ntwire-client`, and `nmaguiar/ntwire-relay`, as an alternative to
the release binaries. Release binaries, Docker Compose, and Kubernetes
manifests are covered in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). See
[AGENTS.md](AGENTS.md) for the full contributor workflow, coding style, and
commit conventions.

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
