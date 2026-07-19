# ntwire

ntwire is a userspace WireGuard multi-tunnel service. SSH keys authenticate a
session, then a per-session WireGuard peer and gVisor netstack forward only
the YAML-granted TCP targets to local `127.0.0.1` listeners. No host network
interface or elevated privilege is needed.

## What works today

| Available | Operational limit |
| --- | --- |
| Ed25519 key generation, SSH request signing, and TOFU | Listener, TLS, and tunnel-CIDR changes require a restart. |
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
| `ntwire list [-i key] URL` | Authenticates once and prints server grants. Without `-i` or `identity_file`, uses the first conventional key found in `~/.ssh`. Do not add a trailing `/` to `URL`. |
| `ntwire connect [-i key] URL [--port name=15432] [--websocket]` | Starts local listeners, renews its session, and prints a token-protected status URL. Without `-i` or `identity_file`, uses the first conventional key found in `~/.ssh`; `--websocket` selects fallback transport. |
| `ntwire port name=15432` | Replaces the local loopback listener for a running tunnel. The same action is available in the status UI. |
| `ntwire version` | Prints the build version (`dev` for an ordinary source build). |

Use an `https://` URL, for example `https://127.0.0.1:8443`. The first use of
a self-signed server prompts to store its fingerprint in `~/.ntwire/known_servers`.

## Server configuration

Run `ntwire-server --config path/to/ntwire.yaml`; the default path is
`ntwire.yaml`. `auth.authorized_keys_dir` is required. The following is the
complete currently parsed configuration:

```yaml
listen:
  https: ":8443"                       # TLS control API and WebSocket fallback
tls:
  cert_file: ""                         # empty generates a self-signed certificate
  key_file: ""
auth:
  authorized_keys_dir: /etc/ntwire/keys  # required; one public key per file
  session_ttl: 15m                       # default: 15m
  max_sessions_per_key: 5
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
      - "*"                             # any authorized key
      - "SHA256:..."                    # SSH key fingerprint
      - "alice@laptop"                  # authorized_keys comment
```

Every readable non-directory file in `authorized_keys_dir` is treated as a
public key. A tunnel is granted when `allow` contains `*`, the authenticated
key's fingerprint, or that key's `authorized_keys` comment. Tunnel names must
be unique and each tunnel requires `name` and `target`.

The server watches the configuration file's directory. Writing, replacing, or
renaming the file reloads runtime configuration. The listener address, TLS
fields, and tunnel CIDR stay unchanged until restart. Existing sessions are
re-evaluated against authorized keys and YAML grants; sessions that lose access
are terminated.

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
| `GET /v1/info` | Returns the protocol version and advertised capabilities. |
| `POST /v1/auth` | Validates a signed SSH-key request and creates a session. |
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
is published as `ghcr.io/nmaguiar/ntwire-client`. It keeps certificate pins and
local status in `/home/nonroot/.ntwire`; mount a named volume there to preserve
that state. The image runs as an unprivileged user. When bind-mounting a host
private key, run it as your host UID and bind-mount a host-owned state
directory as shown below. Use `--insecure` only for a disposable development
server; for an interactive first connection, omit it so the client can pin the
server certificate.

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

Keep private keys, session tokens, and signatures out of logs and source
control. The protocol uses canonical signed payloads, timestamp validation,
nonce replay protection, and constant-time public-key comparison. It does
encrypt the control plane with TLS and the data plane with WireGuard. See
[docs/SECURITY.md](docs/SECURITY.md).

## License

[MIT](LICENSE)
