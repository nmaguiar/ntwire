# nwire

nwire is a userspace WireGuard multi-tunnel service. SSH keys authenticate a
session, then a per-session WireGuard peer and gVisor netstack forward only
the YAML-granted TCP targets to local `127.0.0.1` listeners. No host network
interface or elevated privilege is needed.

For a code-backed checklist of roadmap gaps, see
[docs/PLAN-GAPS.md](docs/PLAN-GAPS.md).

## What works today

| Available | Not implemented yet |
| --- | --- |
| Ed25519 key generation and SSH request signing | WebSocket fallback |
| HTTPS control API, WireGuard netstack, and TCP forwarding | TOFU and client status UI |
| Timestamp/nonce replay protection, rate limits, and session reaping | Automatic renewal and persistent client configuration |
| YAML/key-directory hot reload and Compose/Kubernetes base manifests | Full end-to-end deployment smoke coverage |
| Optional webhook or executable authorization hook | |

## Quick start

This local example exercises the implemented control plane. The server uses
plain HTTP at present, so bind it to loopback and do not expose it to an
untrusted network.

Requirements: Go 1.26 or later.

```sh
git clone https://github.com/nmaguiar/nwire.git
cd nwire
go test ./...
go build -o bin/nwire ./cmd/nwire
go build -o bin/nwire-server ./cmd/nwire-server

mkdir -p .local/nwire/keys
./bin/nwire keygen -o .local/nwire/id_ed25519
cp .local/nwire/id_ed25519.pub .local/nwire/keys/local.pub
```

Create `.local/nwire/nwire.yaml`:

```yaml
listen:
  https: "127.0.0.1:8443"
auth:
  authorized_keys_dir: .local/nwire/keys
  session_ttl: 15m
network:
  tunnel_cidr: 100.64.0.0/16
tunnels:
  - name: demo-http
    target: example.internal:8080
    description: Example grant; no traffic is forwarded yet
    virtual_port: 18080
    allow: ["*"]
```

Start the server in one terminal:

```sh
./bin/nwire-server --config .local/nwire/nwire.yaml
```

In another terminal, authenticate and print the authorized grants:

```sh
./bin/nwire list -i .local/nwire/id_ed25519 http://127.0.0.1:8443
```

The output contains a `demo-http` row. The configured `target` is only a
grant hint in the current bootstrap; it is not dialled by the server.

## Client usage

| Command | Current behavior |
| --- | --- |
| `nwire keygen [-o path]` | Writes a PKCS#8 Ed25519 private key and an OpenSSH `.pub` key. The default private key is `nwire_ed25519`. |
| `nwire list -i key URL` | Authenticates once and prints server grants. Do not add a trailing `/` to `URL`. |
| `nwire connect -i key URL` | Currently an alias for `list`; it does not create a local listener or persistent connection. |
| `nwire version` | Prints the build version (`dev` for an ordinary source build). |

Use an `http://` URL with the current server, for example
`http://127.0.0.1:8443`. HTTPS URLs will not work until TLS serving exists.

## Server configuration

Run `nwire-server --config path/to/nwire.yaml`; the default path is
`nwire.yaml`. `auth.authorized_keys_dir` is required. The following is the
complete currently parsed configuration:

```yaml
listen:
  https: ":8443"                       # default; an HTTP listener for now
tls:
  cert_file: ""                         # parsed, not used yet
  key_file: ""                          # parsed, not used yet
auth:
  authorized_keys_dir: /etc/nwire/keys  # required; one public key per file
  session_ttl: 15m                       # default: 15m
  max_sessions_per_key: 5                # parsed, not enforced yet
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
fields, and tunnel CIDR stay unchanged until restart; existing sessions are
not retroactively re-evaluated.

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

Use `Authorization: Bearer TOKEN` for bearer-token endpoints. The signing
format and response schemas are specified in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Development and deployment

```sh
go test ./...
go build ./cmd/...
```

The Docker and Kubernetes files are scaffolding for the planned service, not
an end-to-end deployment path. The Docker image builds only the server, no TLS
listener exists, and the sample Compose build context needs adjustment before
it can build from the repository root. Use the local quick start to exercise
the present implementation.

## Security

Keep private keys, session tokens, and signatures out of logs and source
control. The protocol uses canonical signed payloads, timestamp validation,
nonce replay protection, and constant-time public-key comparison. It does
**not** encrypt the transport today. Bind to loopback or use a trusted
TLS-terminating proxy until TLS is implemented. See [docs/SECURITY.md](docs/SECURITY.md).

## License

[MIT](LICENSE)
