# ntwire

<p align="center">
  <img src="packaging/darwin/ntwire-icon.svg" width="132" alt="ntwire logo">
</p>

ntwire is a userspace WireGuard multi-tunnel service. Authenticate with an
SSH key or OIDC, then use only the TCP targets granted in the server YAML.
It needs neither a host network interface nor elevated privileges. See
[Security](docs/SECURITY.md) for the trust model and the implications of
binding a local tunnel beyond loopback.

## Quick start

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
network:
  tunnel_cidr: 100.64.0.0/16
  advertised_endpoint: "127.0.0.1:51820"
tunnels:
  - name: demo-http
    target: example.internal:8080
    virtual_port: 18080
    local_port: 58080
    allow: ["*"]
```

Start the server, then connect from another terminal:

```sh
./bin/ntwire-server --config .local/ntwire/ntwire.yaml
./bin/ntwire connect -i .local/ntwire/id_ed25519 https://127.0.0.1:8443
```

The first connection asks to pin the generated certificate. The listener
reported for `demo-http` forwards through the WireGuard tunnel to the target.

## Documentation

The [documentation index](docs/README.md) is the entry point for all details.
Common next steps:

- [Connecting guide](docs/CONNECTING.md) — clients, official WireGuard, and relays.
- [Client guide](docs/CLIENT.md) — commands, local state, GUI, and SSO.
- [Configuration reference](docs/CONFIGURATION.md) — every server/client option.
- [Deployment guide](docs/DEPLOYMENT.md) — release binaries, Docker, Kubernetes, and Helm.
- [Security guide](docs/SECURITY.md) — TLS, OIDC, local bindings, and relay trust.

## Development

```sh
go test ./...
go build ./cmd/...
```

For contributor workflow, release checks, and conventions see
[AGENTS.md](AGENTS.md) and [Release readiness](docs/RELEASE.md).

## License

[Apache-2.0](LICENSE)
