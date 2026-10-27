# ntwire

<p align="center">
  <img src="packaging/darwin/ntwire-icon.svg" width="132" alt="ntwire logo">
</p>

ntwire is a userspace WireGuard multi-tunnel service. Authenticate with an
SSH key or OIDC, then use only the TCP targets granted in the server YAML.
It needs neither a host network interface nor elevated privileges. See
[Security](docs/SECURITY.md) for the trust model and the implications of
binding a local tunnel beyond loopback.

## Weekly security scans

The weekly image build scans the published image digests with Trivy and freshly built release variants with govulncheck. Badges show counts by severity; govulncheck findings are counted as unknown because they are not assigned a severity here. Each badge links to a report with the source commit, artifact identity, scan time, severity counts, and scanner output. Findings do not block publication; failed scans do. Reports appear after the first successful scheduled or manual run.

### Container images

| Target | Report |
| --- | --- |
| ntwire-client-linux-amd64 | [![Scan status](.github/security/image-ntwire-client-linux-amd64.svg)](.github/security/image-ntwire-client-linux-amd64.md) |
| ntwire-client-linux-arm64 | [![Scan status](.github/security/image-ntwire-client-linux-arm64.svg)](.github/security/image-ntwire-client-linux-arm64.md) |
| ntwire-relay-linux-amd64 | [![Scan status](.github/security/image-ntwire-relay-linux-amd64.svg)](.github/security/image-ntwire-relay-linux-amd64.md) |
| ntwire-relay-linux-arm64 | [![Scan status](.github/security/image-ntwire-relay-linux-arm64.svg)](.github/security/image-ntwire-relay-linux-arm64.md) |
| ntwire-server-linux-amd64 | [![Scan status](.github/security/image-ntwire-server-linux-amd64.svg)](.github/security/image-ntwire-server-linux-amd64.md) |
| ntwire-server-linux-arm64 | [![Scan status](.github/security/image-ntwire-server-linux-arm64.svg)](.github/security/image-ntwire-server-linux-arm64.md) |

### Executables

| Target | Report |
| --- | --- |
| ntwire-darwin-amd64 | [![Scan status](.github/security/binary-ntwire-darwin-amd64.svg)](.github/security/binary-ntwire-darwin-amd64.md) |
| ntwire-darwin-arm64 | [![Scan status](.github/security/binary-ntwire-darwin-arm64.svg)](.github/security/binary-ntwire-darwin-arm64.md) |
| ntwire-gui-darwin-arm64 | [![Scan status](.github/security/binary-ntwire-gui-darwin-arm64.svg)](.github/security/binary-ntwire-gui-darwin-arm64.md) |
| ntwire-gui-linux-amd64 | [![Scan status](.github/security/binary-ntwire-gui-linux-amd64.svg)](.github/security/binary-ntwire-gui-linux-amd64.md) |
| ntwire-gui-linux-arm64 | [![Scan status](.github/security/binary-ntwire-gui-linux-arm64.svg)](.github/security/binary-ntwire-gui-linux-arm64.md) |
| ntwire-gui-windows-amd64 | [![Scan status](.github/security/binary-ntwire-gui-windows-amd64.svg)](.github/security/binary-ntwire-gui-windows-amd64.md) |
| ntwire-gui-windows-arm64 | [![Scan status](.github/security/binary-ntwire-gui-windows-arm64.svg)](.github/security/binary-ntwire-gui-windows-arm64.md) |
| ntwire-linux-amd64 | [![Scan status](.github/security/binary-ntwire-linux-amd64.svg)](.github/security/binary-ntwire-linux-amd64.md) |
| ntwire-linux-arm64 | [![Scan status](.github/security/binary-ntwire-linux-arm64.svg)](.github/security/binary-ntwire-linux-arm64.md) |
| ntwire-relay-darwin-amd64 | [![Scan status](.github/security/binary-ntwire-relay-darwin-amd64.svg)](.github/security/binary-ntwire-relay-darwin-amd64.md) |
| ntwire-relay-darwin-arm64 | [![Scan status](.github/security/binary-ntwire-relay-darwin-arm64.svg)](.github/security/binary-ntwire-relay-darwin-arm64.md) |
| ntwire-relay-linux-amd64 | [![Scan status](.github/security/binary-ntwire-relay-linux-amd64.svg)](.github/security/binary-ntwire-relay-linux-amd64.md) |
| ntwire-relay-linux-arm64 | [![Scan status](.github/security/binary-ntwire-relay-linux-arm64.svg)](.github/security/binary-ntwire-relay-linux-arm64.md) |
| ntwire-relay-windows-amd64 | [![Scan status](.github/security/binary-ntwire-relay-windows-amd64.svg)](.github/security/binary-ntwire-relay-windows-amd64.md) |
| ntwire-relay-windows-arm64 | [![Scan status](.github/security/binary-ntwire-relay-windows-arm64.svg)](.github/security/binary-ntwire-relay-windows-arm64.md) |
| ntwire-server-darwin-amd64 | [![Scan status](.github/security/binary-ntwire-server-darwin-amd64.svg)](.github/security/binary-ntwire-server-darwin-amd64.md) |
| ntwire-server-darwin-arm64 | [![Scan status](.github/security/binary-ntwire-server-darwin-arm64.svg)](.github/security/binary-ntwire-server-darwin-arm64.md) |
| ntwire-server-linux-amd64 | [![Scan status](.github/security/binary-ntwire-server-linux-amd64.svg)](.github/security/binary-ntwire-server-linux-amd64.md) |
| ntwire-server-linux-arm64 | [![Scan status](.github/security/binary-ntwire-server-linux-arm64.svg)](.github/security/binary-ntwire-server-linux-arm64.md) |
| ntwire-server-windows-amd64 | [![Scan status](.github/security/binary-ntwire-server-windows-amd64.svg)](.github/security/binary-ntwire-server-windows-amd64.md) |
| ntwire-server-windows-arm64 | [![Scan status](.github/security/binary-ntwire-server-windows-arm64.svg)](.github/security/binary-ntwire-server-windows-arm64.md) |
| ntwire-windows-amd64 | [![Scan status](.github/security/binary-ntwire-windows-amd64.svg)](.github/security/binary-ntwire-windows-amd64.md) |
| ntwire-windows-arm64 | [![Scan status](.github/security/binary-ntwire-windows-arm64.svg)](.github/security/binary-ntwire-windows-arm64.md) |

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
