# Deployment

## Building from source

```sh
go test ./...
go build ./cmd/...
```

builds and tests the client (`ntwire`), server (`ntwire-server`), and relay
(`ntwire-relay`) together; `go build -o bin/ntwire ./cmd/ntwire` builds just
one of them. See [AGENTS.md](../AGENTS.md) for the full contributor workflow,
including `ojob tasks.yaml op=check`.

## Release binaries and containers

Each versioned GitHub Release includes direct-download archives for the
`ntwire` client, `ntwire-server`, and `ntwire-relay` executables on Linux,
macOS, and Windows (amd64 and arm64). Download and unpack the archive that
matches the host running that component: the client archive for a
workstation, the server archive for the host that accepts connections, and
the relay archive for a public host relaying servers behind NAT (see
[RELAY.md](RELAY.md)).

Container images for all three components are also published to Docker Hub as
`nmaguiar/ntwire-server`, `nmaguiar/ntwire-client`, and `nmaguiar/ntwire-relay`
(currently tagged `build`, built from `main`). They are optional deployment
alternatives and do not replace the release binaries. All three images set
`NTWIRE_LOG_FORMAT=json` by default, so logs are Logstash-format JSON out of
the box; see [LOGGING.md](LOGGING.md) to change or override it.

## Docker Compose

The Compose example in `deploy/docker` is runnable as-is and exposes HTTPS
and UDP:

```sh
mkdir -p deploy/docker/keys
cp .local/ntwire/id_ed25519.pub deploy/docker/keys/local.pub  # or any authorized .pub key
docker compose -f deploy/docker/docker-compose.yml up --build
```

It starts `ntwire-server` from `deploy/docker/Dockerfile` using
`deploy/docker/ntwire.yaml`, plus an `echo` service that the `example` tunnel
forwards to. `ojob tasks.yaml op=compose-up` runs the same thing; use
`op=compose-down` when finished.

## End-to-end Docker test

Docker Compose is also used for the repository's black-box E2E test:

```sh
ojob tasks.yaml op=e2e
# or: tests/e2e/run.sh
```

It creates disposable keys, certificates, and configuration outside the
working tree, then verifies both a direct UDP/WireGuard connection and a
relayed WebSocket/WireGuard connection. Each path reaches the same dummy HTTP
target through a fixed tunnel and an explicitly domain-filtered SOCKS5
tunnel. The Compose networks isolate clients from the target, so a passing
probe must traverse ntwire. The runner removes its temporary files and Docker
resources automatically; on failure it prints the Compose logs.

### Client image

The matching client image is built from `deploy/docker/Dockerfile.client` and
published as `nmaguiar/ntwire-client`. It keeps certificate pins,
local status, and (for `--sso`) the token cache in `/home/nonroot/.ntwire`;
mount a named volume there to preserve that state. The image runs as an
unprivileged user. When bind-mounting a host private key, run it as your host
UID and bind-mount a host-owned state directory as shown below. Use
`--insecure` only for a disposable development server; for an interactive
first connection, omit it so the client can pin the server certificate. SSO
login inside a container has no browser to open, so pass `--sso --no-browser`
to use the device flow.

```sh
mkdir -p .local/ntwire/client-state
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/.local/ntwire/id_ed25519:/keys/id_ed25519:ro" \
  -v "$PWD/.local/ntwire/client-state:/home/nonroot/.ntwire" \
  nmaguiar/ntwire-client:build connect --no-browser -i /keys/id_ed25519 https://host.docker.internal:8443
```

Or build the image locally instead of pulling it:

```sh
docker build -f deploy/docker/Dockerfile.client -t ntwire-client .
```

### Relay image

`deploy/docker/Dockerfile.relay` builds `ntwire-relay`, and
`deploy/docker/ntwire-relay.yaml` is a runnable sample config. See
[RELAY.md](RELAY.md) for how to configure a relay and point a server at it.

## Kubernetes

Manifests under `deploy/k8s` mount config and keys and expose both protocols:

| File | Purpose |
| --- | --- |
| `deployment.yaml` | `ntwire-server` Deployment; runs as non-root with a read-only root filesystem |
| `service.yaml` | Exposes the `https` (TCP 8443) and `wireguard` (UDP 51820) ports |
| `configmap.yaml` | `ntwire.yaml` contents; edit `tunnels:` and (optionally) `auth.oidc` here |
| `networkpolicy.yaml` | Restricts ingress to the two exposed ports |
| `kustomization.yaml` | Bundles the four resources above |

Create an `ntwire-authorized-keys` Secret with one key per data entry before
applying, then:

```sh
kubectl apply -k deploy/k8s
```

Edit `configmap.yaml`'s `tunnels:` list for real targets, and see
[OIDC-SETUP.md](OIDC-SETUP.md) before uncommenting its `auth.oidc` block.

## See also

- [CONFIGURATION.md](CONFIGURATION.md) — full `ntwire.yaml` reference
- [RELAY.md](RELAY.md) — deploying a relay for servers behind NAT
- [SECURITY.md](SECURITY.md) — TLS trust model for a deployed server
- [LOGGING.md](LOGGING.md) — text vs. JSON logs, and the container default
