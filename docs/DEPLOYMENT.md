# Deployment

## Kubernetes discovery deployment

For an ALB/NLB EKS topology, terminate neither client TLS nor WireGuard at
the relay: expose relay TCP 443 through the ALB and the configured UDP relay
ports through the NLB. Run the relay with its ServiceAccount and the minimal
RBAC in `deploy/k8s/relay-discovery-rbac.yaml`; apply the example in
`deploy/k8s/relay-discovery-example.yaml` as a starting point. AWS resources
are optional—the discovery implementation uses standard in-cluster Kubernetes
authentication and Service DNS.

For restricted deployments use `kubernetes.namespaces.mode: selected` with
explicit names and create Role/RoleBinding pairs for Services only in those
namespaces. If `namespaces.selector` is used, namespace list/watch access is
also required. Add NetworkPolicies that allow relay namespace pods to TCP
8443 on selected tenant ntwire-server pods, allow each ntwire-server only its
namespace's workload ports/DNS, and otherwise deny tenant-to-tenant traffic.

## Building from source

```sh
go test ./...
go build ./cmd/...
```

builds and tests the client (`ntwire`), server (`ntwire-server`), relay
(`ntwire-relay`), and GUI client (`ntwire-gui`) together; `go build -o
bin/ntwire ./cmd/ntwire` builds just one of them. See
[AGENTS.md](../AGENTS.md) for the full contributor workflow, including
`ojob tasks.yaml op=check`.

## Release binaries and containers

Each versioned GitHub Release includes direct-download archives for the
`ntwire` client, `ntwire-server`, and `ntwire-relay` executables on Linux,
macOS, and Windows (amd64 and arm64). Download and unpack the archive that
matches the host running that component: the client archive for a
workstation, the server archive for the host that accepts connections, and
the relay archive for a public host relaying servers behind NAT (see
[RELAY.md](RELAY.md)).

`ntwire-gui` archives are published for Linux and Windows (amd64 and
arm64) alongside the others; macOS ships instead as an unsigned
`ntwire-gui.app` bundle (arm64), built separately since its tray
needs cgo there (see [GUI.md](GUI.md)). Being unsigned, macOS shows a
Gatekeeper "unidentified developer" warning on first launch --
right-click -> Open bypasses it; Windows SmartScreen similarly warns on
an unsigned `.exe`. Both are deferred follow-up work pending a paid
developer account.

Container images for all three components are also published to Docker Hub as
`nmaguiar/ntwire-server`, `nmaguiar/ntwire-client`, and `nmaguiar/ntwire-relay`
(with each tagged release published as both `<version>` and `latest`; `build`
continues to track `main`). The release workflow publishes the same version and
`latest` tags to GitHub Container Registry. They are optional deployment
alternatives and do not replace the release binaries. All three images set
`NTWIRE_LOG_FORMAT=json` by default, so logs are Logstash-format JSON out of
the box; see [LOGGING.md](LOGGING.md) to change or override it.

Every tagged release also publishes its versioned Helm chart to the ntwire
Helm repository at `https://ntwire.io/charts`. Its default image tag matches
the chart release version; use the source-tree chart only when you deliberately
want the source `build` image or override `image.tag`.

## Docker Compose

The Compose example in `deploy/docker` is runnable as-is and exposes HTTPS
and UDP:

```sh
mkdir -p deploy/docker/keys
cp .local/ntwire/id_ed25519.pub deploy/docker/keys/local.pub  # or any authorized .pub key
docker compose -f deploy/docker/docker-compose.yml up --build
```

It starts `ntwire-server` from `deploy/docker/Dockerfile` using
`deploy/docker/ntwire.yaml`, plus an `example` service that the `example`
tunnel forwards to. `ojob tasks.yaml op=compose-up` runs the same thing; use
`op=compose-down` when finished.

### Interacting with a running server container or pod

When `ntwire-server` is running in a Docker container (e.g. named `ntwire-server`) or Kubernetes pod, you can execute server management commands, view status and metrics, print WireGuard QR codes, list tunnels, and reload configuration without stopping the container.

#### 1. WireGuard QR codes & client configuration

If native WireGuard peers are configured (see [NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md)), you can generate and display QR codes directly in your terminal for instant scanning with official WireGuard mobile apps, or export `.conf` profiles:

```sh
# Display WireGuard QR code in the terminal (for mobile app scanning)
docker exec -it ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr

# Display QR code for a specific configured peer
docker exec -it ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr -wireguard-peer iphone

# Export client .conf configuration file
docker exec ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-conf > client.conf

# Print both .conf configuration and terminal QR code
docker exec -it ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-config
```

When using Docker Compose from `deploy/docker`:

```sh
docker compose -f deploy/docker/docker-compose.yml exec -it ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr
docker compose -f deploy/docker/docker-compose.yml exec ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-conf > client.conf
```

When using Kubernetes (`kubectl`):

```sh
# Display WireGuard QR code in the terminal (for mobile app scanning)
kubectl exec -it deployment/ntwire-server -- /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr

# Display QR code for a specific configured peer
kubectl exec -it deployment/ntwire-server -- /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr -wireguard-peer iphone

# Export client .conf configuration file
kubectl exec deployment/ntwire-server -- /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-conf > client.conf

# Print both .conf configuration and terminal QR code
kubectl exec -it deployment/ntwire-server -- /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-config
```

#### 2. Listing allowed tunnels (`list`)

To check what tunnels are permitted for an identity against the running server:

```sh
# From the host using the ntwire CLI:
ntwire list -i ~/.ntwire/id_ed25519 https://localhost:8443
ntwire list --json -i ~/.ntwire/id_ed25519 https://localhost:8443

# Or using the containerized client with Docker:
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/deploy/docker/keys/local.pub:/keys/id_ed25519.pub:ro" \
  -v "$PWD/.local/ntwire/id_ed25519:/keys/id_ed25519:ro" \
  nmaguiar/ntwire-client:build list -i /keys/id_ed25519 https://host.docker.internal:8443

# Or using the containerized client in Kubernetes:
kubectl run ntwire-client --rm -i --tty --image=nmaguiar/ntwire-client:build --restart=Never -- \
  list -i /keys/id_ed25519 https://ntwire-server:8443
```

#### 3. Viewing server status, metrics, and logs (`status`)

```sh
# Check container status
docker ps --filter "name=ntwire-server"

# Stream live container logs (Logstash JSON by default)
docker logs -f ntwire-server
# Or via Compose:
docker compose -f deploy/docker/docker-compose.yml logs -f ntwire-server

# Or via Kubernetes (kubectl):
kubectl get pods -l app=ntwire-server
kubectl logs -f deployment/ntwire-server
```

When `listen.metrics` (e.g. `:9090` or `127.0.0.1:9090`) and `admin.web_ui_token` are configured in `ntwire.yaml` and published to the host:

```sh
# Prometheus metrics endpoint
curl http://localhost:9090/metrics

# Live operator dashboard status (JSON format)
curl "http://localhost:9090/v1/dashboard?token=YOUR_ADMIN_WEB_UI_TOKEN"

# Or open the web dashboard in a browser:
# http://localhost:9090/?token=YOUR_ADMIN_WEB_UI_TOKEN

# When running in Kubernetes, forward the metrics port to localhost:
kubectl port-forward deployment/ntwire-server 9090:9090
```

To inspect an active client connection's status from the client side:

```sh
ntwire status
ntwire status --json
```

#### 4. Generating keys & reloading configuration

```sh
# Generate a native WireGuard key pair inside the container's keys directory
docker exec ntwire-server /ntwire-server -generate-wireguard-key /etc/ntwire/keys/client_wg

# Generate a relay identity key
docker exec ntwire-server /ntwire-server -generate-relay-key /etc/ntwire/keys/relay_id_ed25519

# Hot reload configuration on SIGHUP without dropping existing connections
docker kill -s HUP ntwire-server
# Or via Compose:
docker compose -f deploy/docker/docker-compose.yml kill -s HUP ntwire-server

# Or via Kubernetes (kubectl):
kubectl exec deployment/ntwire-server -- /ntwire-server -generate-wireguard-key /etc/ntwire/keys/client_wg
kubectl exec deployment/ntwire-server -- /ntwire-server -generate-relay-key /etc/ntwire/keys/relay_id_ed25519
kubectl exec deployment/ntwire-server -- kill -HUP 1
# Or trigger a rolling restart:
kubectl rollout restart deployment/ntwire-server
```

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

For the full release gate, including normal/race tests, bounded fuzzing, and
all command builds before this Docker check, run `ojob tasks.yaml op=release`.
Record a missing Docker daemon, registry access, or platform restriction as an
environment-blocked check rather than a product failure; see
[RELEASE.md](RELEASE.md).

### Client image

The matching client image is built from `deploy/docker/Dockerfile.client` and
published as `nmaguiar/ntwire-client`. It keeps certificate pins,
local status, and the mode-`0600` fallback cache (when no desktop keyring is
available) in `/home/nonroot/.ntwire`; mount a named volume there to preserve
that state. The image runs as an
unprivileged user. When bind-mounting a host private key, run it as your host
UID and bind-mount a host-owned state directory as shown below. Use
`--insecure` only for a disposable development server; for an interactive
first connection, omit it so the client can pin the server certificate. SSO
login inside a container has no browser to open, so pass `--sso --no-browser`
to use the device flow.

```sh
# Running with Docker:
mkdir -p .local/ntwire/client-state
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/.local/ntwire/id_ed25519:/keys/id_ed25519:ro" \
  -v "$PWD/.local/ntwire/client-state:/home/nonroot/.ntwire" \
  nmaguiar/ntwire-client:build connect --no-browser -i /keys/id_ed25519 https://host.docker.internal:8443

# Or running in Kubernetes with kubectl:
kubectl run ntwire-client --rm -i --tty --image=nmaguiar/ntwire-client:build --restart=Never -- \
  connect --no-browser -i /keys/id_ed25519 https://ntwire-server:8443
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
applying:

```sh
# Create authorized keys secret
kubectl create secret generic ntwire-authorized-keys --from-file=local.pub=.local/ntwire/id_ed25519.pub

# Apply Kubernetes manifests
kubectl apply -k deploy/k8s

# Check deployment and service status
kubectl get deployment,pods,svc -l app=ntwire-server

# Stream server logs
kubectl logs -f deployment/ntwire-server

# Forward HTTPS control port for local client testing
kubectl port-forward svc/ntwire-server 8443:8443

# Execute server commands (e.g. generate WireGuard QR code)
kubectl exec -it deployment/ntwire-server -- /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr

# Hot reload configuration on SIGHUP
kubectl exec deployment/ntwire-server -- kill -HUP 1
# Or trigger a rolling restart
kubectl rollout restart deployment/ntwire-server
```

Edit `configmap.yaml`'s `tunnels:` list for real targets, and see
[OIDC-SETUP.md](OIDC-SETUP.md) before uncommenting its `auth.oidc` block.

### Helm chart

`deploy/helm/ntwire` is the configurable alternative to the server-only
Kustomize example. It deploys exactly one component selected with
`component: server`, `component: relay`, or `component: client`. The matching
`server.config`, `relay.config`, or `client.config` values map is rendered
verbatim as that component's ntwire YAML file. This keeps the source of truth
in normal ntwire configuration instead of creating a partial Helm-specific
configuration language.

Use a values file rather than many `--set` flags so lists, nested settings,
and sensitive paths are preserved:

```sh
# Create the public-key Secret separately; it contains no private key.
kubectl -n ntwire create secret generic ntwire-authorized-keys \
  --from-file=authorized_keys="$HOME/.ntwire/id_ed25519.pub"

helm repo add ntwire https://ntwire.io/charts
helm repo update
helm upgrade --install ntwire-server ntwire/ntwire \
  --namespace ntwire --create-namespace \
  --values my-server-values.yaml
```

The repository always selects the newest published chart. For a controlled
upgrade, add `--version <chart-version>` to the `helm upgrade` command. The
source-tree path `deploy/helm/ntwire` remains useful for chart development.

For example, `my-server-values.yaml` can keep the connection configuration and
Secret reference together without embedding the secret itself:

```yaml
component: server
secretMounts:
  - name: authorized-keys
    secretName: ntwire-authorized-keys
    mountPath: /etc/ntwire/keys
server:
  config:
    listen: {https: ":8443", wireguard: ":51820"}
    tls: {state_dir: /var/lib/ntwire/tls}
    auth: {authorized_keys_dir: /etc/ntwire/keys}
    network: {tunnel_cidr: 100.64.0.0/16}
    tunnels: []
```

Set `component: relay` and configure `relay.config` to deploy a public relay,
or `component: client` and configure `client.config` for a persistent
`ntwire connect` workload. The client normally needs no Service; mount its SSH
identity or CA material through `secretMounts`, and set `client.config` to
refer to those files. The default state volume is ephemeral. Enable
`persistence` when generated TLS state, certificate pins, client status, or
other configured files under `/var/lib/ntwire` must survive a replacement pod.

The chart creates a ServiceAccount without an API token by default. If relay
Kubernetes Service discovery is enabled, set
`serviceAccount.automountServiceAccountToken: true` and bind only the RBAC
needed for the selected namespaces and Services; reuse
`deploy/k8s/relay-discovery-rbac.yaml` as the starting point. Do not expose
optional metrics, relay reflector/UDP-relay, or dedicated tenant ports by
accident: add them explicitly through `service.ports`, then match the
configuration, load balancer, and firewall. Full chart settings are documented
in [`deploy/helm/ntwire/README.md`](../deploy/helm/ntwire/README.md).

## See also

- [CONFIGURATION.md](CONFIGURATION.md) — full `ntwire.yaml` reference
- [RELAY.md](RELAY.md) — deploying a relay for servers behind NAT
- [SECURITY.md](SECURITY.md) — TLS trust model for a deployed server
- [LOGGING.md](LOGGING.md) — text vs. JSON logs, and the container default
