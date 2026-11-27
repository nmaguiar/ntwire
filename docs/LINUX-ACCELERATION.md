# Linux server acceleration

ntwire-server can use Linux kernel WireGuard and kernel TCP/IP sockets for in-tunnel listeners. The public bind still handles ntwire UDP control packets, WebSocket, UDP relay, multipath and the alternate UDP port. Public endpoints, WireGuard profiles and session authorization work the same way across backend selections.

```yaml
acceleration:
  mode: auto
  allow_auto: false
  ebpf: false
```

| Mode | Behavior |
| --- | --- |
| `auto` | Default. On Linux, `allow_auto: true` enables a kernel setup attempt. A setup failure falls back to userspace after successful cleanup. A cleanup failure stops startup. |
| `off` | Use the portable backend and skip Linux acceleration setup, even as root. |
| `required` | Use the Linux kernel backend or fail startup with the operation that failed. Use this mode to validate a deployment and measure performance. |

Set `mode: auto` and `allow_auto: true` to let a Linux build try kernel WireGuard at startup. Setup checks the running kernel's WireGuard, namespace and nftables support using the server's effective permissions. Other operating systems use userspace in `auto` mode. Use `required` to require a successful kernel setup. [Performance qualification criteria](#metrics-and-performance)

The command-line flag overrides YAML mode. Backend, consent and eBPF changes require a restart. Established flows can reset on restart. Clients reconnect normally, and a persistent server WireGuard key keeps native client profiles usable across restarts. Remove `allow_auto` from YAML before starting older binaries with strict config parsing.

## Backend coverage

The startup choice applies to the legacy WireGuard device, including ordinary WireGuard peers, legacy native and alternate UDP, WSS, UDP relay and multipath. The adaptive device stays on the portable backend and owns its distinct peers, pinned endpoint identities and carrier negotiation. Both devices use the existing grant and destination checks. Same-lane carrier moves on the adaptive device keep that device and its TCP state. Replacing a device or its TCP/IP stack requires reconnecting.

| Option | Phase 6 disposition |
| --- | --- |
| Portable userspace | Default and fallback after verified cleanup. Covers every carrier. |
| Kernel WireGuard behind the encrypted UDP bridge | Independently selectable for evaluation. Keeps the common bind, relay roles and virtual listeners. The bridge adds socket, queue and copy costs. |
| Direct kernel-native UDP | Candidate only for a separate endpoint and disjoint peer ownership. The shared public UDP listener also carries ntwire control and relay data. |
| Kernel plus adaptive userspace | Parallel devices with independent peers on this server. Adaptive traffic and its socket state stay on their userspace device. |
| Kernel-assisted relay, splice and more invasive acceleration | Deferred until profiles establish a bottleneck. Relay work must stay on encrypted datagrams. Forwarding changes must preserve authorization, accounting and half-close. |

## Prerequisites and isolation

Use a Linux kernel with network namespaces, WireGuard and inet-family nftables. The process needs effective `CAP_SYS_ADMIN` for `unshare(CLONE_NEWNET)` and `CAP_NET_ADMIN` for private network configuration. Allow the namespace and netlink operations in the runtime's security policy. If a socket uses a privileged port, the process also needs permission to bind it, including for in-tunnel DNS on port 53. Rootless and restricted deployments can use the portable backend. The kernel backend reserves loopback and IPv6 link-local space for Linux networking, so choose a tunnel CIDR outside those ranges.

The server owns an anonymous network namespace with its own WireGuard device, loopback and nftables. It installs rules before activating the public packet bridge. The rules permit the tunnel service address and active TCP and UDP listeners plus IP control traffic to the service address. Tunnel forwarding is blocked. Existing Go handlers authorize each peer and destination and dial targets from the original namespace. No host routing, firewall or sysctl change is required. The namespace, sockets and optional eBPF links are released on teardown.

The encrypted bridge allows at most 4,096 mappings, including 512 pending endpoint mappings. Raw UDP traffic can hold up to 32 pending mappings per IPv4 address or IPv6 `/64`. Authentication and expiry free pending slots. The public UDP bind retains batched I/O and reports its effective socket buffers. The private bridge batches I/O and requests larger receive buffers per socket. Monitor bridge drops and socket errors when evaluating a busy deployment.

## Start with kernel WireGuard

The examples use `required` so startup reports the operation that failed if a prerequisite is missing. To verify backend selection, check that the `WireGuard data plane started` log reports `kernel` in the `backend` field, or read `ntwire_acceleration_info` on the configured metrics listener.

### Linux binary

Start the server under a service manager or account with the effective capabilities listed above.

```sh
ntwire-server --config /etc/ntwire/ntwire.yaml --acceleration=required
```

Restart with `--acceleration=off` and remove any service capabilities assigned solely for kernel mode to return to the portable backend.

### Docker CLI

Run from the repository root on a Docker engine backed by a compatible Linux kernel. Prepare `.local/ntwire-server/ntwire.yaml` with your server configuration and put any authorized public SSH keys under `.local/ntwire-server/keys/` when using `auth.authorized_keys_dir: /etc/ntwire/keys`. Set `network.advertised_endpoint` to the address and UDP port clients can reach. The port mappings below assume HTTPS listens on 8443 and WireGuard on 51820.

```sh
docker build -f deploy/docker/Dockerfile -t ntwire-server:local .

docker run -d --name ntwire-server \
  --user 0:0 \
  --cap-drop ALL --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  --publish 8443:8443/tcp --publish 51820:51820/udp \
  --mount "type=bind,source=$PWD/.local/ntwire-server,target=/etc/ntwire,readonly" \
  ntwire-server:local --config /etc/ntwire/ntwire.yaml --acceleration=required

docker logs ntwire-server
```

Attach the container to the Docker network where its configured tunnel targets are reachable, and publish any additional transport ports configured for external clients. For a stable TLS identity, configure `tls.cert_file` and `tls.key_file` on the read-only mount, or add a writable mount for `tls.state_dir`. Keep the TLS material and persistent WireGuard key readable by the UID used in each mode. For rollback, recreate the container with the same ports, network and storage, omit the root user and capability overrides, and pass `--acceleration=off`.

### Docker Compose

```sh
docker compose -f deploy/docker/docker-compose.yml \
  -f deploy/docker/compose-acceleration.yaml up --build -d
docker compose -f deploy/docker/docker-compose.yml \
  -f deploy/docker/compose-acceleration.yaml logs ntwire-server
```

To roll back, set `acceleration.mode: off` in the mounted server YAML and apply the base Compose file with `docker compose -f deploy/docker/docker-compose.yml up -d --force-recreate ntwire-server`. Keep the configuration and keys mounts.

### Kubernetes with Kustomize

Prepare the base configuration and authorized-key Secret in the target namespace. Use Linux nodes with WireGuard and nftables support. The overlay grants capabilities to the server container and uses `RuntimeDefault` seccomp. Confirm that the namespace admission policy and the node runtime allow the requested capabilities and network namespace creation. Keep the context and namespace consistent across the commands. [Base Kubernetes configuration](../deploy/k8s/README.md) · [Kubernetes security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

```sh
kubectl kustomize deploy/k8s-acceleration
kubectl apply -k deploy/k8s-acceleration
kubectl rollout status deployment/ntwire-server
kubectl logs deployment/ntwire-server
```

For deployments applied with this overlay, set `acceleration.mode: off` in the server YAML inside the ConfigMap and reapply the base with `kubectl apply -k deploy/k8s` to restore the portable server and base security context. Confirm the rollout and check the backend log. Retain the existing Service exposure and Secrets.

The Compose and Kustomize overlays pass `--acceleration=required`. To allow fallback on a Linux deployment, keep the kernel capabilities, use `--acceleration=auto` in place of that flag, and set `acceleration.allow_auto: true` in the server YAML.

### Kubernetes with Helm

Merge these values into the existing server values file for a Linux deployment. Keep the existing listeners, authentication, tunnels, Secret mounts and persistence settings. The chart passes the acceleration settings through `server.config` and renders the container security context from `securityContext`.

```yaml
component: server
server:
  config:
    acceleration:
      mode: required
securityContext:
  allowPrivilegeEscalation: true
  readOnlyRootFilesystem: true
  runAsNonRoot: false
  runAsUser: 0
  runAsGroup: 0
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop: [ALL]
    add: [SYS_ADMIN, NET_ADMIN, NET_BIND_SERVICE]
```

Apply with the existing `helm upgrade` command and check the rollout and server log. To roll back, restore the portable container security context and set `server.config.acceleration.mode: off` before upgrading with the same storage and Secrets. [Helm deployment](DEPLOYMENT.md#helm-chart)

## Metrics and performance

On the configured metrics listener, `ntwire_acceleration_info` reports mode and the legacy device backend. `operator_consent_required` means automatic kernel setup lacks explicit opt-in. `unsupported_platform` means the opted-in server is running on another operating system. `kernel_setup_failed` means Linux kernel setup failed and the server switched to userspace after cleanup. When the adaptive device is present, `ntwire_acceleration_plane_info{plane="adaptive",backend="userspace"}` reports its backend separately. Kernel mode also exposes health, WireGuard bytes, firewall drops and bridge mapping counts. Set `acceleration.ebpf: true` to enable optional TCX ingress and egress packet-size counters on the private WireGuard interface. It requires a kernel with TCX and permission to load and attach BPF, typically `CAP_BPF` and `CAP_NET_ADMIN` on modern kernels. An attachment failure appears in logs and `ntwire_acceleration_ebpf_info`. Collection includes aggregate sizes and directions.

Run the privileged fixture suite on an isolated test worker with:

```sh
NTWIRE_TEST_KERNEL=1 go test ./pkg/server
```

The privileged suite includes coexistence and peer isolation checks for legacy and adaptive flows, a killed server fixture followed by restart on the same UDP port with the configured WireGuard key, and teardown of live sockets. The manually dispatched Linux peer performance workflow runs these checks in a disposable network namespace. Run the restricted startup fixture separately with `NTWIRE_TEST_RESTRICTED=1` as an unprivileged Linux user.

For performance qualification, compare `off` and `required` on identical Linux hosts with eBPF initially disabled. Repeat matched direct UDP, UDP relay and WebSocket workloads at small-packet and bulk sizes. Capture end-to-end throughput and p95 latency plus total CPU per GiB, including kernel and softirq time. On a dedicated worker use host CPU accounting from `/proc/stat` with an idle baseline, a fixed client and target, and the same traffic and run duration for both modes. The qualification target is at least 15% more throughput or 15% lower CPU per GiB on direct UDP and no greater than a 5% throughput or p95 latency regression on each transport. Kernel selection at startup checks setup success. Use paired measurements to establish the benefit on target hardware. Evaluate UDP segmentation and receive coalescing separately.

The test harness exercises both backends through real ntwire clients and can also measure the Linux UDP socket features in isolation:

```sh
NTWIRE_TEST_KERNEL=1 go test ./pkg/server -run '^$' \
  -bench 'BenchmarkAcceleration(Tunnel|UDPOffloads)' -benchtime=5s -count=5
```

The tunnel benchmark reports bidirectional transfer throughput, p95 round-trip latency and machine-wide busy CPU ticks per GiB. Its CPU figure includes other processes, so use an isolated worker for comparisons. The UDP offload benchmark verifies datagram boundaries and coalesced receive metadata before timing.

The peer benchmark can evaluate each workload against the release margins while retaining raw JSON. Use a dedicated Linux worker and an absolute binary path.

```sh
go build -o /tmp/ntwire-bench-lab ./tests/performance/lab
for path in direct-udp udp-relay wss; do
  sudo python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
    --output "/tmp/ntwire-kernel-$path" --modes "$path" \
    --peer-netem 10 0 100 42 10 0 100 43 --peer-queue-packets 4096 \
    --compare-server-backends --require-kernel-qualification --require-progress \
    --workload mixed --connections 2 --warmup 10s --duration 30s --repeat 7
done
```

The case gate uses paired 95% bootstrap intervals for bulk goodput, interactive p95 and host CPU. Each p95 sample needs at least 30 measured responses. Busy CPU ticks include system, IRQ and softirq work. The runner subtracts the per-run idle rate and normalizes by delivered bidirectional bytes. A noisy idle subtraction, too few latency samples, unequal measurement stop reasons or an incomplete pair can make results inconclusive. Reproduce the full transport, native-client, hardware and deployment matrix before qualifying a release. The workflow smoke uses a single pair to check measurement and transport wiring.
