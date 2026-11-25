# Linux server acceleration

ntwire-server can use Linux kernel WireGuard and kernel TCP/IP sockets for in-tunnel listeners. The public bind still handles ntwire UDP control packets, WebSocket, UDP relay, multipath and the alternate UDP port. Public endpoints, WireGuard profiles and session authorization work the same way across backend selections.

```yaml
acceleration:
  mode: auto
  ebpf: false
```

| Mode | Behavior |
| --- | --- |
| `auto` | Default. Release qualification controls automatic selection. This release selects userspace while the kernel backend is being evaluated. After qualification, eligible Linux processes try kernel setup and fall back to userspace after successful cleanup if a prerequisite fails. |
| `off` | Use the portable backend and skip Linux acceleration setup, even as root. |
| `required` | Use the Linux kernel backend or fail startup with the operation that failed. Use this mode to validate a deployment and measure performance. |

Use `--acceleration=required` to evaluate the backend without editing YAML. To roll back, restart with `--acceleration=off`. The command-line flag overrides YAML. Backend and eBPF changes require a restart. Clients reconnect normally, and a persistent server WireGuard key keeps native client profiles usable across restarts.

## Prerequisites and isolation

Use a Linux kernel with network namespaces, WireGuard and inet-family nftables. The process needs effective `CAP_SYS_ADMIN` for `unshare(CLONE_NEWNET)` and `CAP_NET_ADMIN` for private network configuration. Allow the namespace and netlink operations in the runtime's security policy. If a socket uses a privileged port, the process also needs permission to bind it, including for in-tunnel DNS on port 53. Rootless and restricted deployments can use the portable backend. The kernel backend reserves loopback and IPv6 link-local space for Linux networking, so choose a tunnel CIDR outside those ranges.

The server owns an anonymous network namespace with its own WireGuard device, loopback and nftables. It installs rules before activating the public packet bridge. The rules permit the tunnel service address and active TCP and UDP listeners plus IP control traffic to the service address. Tunnel forwarding is blocked. Existing Go handlers authorize each peer and destination and dial targets from the original namespace. No host routing, firewall or sysctl change is required. The namespace, sockets and optional eBPF links are released on teardown.

The encrypted bridge has a 4,096-mapping bound, including at most 512 pending endpoint mappings. The public UDP bind retains batched I/O and reports its effective socket buffers. The private bridge batches I/O and requests larger receive buffers per socket. Monitor bridge drops and socket errors when evaluating a busy deployment.

## Docker and Kubernetes

On a Linux host run the server with the permissions above, for example from a service manager with the relevant capability set. For Docker Compose, add `deploy/docker/compose-acceleration.yaml` after the existing file. With Kubernetes, use `deploy/k8s-acceleration` as a separate Kustomize overlay. Both examples use explicit `required` mode so a placement that cannot satisfy the prerequisites fails visibly. Docker's default seccomp profile was exercised with the example capabilities. The Kubernetes overlay sets `allowPrivilegeEscalation: true` because it requests `CAP_SYS_ADMIN`. Verify that the node's `RuntimeDefault` profile allows the namespace operation and that its Pod Security policy permits the capabilities. [Kubernetes security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

## Metrics and performance

On the configured metrics listener, `ntwire_acceleration_info` reports the requested mode, active backend and any reason for userspace selection. Kernel mode also exposes health, WireGuard bytes, firewall drops and bridge mapping counts. Set `acceleration.ebpf: true` to enable optional TCX ingress and egress packet-size counters on the private WireGuard interface. It requires a kernel with TCX and permission to load and attach BPF, typically `CAP_BPF` and `CAP_NET_ADMIN` on modern kernels. An attachment failure appears in logs and `ntwire_acceleration_ebpf_info`. Collection includes aggregate sizes and directions.

Run the privileged fixture suite on an isolated test worker with:

```sh
NTWIRE_TEST_KERNEL=1 go test ./pkg/server
```

For release qualification, compare `off` and `required` on identical Linux hosts with eBPF initially disabled. Repeat matched direct UDP, UDP relay and WebSocket workloads at small-packet and bulk sizes. Capture end-to-end throughput and p95 latency plus total CPU per GiB, including kernel and softirq time. On a dedicated worker use host CPU accounting from `/proc/stat` with an idle baseline, a fixed client and target, and the same traffic and run duration for both modes. Automatic selection requires at least 15% more throughput or 15% lower CPU per GiB on direct UDP and no greater than a 5% throughput or p95 latency regression on each transport. Evaluate UDP segmentation and receive coalescing separately. Qualify each before making it part of automatic tuning.

The test harness exercises both backends through real ntwire clients and can also measure the Linux UDP socket features in isolation:

```sh
NTWIRE_TEST_KERNEL=1 go test ./pkg/server -run '^$' \
  -bench 'BenchmarkAcceleration(Tunnel|UDPOffloads)' -benchtime=5s -count=5
```

The tunnel benchmark reports bidirectional transfer throughput, p95 round-trip latency and machine-wide busy CPU ticks per GiB. Its CPU figure includes other processes, so use an isolated worker for comparisons. The UDP offload benchmark verifies datagram boundaries and coalesced receive metadata before timing.
