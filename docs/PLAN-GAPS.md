# Implementation gaps against PLAN.md

This is a code-backed snapshot of the difference between the roadmap in
[PLAN.md](../PLAN.md) and the current checkout. It is intentionally limited to
observable implementation, not a promise of delivery order.

## Implemented foundations

The repository already has the Go module and both command entry points,
Ed25519 key generation, OpenSSH/PEM private-key parsing through
`x/crypto/ssh`, canonical signing payloads, the versioned auth protocol, YAML
configuration validation, session-token storage, YAML grants, optional
webhook/exec authorization, and a configuration-file watcher. CI builds both
binaries for Linux, macOS, and Windows on amd64 and arm64; release packaging is
configured through GoReleaser.

## Missing or incomplete work

### Transport and forwarding

- [x] Userspace WireGuard/netstack on both client and server, backed by
  wireguard-go and gVisor netstack without an OS network interface.
- [x] Server UDP listener, ephemeral WireGuard peer lifecycle, tunnel-IP
  allocation, allowed-IP enforcement, and peer removal on expiry/revocation.
- [x] Server TCP proxy/virtual-port listeners to configured targets.
- [x] Client local `127.0.0.1` listeners, ephemeral port selection or repeated
  `--port name=port` mappings, and forwarding through the data plane.
- [x] WireGuard-over-WebSocket transport at `/v1/wg`, token-gated per session;
  clients can select it with `connect --websocket` where UDP is blocked.
- [x] TLS serving with configured certificates or an in-memory self-signed
  certificate at boot.

### Client experience

- [x] A persistent `connect` command that starts local listeners and closes the
  session on Ctrl-C.
- [x] `status` and `disconnect` commands, automatic renewal with exponential
  retry, and re-authentication using the existing WireGuard peer after an
  expired session. The local runtime file contains no secret material.
- [x] TOFU certificate pinning in `~/.nwire/known_servers`, plus `--ca` and
  explicitly opt-in `--insecure`.
- [x] Persistent client configuration at `~/.nwire/config.yaml`, with
  command-line overrides including `--port`, `--no-browser`, and
  `--collect-exec`.
- [x] Built-in username collection and a size-capped JSON `ExecCollector`.
- [x] A loopback-only connection-status web UI, protected by a random URL
  token and served for the lifetime of `connect`.

### Server lifecycle and authorization

- [x] Enforcement of `auth.max_sessions_per_key`.
- [x] A background session reaper with WireGuard peer cleanup.
- [x] Key-directory watching and termination of sessions whose keys are
  removed; configuration reload re-evaluates live YAML grants.
- [x] Reload semantics explicitly apply all safe live authorization, grant,
  endpoint, TTL, and rate-limit configuration; listener, TLS, and CIDR values
  remain restart-only because changing a live WireGuard device is unsafe.
- [x] Structured audit records for successful auth and session lifecycle.
- [x] Auth rate limiting per source address.
- [x] The authorizer contract now includes `session_id` and `risk_score`.

### Deployment

- [x] A Docker Compose example with a target service and repository-root build
  context.
- [x] Kubernetes base resources now mount configuration and keys and expose
  UDP alongside HTTPS, with ConfigMap and NetworkPolicy examples.
- [x] Documented Docker Compose and Kubernetes deployment paths, including
  non-root image, configuration/key mounts, TLS behavior, HTTPS and UDP ports.

### Testing and quality gates

- [x] Focused unit tests cover SSH signing/parsing, authorizer behavior,
  session lifecycle, client TLS pins, protocol payloads, and transport frames.
- [x] A fuzz target protects canonical protocol payload construction.
- [x] In-process WebSocket transport round-trip coverage is included (it skips
  only in sandboxes that prohibit loopback listeners).
- [x] Docker Compose and Kubernetes manifests provide the documented smoke
  path; run them in an environment that permits containers and loopback UDP.
- [x] TLS/TOFU, authorization-deny, key-revocation, and forwarding behavior
  are covered by focused unit tests and the documented deployment smoke path.

## Documentation status

The README, protocol reference, and security notes document the implemented
control-plane behavior and explicitly mark the items above as unavailable. The
roadmap remains [PLAN.md](../PLAN.md); update this gap list when implementation
changes make an item materially complete.
