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

- [ ] Userspace WireGuard/netstack on either client or server. `pkg/wgnet` and
  `pkg/wstransport` have no implementation, and the Go module has no WireGuard,
  gVisor, or WebSocket dependencies.
- [ ] Server UDP listener, ephemeral WireGuard peer lifecycle, tunnel-IP
  allocation, allowed-IP enforcement, and peer removal on expiry/revocation.
- [ ] Server TCP proxy/virtual-port listeners to configured targets.
- [ ] Client local `127.0.0.1` listeners, port selection or `--port` mapping,
  and forwarding through the data plane.
- [ ] WireGuard-over-WebSocket fallback and any `/v1/wg` endpoint.
- [ ] Actual TLS serving, self-signed certificate generation, or client TLS
  verification. The server calls `http.ListenAndServe`; `tls.cert_file` and
  `tls.key_file` are currently unused.

### Client experience

- [ ] A real `connect` command. It currently executes the same one-shot grant
  listing path as `list`.
- [ ] `status`, disconnect UX, automatic renewal, reconnect/backoff, or a
  persistent client process.
- [ ] TOFU certificate pinning, `known_servers`, `--ca`, and `--insecure`.
- [ ] Persistent client configuration, `--port`, `--no-browser`, and
  `--collect-exec` command-line options.
- [ ] Built-in username collection and wired-in extensible collectors. The
  `Collector` and `ExecCollector` types exist, but no collector command or
  execution path is implemented.
- [ ] A served connection-status web UI. Static assets are embedded, but no
  route starts or uses them.

### Server lifecycle and authorization

- [ ] Enforcement of `auth.max_sessions_per_key`; the field is parsed but not
  used.
- [ ] A background session reaper and cleanup side effects. Expired sessions
  are removed only when a token is read.
- [ ] Key-directory watching, SIGHUP reload, and safe handling of key changes.
  The watcher observes only the parent directory of the YAML file.
- [ ] Immediate re-evaluation or termination of live sessions after config or
  ACL changes. Reload updates future authorization only.
- [ ] Reloadable network semantics beyond the existing deliberate preservation
  of listener, TLS, and tunnel CIDR fields.
- [ ] Structured audit logging for all auth attempts, session lifecycle, and
  tunnel connections. Current logging is limited to selected server events.
- [ ] Auth rate limiting per source address.
- [ ] The plan's full authorizer contract: the implementation supports the
  basic allow/narrow/shorten-TTL result, but does not supply a session ID to
  the hook and does not use a risk score.

### Deployment

- [ ] A runnable Docker Compose example with a target service and a verified
  repository-root build context. The current Compose file is located under
  `deploy/docker` and its `build: .` context does not contain the Go module
  files required by its Dockerfile.
- [ ] Complete Kubernetes deployment resources: mounted configuration and
  authorized keys, UDP service, ConfigMap/Secret examples, NetworkPolicy, and
  a verified in-cluster target example. Current manifests define only a basic
  Deployment and TCP Service.
- [ ] A documented end-to-end production deployment. The Dockerfile itself is
  a non-root distroless server build, but it cannot provide the planned data
  plane yet.

### Testing and quality gates

- [ ] Unit coverage for SSH key parsing/signing, configuration reload,
  authorizer behavior, session lifecycle, and server endpoints. The only test
  file currently covers canonical signing-payload determinism.
- [ ] Fuzz tests for protocol parsers.
- [ ] In-process integration tests for UDP and forced WebSocket paths.
- [ ] End-to-end Docker Compose and Kubernetes smoke tests.
- [ ] Verified TLS/TOFU, authorization-deny, key-revocation, and forwarding
  scenarios described in the plan.

## Documentation status

The README, protocol reference, and security notes document the implemented
control-plane behavior and explicitly mark the items above as unavailable. The
roadmap remains [PLAN.md](../PLAN.md); update this gap list when implementation
changes make an item materially complete.
