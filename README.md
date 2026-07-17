# nwire

nwire is a Go control-plane bootstrap for a WireGuard multi-tunnel client and
server. It currently provides the versioned, signed SSH-key authentication
protocol, replay protection, YAML grant configuration, session lifecycle, and
an intentionally small server binary. The userspace WireGuard/netstack and TCP
forwarding milestones described in [PLAN.md](PLAN.md) are not yet present.

## Build

```sh
go test ./...
go build ./cmd/...
./nwire keygen -o ~/.nwire/id_ed25519
```

Configure `deploy/docker/nwire.yaml`, put authorized public keys in its keys
directory, then start `nwire-server --config deploy/docker/nwire.yaml`.
