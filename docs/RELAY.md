---
title: Relay Mode (NAT Traversal)
description: Guide to configuring ntwire-relay for servers behind NAT
type: guide
---

# Relay mode (NAT traversal)

Today's default topology is strictly one-directional: only `ntwire-server`
listens on a public network, and clients always dial in. A server behind NAT
or on a home/lab network with no inbound connectivity cannot be reached at
all — unless it dials out to an `ntwire-relay`:

```
ntwire-server (behind NAT, no inbound) --outbound--> ntwire-relay (public) <--inbound-- ntwire client
```

The relay never terminates the client's TLS session: it reads only the TLS
ClientHello's SNI to route the connection, then splices raw bytes to the
origin server over an authenticated, outbound-initiated connection. This is
safe because the client already pins the origin server's certificate by
SHA256 fingerprint with no hostname check (see
[SECURITY.md](SECURITY.md#the-relays-trust-model)) — the relay
cannot MITM the session even if compromised. It is trusted only for
availability, and for the client address it reports for rate limiting and
audit logging.

Relay mode is TCP-only: with no inbound UDP path available, WireGuard rides
the existing WebSocket fallback (`/v1/wg`) instead of the direct UDP
endpoint. `ntwire connect` detects this automatically — a server that
advertises no UDP endpoint but does advertise a WebSocket one is used over
WebSocket with no extra flag needed.

## Running a relay

Run `ntwire-relay --config path/to/ntwire-relay.yaml`; the default path is
`ntwire-relay.yaml`. Use `ntwire-relay --print-sample-config > ntwire-relay.yaml`
for a complete, commented template. A relay serves multiple tenants under one
wildcard DNS domain, each identified by a first DNS label:

```yaml
listen:
  public: ":443"          # raw TCP; client TLS is spliced through, never terminated here
  agents: ":8444"          # HTTPS endpoint ntwire-servers dial outbound to and register on
domain: relay.example.com # wildcard suffix; a server registered as "home" is reached at home.relay.example.com
registrations:
  - name: home
    public_key: "ssh-ed25519 AAAA... admin@laptop"
```

Point wildcard DNS (`*.relay.example.com`) at the host running `listen.public`,
and give each registered server its own key with `ntwire keygen -o relay_id_ed25519`.

The sample config also includes a `log:` section (text/json format, log
level); see [LOGGING.md](LOGGING.md) for the full reference.

## Pointing a server at a relay

On the server side, add a `relay:` block (see the full option list in
[CONFIGURATION.md](CONFIGURATION.md)) and leave
`listen.https` alone — it is simply never bound in relay mode:

```yaml
relay:
  enabled: true
  url: "wss://relay.example.com:8444"
  name: home                                    # must match a registrations[] entry on the relay
  identity_file: /etc/ntwire/relay_id_ed25519    # separate key from auth.authorized_keys_dir
  fingerprint: ""                                # SHA256:... pin of the relay's own cert; empty uses normal PKI
network:
  advertised_endpoint: ""                        # must stay empty when relay.enabled is true
```

Clients connect exactly as before, using the wildcard hostname:

```sh
ntwire connect https://home.relay.example.com
```

## Trust model

See [SECURITY.md#the-relays-trust-model](SECURITY.md#the-relays-trust-model)
for what a malicious or compromised relay can and cannot do. In short: the
relay is untrusted for confidentiality and integrity, and trusted only for
availability and for the client addresses it reports.

## Protocol details

The wire protocol between an `ntwire-server` and an `ntwire-relay`
(registration, `RelayOpen`, and data-connection splicing) is specified in
[PROTOCOL.md](PROTOCOL.md#relay-registration-protocol-ntwire-server-ntwire-relay).

## Docker Compose example

`deploy/docker/Dockerfile.relay` builds the relay image, and
`deploy/docker/ntwire-relay.yaml` is a runnable sample config — see
[DEPLOYMENT.md](DEPLOYMENT.md) for container and Kubernetes deployment.
