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

By default WireGuard rides the WebSocket fallback (`/v1/wg`) in relay mode,
since there is no inbound UDP path to the server's real address. `ntwire
connect` detects this automatically — a server that advertises no UDP
endpoint but does advertise a WebSocket one is used over WebSocket with no
extra flag needed. A relayed server can optionally also offer clients an
opportunistic upgrade to a direct UDP path that bypasses the relay's data
plane entirely — see [below](#opportunistic-direct-udp-upgrade).

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

`listen.reflect` is left out here deliberately: it is optional, off by default,
and only matters to a server that opts into the direct-UDP upgrade — see
[below](#opportunistic-direct-udp-upgrade).

Point wildcard DNS (`*.relay.example.com`) at the host running `listen.public`,
and give each registered server its own key. On that server, run
`ntwire-server -generate-relay-key relay_id_ed25519`: it creates the key pair
and prints the `public_key` line to add above, plus the matching `relay:`
block described next.

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

## Opportunistic direct-UDP upgrade

Relaying WireGuard over `/v1/wg`'s WebSocket fallback works everywhere, but it
means every packet crosses the relay twice (client→relay, relay→server) over
TCP, carrying TLS and WebSocket framing on top of WireGuard's own encryption.
A relayed server can instead let clients try to punch a direct UDP path
straight to it — bypassing the relay's data plane, and the TCP/TLS/WebSocket
overhead, entirely. The control plane (auth, session renewal) still goes
through the relay either way; only the WireGuard data plane can escape it.

This only works against a NAT that maps a given local UDP port to the same
public port regardless of destination (true of most home/office routers). A
symmetric NAT breaks it, silently: the client keeps using the WebSocket
fallback and nothing needs configuring differently for that case.

Both sides must opt in — either alone does nothing:

```yaml
# ntwire-relay.yaml
listen:
  reflect: ":3480"        # UDP address-reflection endpoint; empty (default) disables it
```

```yaml
# ntwire-server.yaml
relay:
  enabled: true
  advertise_direct: true  # default false
```

With both set, the server periodically asks the relay's reflector what public
UDP address it is currently mapped to, and caches the answer. An
authenticated client asks the server for that address (`POST /v1/punch`),
reflects its own address off the same relay endpoint, and both sides fire a
short burst of packets at each other to open their NAT mappings before the
client's real WireGuard handshake tries the direct path. If it doesn't
connect within a couple of seconds — most commonly because of a symmetric
NAT on one side — the client just keeps using WebSocket, and retries the
whole exchange periodically in case network conditions change. If it does
connect, WireGuard's own connection migration keeps using it, with a
background health check that reverts back to WebSocket if the direct path
later goes stale (a NAT mapping expiring, a network change).

**This trades away part of what relay mode is otherwise for.** A relayed
server's whole appeal to many operators is that its real network address
never has to be exposed to anyone — the relay is the only thing that sees it.
Turning on `advertise_direct` means every authenticated client learns that
address too (and the relay's reflector logs it, for whoever can read the
relay's logs). That's why it defaults to off and has to be opted into
explicitly on both the relay and the server, not inferred from `relay.enabled`
alone.

One operational note: `listen.wireguard` needs to stay reachable on the
network when `advertise_direct` is on — it's the same UDP socket the server
uses to self-reflect and to receive a punched-through direct connection, so
the older advice to bind it to `127.0.0.1:0` in relay mode (it used to go
unused there) no longer applies once this is enabled.

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
