---
title: Relay Mode (NAT Traversal)
description: Guide to configuring ntwire-relay for servers behind NAT
type: guide
---

# Relay mode (NAT traversal)

## Kubernetes Service discovery

`ntwire-relay` can optionally discover tenant origins from Kubernetes
Services. It is disabled unless `kubernetes.enabled: true`; existing relay
registrations and outbound NAT traversal require no changes.

```
Internet ── ALB (HTTPS/WSS) ─┐
Internet ── NLB (UDP) ───────┼── ntwire-relay ── Kubernetes registry
                             │        ├─ customer-a/ntwire-server
                             │        └─ customer-b/ntwire-server
```

The relay watches Services (and Namespaces when a namespace selector is
configured) through Kubernetes shared informers. It does not poll. A selected
Service must match `kubernetes.service.selector`, carry
`ntwire.io/relay-enabled: "true"`, have the hostname annotation, and expose
the configured named port. It is reached through Service DNS, never a cached
Pod IP. The public listener still only reads ClientHello SNI and splices raw
TLS bytes; it does not terminate client TLS.

```yaml
kubernetes:
  enabled: true
  namespaces: {mode: selected, names: [customer-a, customer-b]}
  # Or: {mode: all, selector: "ntwire.io/enabled=true"}
  service: {selector: "app.kubernetes.io/name=ntwire-server", port_name: ntwire-relay}
  registration: {hostname_annotation: ntwire.io/hostname, tenant_annotation: ntwire.io/tenant}
```

Registration precedence is: live authenticated outbound registration, then
an unambiguous Kubernetes Service, then the legacy static registration state.
If two Services claim the same hostname, that hostname fails closed until the
conflict is removed; the relay logs conflict events and never picks one. An
API/watch interruption retains already accepted Service entries and the
informer reconnects with Kubernetes resource versions. Explicit deletion
removes the route promptly. A Service with no ready Pods remains registered
but connection attempts fail normally until its endpoints return.

Kubernetes discovery provides TCP TLS-passthrough routing. It does not turn a
Service into an authenticated outbound relay agent, so native WireGuard UDP
and UDP-relay allocation continue to require the existing live outbound
server registration and capability negotiation. No WireGuard protocol changes.

See `deploy/k8s/relay-discovery-rbac.yaml` and
`deploy/k8s/relay-discovery-example.yaml` for minimal RBAC and a generic
Kubernetes/EKS-shaped deployment.

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
extra flag needed. If the relay offers it, the client tries an opportunistic
upgrade to native UDP that stays relayed — see
[below](#relay-mediated-udp-forwarding) — before ever attempting the further
opportunistic upgrade to a fully direct UDP path that bypasses the relay's
data plane entirely — see
[below](#opportunistic-direct-udp-upgrade).

## Multipath relay transport

Relay-mode servers that support it advertise the `multipath` capability. When
both peers support it, WSS stays live for the session while UDP-relay and
direct UDP become candidates for one stable logical WireGuard endpoint. This
prevents native endpoint roaming from selecting whichever duplicate packet
arrived most recently. Handshake and control packets use the selected primary;
only encrypted WireGuard transport packets may also go to one healthy
alternate.

`multipath-v1` is negotiated in the authenticated client/server response. The
server also sends its version and supported transport capabilities when it
registers with the relay; the relay returns its own version/capabilities. An
older peer omits the capability and stays on the legacy transport rather than
being placed on a stable endpoint it cannot route.

Candidates are probed roughly once a second, over the candidate's own
transport (a tiny fixed-size `FramePathProbe`/`FramePathAck` exchange,
answered immediately by the peer). A candidate starts unhealthy the moment
it's registered and only becomes eligible for selection once its first probe
is acknowledged -- bounding a freshly registered candidate's unusable window
to roughly one round trip, since registration itself fires an immediate,
out-of-band probe rather than waiting for the next tick. The primary is the
healthy path with the best RTT/loss score. A second copy is used only after
at least 5% rolling probe loss on the primary, or when its p95 latency is
above 150 ms and at least 50 ms worse than the alternate. Three missed probes
make a candidate unhealthy, but it remains registered and is re-probed so
recovery does not require a session reconnect. Receivers suppress repeated
type-4 WireGuard transport packets by receiver index and counter in a short
bounded cache; handshake packets are never suppressed.

The server independently schedules its return traffic through the same
candidate set, including when it is connected to an `ntwire-relay`. Operators
can set `transport.force: wss`, `udp-relay`, or `direct-udp` in
`ntwire-server` configuration to prefer one path for every multipath peer;
if that candidate is unhealthy or unavailable, the scheduler safely falls
back to the best healthy path. `transport.force: auto` is the default.

Probe/ack controls have fixed-size payloads and invalid or oversized frames
are ignored. There are no tuning options in v1. A server without `multipath`
uses the original WSS → UDP-relay → direct-UDP endpoint upgrade ladder.

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
    listen: ":8443"       # optional dedicated TCP public listener for this tenant; bypasses wildcard DNS/SNI
```

`listen.reflect` is left out here deliberately: it is optional, off by default,
and only matters to a server that opts into the direct-UDP upgrade — see
[below](#opportunistic-direct-udp-upgrade).

Point wildcard DNS (`*.relay.example.com`) at the host running `listen.public`,
and give each registered server its own key. Alternatively, if `registrations[].listen`
is configured for a tenant, clients can dial that dedicated port directly (e.g.
`https://relay.example.com:8443` or `https://<relay-ip>:8443`) without requiring
wildcard DNS or a specific SNI subdomain.

On that server, run
`ntwire-server -generate-relay-key relay_id_ed25519`: it creates the key pair
and prints the `public_key` line to add above, plus the matching `relay:`
block described next.

The sample config also includes a `log:` section (text/json format, log
level); see [LOGGING.md](LOGGING.md) for the full reference.

## Pointing a server at a relay

On the server side, add a `relay:` block (see the full option list in
[CONFIGURATION.md](CONFIGURATION.md)). By default, `listen.https` is never
bound in relay mode:

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

### Also accepting direct ntwire clients

Set `relay.direct_clients: true` to serve the same authenticated HTTPS/WebSocket
handler on `listen.https` as well as through the relay. This is opt-in: it
exposes an inbound listener, and the configured TLS certificate must cover the
direct hostname.

```yaml
listen:
  https: ":8443"
relay:
  enabled: true
  direct_clients: true
```

Relay clients continue to use the relay tenant hostname; direct clients use
the server's own reachable hostname and port. This only adds direct HTTPS/WSS
ingress. Direct UDP promotion still requires `relay.advertise_direct: true`
and a reachable WireGuard UDP path.

## High availability and recovery

`relay.url` remains the single-relay configuration. To run an active-active
relay pool, replace it with `relay.endpoints`; the server registers with every
member and accepts dial-backs from any healthy member:

```yaml
relay:
  enabled: true
  name: home
  identity_file: /etc/ntwire/relay_id_ed25519
  endpoints:
    - url: "wss://relay-a.internal.example:8444"
      fingerprint: "SHA256:..."
    - url: "wss://relay-b.internal.example:8444"
      fingerprint: "SHA256:..."
```

All pool members must carry the same `registrations` entry for the tenant and
serve the same wildcard client domain (`home.relay.example.com` in this
guide). Publish multiple A/AAAA records for that hostname, or place replicas
behind an L4 load balancer that preserves the TLS ClientHello. The client
races resolved addresses, keeps the first healthy route, and re-resolves on a
failure; no new `ntwire connect` syntax is needed.

The recovery contract is deliberately practical: local tunnel listeners and
the WireGuard identity remain in place, and new requests recover through a
healthy relay automatically. A relay/server/network failure can reset an
already-open TCP stream; callers must retry idempotent operations. The client
first falls back between direct UDP, UDP via relay, and WebSocket relay, then
re-authenticates through another resolved relay address when necessary.

### Kubernetes relay replicas

Run relay replicas as separate failure domains (different nodes/zones where
available), each with the same tenant registrations and a reachable
`listen.agents` service. Expose `listen.public` through a TCP/L4 Service or
LoadBalancer, never a TLS-terminating HTTP Ingress: the relay must inspect and
splice the original ClientHello. Publish the shared wildcard DNS name to all
replicas/load-balancer addresses. Give `listen.udp_relay`, `listen.reflect`,
and the UDP relay port range their own UDP Service/L4 rules on every replica;
UDP forwarding sessions are replica-local and clients reallocate after a
replica loss.

### Kubernetes server replicas

Do not scale one relay tenant by simply running two independent
`ntwire-server` pods with the same relay name: registrations are
last-writer-wins and each pod has separate sessions, WireGuard state, and
tunnel IP allocation. Use one active server replica per tenant today. A
future active-active server deployment requires shared session/IP ownership
and deterministic WireGuard peer routing; until then use Kubernetes restart,
anti-affinity, persistent identity/certificate storage, and a PodDisruption-
Budget to improve availability of the single active server.

## Native WireGuard UDP endpoints

An ordinary official WireGuard client cannot use ntwire's token-bound
per-session UDP relay. Configure a dedicated public UDP listener for a tenant
instead:

```yaml
registrations:
  - name: home
    public_key: "ssh-ed25519 ..."
    native_wireguard:
      listen: ":51821" # or relay.example.com:51821
```

The registered `ntwire-server` receives an authenticated, short-lived relay
association token over its existing control connection and sends it from the
same userspace WireGuard UDP socket. The relay then forwards opaque WireGuard
datagrams only between that associated server address and clients of this one
tenant endpoint. It parses packet type and public receiver indices solely to
route handshake/transport responses to multiple clients; it has no WireGuard
private key and cannot decrypt payloads. Association is invalidated when the
server registration is replaced or disconnects. This listener is opt-in and
does not alter `listen.udp_relay` or its token-binding security model.

`native_wireguard.listen` accepts a numeric local interface or a hostname.
For a hostname, the relay resolves it at startup and binds the resulting IP
address; use this when the relay should bind one explicit interface. A
wildcard listener such as `":51821"` remains supported: its association is
advertised to the server as `home.<domain>:51821`, never as `0.0.0.0` or
`[::]`. Ensure that this tenant hostname resolves to the relay for both
ordinary clients and the registered server.

This tier is opt-in on both sides: the relay needs `registrations[].native_wireguard.listen`
above, and the server needs `native_wireguard.enabled: true` (see
[NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md)) — the association frame is never
sent otherwise. An official client's profile changes in exactly one field
from the direct-listener case: `Endpoint` becomes the relay's wildcard
hostname and this tenant's `native_wireguard.listen` port, e.g.
`home.relay.example.com:51821`. `PublicKey` still pins the *server's*
WireGuard key, unchanged — the relay only ever forwards opaque datagrams and
never holds a WireGuard key of its own. `Address` and `AllowedIPs` still come
from `network.tunnel_cidr` and the peer's `tunnel_ip` on the server, exactly
as in the direct case:

```ini
[Interface]
PrivateKey = <client private key>
Address = 100.64.0.10/32
[Peer]
PublicKey = <server public key>
Endpoint = home.relay.example.com:51821
AllowedIPs = 100.64.0.0/16
PersistentKeepalive = 25
```

Because this listener is selected by UDP port rather than by the TLS SNI
`listen.public` uses for `wss://name.relay.example.com`, one relay port
serves exactly one tenant — hence the duplicate-listener rejection in the
relay's config validation.

## Relay-mediated UDP forwarding

Relaying WireGuard over `/v1/wg`'s WebSocket fallback works everywhere, but it
means every packet crosses the relay twice (client→relay, relay→server) over
TCP, carrying TLS and WebSocket framing on top of WireGuard's own encryption.
A relay can offer a middle option: it forwards WireGuard's own UDP datagrams
directly between client and server, without the TCP/TLS/WebSocket overhead —
but, unlike the fully direct upgrade described
[below](#opportunistic-direct-udp-upgrade), the relay stays in the data path
the whole time. The server's real address is never revealed to a client, so
this carries none of that upgrade's privacy trade-off — a registered server
uses it automatically whenever the relay offers it, with nothing to configure
on the server side:

```yaml
# ntwire-relay.yaml
listen:
  udp_relay: ":3481"             # shared, client-facing UDP address; empty (default) disables the tier
  udp_relay_ports: "20000-20063" # inclusive range of per-session server-leg ports, bound eagerly at startup
limits:
  udp_relay_idle_timeout: 60s              # default; reclaims a session no client/server has kept alive
  max_udp_relay_sessions_per_server: 64     # default; independent of the pool-wide port count
```

The relay allocates one dedicated UDP port from `udp_relay_ports` per active
session (TURN-style), so a firewall in front of the relay only ever needs a
static rule for that range — never a rule per session. Size the range to the
number of concurrent sessions you actually expect, not maximally: every port
in it is bound (and costs a listening goroutine plus a firewall-rule slot) the
moment the relay starts, whether or not a session ever uses it. The
client-facing side is different: every client relay-wide shares the single
`listen.udp_relay` socket, since the relay demultiplexes inbound client
datagrams by a token-locked source address once a session is bound, not by
port — a client's NAT only ever needs to reach one address.

A session is only forwarded once *both* the server's and the client's leg
have completed a token-verified bind; a datagram addressed to a half-bound
session is dropped, never buffered. This is a symmetric pair-relay (a
TURN-style permission model), not an open reflector: nothing is forwarded
anywhere until both ends have proven they hold the same session token. Each
side resends its bind periodically as a keepalive, refreshing both its own
NAT mapping and the relay's idle timer for the session; `udp_relay_idle_timeout`
is the backstop that reclaims a session whose teardown message never arrives
(a crash, or a control-connection drop with no reconnect).

Because this tier never exposes the server's real address, it needs no
`advertise_direct`-style opt-in flag on the server — see that option's doc
comment in [CONFIGURATION.md](CONFIGURATION.md) for the asymmetry versus the
fully direct upgrade below. A client always tries this tier first (if the
relay offers it) and only escalates further to the fully direct path if
`advertise_direct` is also on and that path turns out healthier; falling back
lands on whichever of these two rungs is still warm, not always straight back
to WebSocket.

## Opportunistic direct-UDP upgrade

A relayed server can also let clients try to punch a direct UDP path straight
to it — bypassing the relay's data plane, not just the TCP/TLS/WebSocket
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

## Deployment examples

### Docker Compose

`deploy/docker/Dockerfile.relay` builds the relay image, and
`deploy/docker/ntwire-relay.yaml` is a runnable sample config — see
[DEPLOYMENT.md](DEPLOYMENT.md) for container and Kubernetes deployment.

```sh
# Run relay with Docker Compose
docker compose -f deploy/docker/docker-compose.yml up --build
```

### Kubernetes

To run and inspect `ntwire-relay` in Kubernetes with `kubectl`:

```sh
# Run an ad-hoc relay pod
kubectl run ntwire-relay --image=nmaguiar/ntwire-relay:build --port=8444

# Check relay pod status and logs
kubectl get pods -l app=ntwire-relay
kubectl logs -f deployment/ntwire-relay
```
