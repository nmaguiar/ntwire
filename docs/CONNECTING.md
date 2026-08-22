---
title: Connecting to ntwire
description: Step-by-step setup for every client/endpoint combination — ntwire and official WireGuard clients, against a direct ntwire-server or one behind ntwire-relay
type: guide
---

# Connecting to ntwire

There are two kinds of client (the `ntwire` client, and an unmodified
official WireGuard client) and two kinds of endpoint (`ntwire-server`
directly, or `ntwire-server` reached through `ntwire-relay`), plus the
server-to-relay registration that makes the relayed cases possible:

| # | Path | Client config changes | Server config changes |
| --- | --- | --- | --- |
| [1](#1-ntwire-client--ntwire-server-direct) | `ntwire` → `ntwire-server` | none | `auth.authorized_keys_dir` or `auth.oidc.issuers` |
| [2](#2-ntwire-client--ntwire-relay-server-behind-nat) | `ntwire` → `ntwire-relay` | none — same `ntwire connect URL` | `relay:` block (see [5](#5-ntwire-server--ntwire-relay-registering-as-a-tenant)) |
| [3](#3-official-wireguard-client--ntwire-server-direct) | official WireGuard → `ntwire-server` | ordinary `.conf`/profile import | `native_wireguard:` block |
| [4](#4-official-wireguard-client--ntwire-relay-server-behind-nat) | official WireGuard → `ntwire-relay` | same profile, different `Endpoint` | `native_wireguard:` + relay's `native_wireguard.listen` |
| [5](#5-ntwire-server--ntwire-relay-registering-as-a-tenant) | `ntwire-server` → `ntwire-relay` | n/a | `relay:` block |

The `ntwire` client always uses ntwire's own authenticated, bearer-token
protocol (SSH-key or OIDC login, session TTLs, per-tunnel grants). An
official WireGuard client never touches that protocol at all — it's admitted
as a static cryptographic peer in the same userspace WireGuard device (see
[NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md)). Whether either of them goes
through `ntwire-relay` is orthogonal to which kind of client it is: the
relay only ever forwards opaque bytes, and never terminates the client's TLS
or WireGuard session (see [SECURITY.md#the-relays-trust-model](SECURITY.md#the-relays-trust-model)).

## Generating a WireGuard key pair for an official client

**This whole section is optional**, and only relevant to scenarios
[3](#3-official-wireguard-client--ntwire-server-direct) and
[4](#4-official-wireguard-client--ntwire-relay-server-behind-nat) — connecting
an *unmodified official WireGuard client*. If you're able to use the `ntwire`
client instead (scenarios [1](#1-ntwire-client--ntwire-server-direct)/[2](#2-ntwire-client--ntwire-relay-server-behind-nat)),
that remains the better default: `ntwire keygen` needs no WireGuard tooling
at all, and you get session auth, grants, TTLs, and revocation instead of a
static peer with no expiry. Reach for native WireGuard peers only when the
device genuinely needs the official app (e.g. it's the platform's own VPN UI,
or another tool already expects a plain WireGuard profile).

A key pair for this path can come from any of three places — none of them
`ntwire-server`'s own identity, and the private half should never be stored
anywhere but the client:

**`ntwire-server` itself**, so you don't need `wireguard-tools` installed
anywhere:

```sh
ntwire-server -generate-wireguard-key client_wg
```

This writes `client_wg` (private key, mode `0600`) and `client_wg.pub`, and
prints the matching `native_wireguard.peers[]` entry to add. It's a pure
convenience wrapper around the same key generation the server already uses
for its own `network.wireguard_private_key_file` — the server never sees or
stores a client's private key beyond writing this one file, which you then
move to the client and delete here.

**Command line** (Linux, macOS, or any host with `wireguard-tools`):

```sh
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

`client_private.key` goes in the profile's `[Interface] PrivateKey`, below;
send only the contents of `client_public.key` to the ntwire-server
administrator — never the private key.

**Official GUI apps** (iOS, macOS, Windows, Android): tapping "Add a tunnel" /
"+" to create a new, empty tunnel generates the key pair for you and shows
"Public key" in the tunnel's interface settings — copy that value to send to
the administrator instead of using either command above. The corresponding
`PrivateKey` stays inside the app's own storage and is never displayed again
after the tunnel is created, so keep the key pair (or the exported `.conf`)
if you'll need to reconfigure the same tunnel later.

Whichever you use, the resulting public key is what goes into the server's
`native_wireguard.peers[].public_key` in the scenarios below — the server
never generates or holds a client's *private* key beyond the convenience file
above, and that file is meant to be deleted from the server once transferred.

## 1. `ntwire` client → `ntwire-server` (direct)

1. Generate a key and send the public half to the server administrator:
   ```sh
   ntwire keygen
   ```
   This writes `~/.ntwire/id_ed25519` and `~/.ntwire/id_ed25519.pub`.
2. The administrator adds your `.pub` file to `auth.authorized_keys_dir` (or
   grants your OIDC identity — see [OIDC-SETUP.md](OIDC-SETUP.md) — if the
   server uses SSO instead).
3. Connect:
   ```sh
   ntwire connect https://server.example:8443
   ```
   The first connection to a self-signed server prompts you to confirm and
   store its certificate fingerprint (TOFU); see
   [SECURITY.md#tls-trust-model-and-avoiding-repeated-re-trust-prompts](SECURITY.md#tls-trust-model-and-avoiding-repeated-re-trust-prompts).
   Every later `ntwire connect` (no URL needed once cached) reuses it.
4. Check tunnels and status:
   ```sh
   ntwire status
   ```
   or open the token-protected status URL `connect` prints.

Full flag reference: [../README.md#client-usage](../README.md#client-usage).
Server-side tunnel/auth options: [CONFIGURATION.md](CONFIGURATION.md).

## 2. `ntwire` client → `ntwire-relay` (server behind NAT)

Nothing changes on the client side beyond the URL — the relay is
transparent to it:

```sh
ntwire connect https://home.relay.example.com
```

`home` here is the tenant name the server administrator registered on the
relay (see [5](#5-ntwire-server--ntwire-relay-registering-as-a-tenant)); the
relay serves every tenant under one wildcard domain, so the first DNS label
selects which `ntwire-server` you reach.

`ntwire connect` auto-detects relay mode: a server with no advertised UDP
endpoint but a WebSocket one is used over WebSocket automatically, with no
extra flag. If the relay offers relay-mediated or direct UDP, the client
upgrades to it opportunistically once connected — see
[RELAY.md](RELAY.md#relay-mediated-udp-forwarding) and
[RELAY.md](RELAY.md#opportunistic-direct-udp-upgrade) for what "opportunistic"
means and what each tier trades away. None of this needs any client-side
configuration; it's the server and relay operators who opt into it.

## 3. Official WireGuard client → `ntwire-server` (direct)

0. Generate a WireGuard key pair for the client — see
   [above](#generating-a-wireguard-key-pair-for-an-official-client) if you
   don't already have one.
1. On the server, admit the peer and give it a stable server key:
   ```yaml
   # ntwire-server.yaml
   network:
     wireguard_private_key_file: /etc/ntwire/wireguard.key
   native_wireguard:
     enabled: true
     peers:
       - name: iphone
         public_key: "BASE64_CLIENT_PUBLIC_KEY"
         tunnel_ip: 100.64.0.10
         tunnels: [reports]
   ```
   `wireguard_private_key_file` is created (mode `0600`) on first start if
   absent, and keeps the server's public key stable across restarts — needed
   because the client profile below pins it. The client's own private key is
   generated by the client/operator and never appears in server config.
2. Import an ordinary WireGuard profile on the device (iOS, macOS, Windows,
   Android, or Linux official app):
   ```ini
   [Interface]
   PrivateKey = <client private key>
   Address = 100.64.0.10/32
   [Peer]
   PublicKey = <server public key, from wireguard_private_key_file>
   Endpoint = vpn.example.com:51820
   AllowedIPs = 100.64.0.0/16
   PersistentKeepalive = 25
   ```
   `AllowedIPs` is WireGuard's own cryptographic routing, not an ntwire
   destination grant — keep it to the tunnel_cidr range unless you deliberately
   want full routing (never `0.0.0.0/0`/`::/0` by accident).
3. Connect from the official app as normal — there's no `ntwire connect` step
   for this path.
4. Reach a target — see [below](#reaching-a-target-once-the-tunnel-is-up); an
   official client has no local port-forwarding step, so it addresses the
   server's tunnel IP and the target's `virtual_port` directly.

Full detail, including how peer/tunnel grants and destination policies
compose: [NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md).

## 4. Official WireGuard client → `ntwire-relay` (server behind NAT)

This layers on top of [3](#3-official-wireguard-client--ntwire-server-direct):
the server still needs its own `native_wireguard:` block, and additionally
the relay needs a dedicated per-tenant UDP listener for it:

```yaml
# ntwire-relay.yaml
registrations:
  - name: home
    public_key: "ssh-ed25519 ... admin@laptop"   # from step 1 of scenario 5
    native_wireguard:
      listen: ":51821"
```

This tier is opt-in on both sides: the relay needs the `native_wireguard.listen`
line above, and the server needs `native_wireguard.enabled: true` — the
association handshake between them is never sent otherwise.

The client profile is identical to scenario 3 except for one field —
`Endpoint` becomes the relay's wildcard hostname and this tenant's
`native_wireguard.listen` port:

```ini
[Interface]
PrivateKey = <client private key>
Address = 100.64.0.10/32
[Peer]
PublicKey = <server public key>          # unchanged: still the server's key, never the relay's
Endpoint = home.relay.example.com:51821
AllowedIPs = 100.64.0.0/16
PersistentKeepalive = 25
```

The relay forwards opaque WireGuard datagrams only between this tenant's
registered server and its clients — it holds no WireGuard key and cannot
decrypt anything, and the server's real network address is never exposed to
the client. Because the listener is selected by UDP port rather than by the
TLS SNI `listen.public` uses, one relay port serves exactly one tenant. Full
detail: [RELAY.md#native-wireguard-udp-endpoints](RELAY.md#native-wireguard-udp-endpoints).

Reaching a target once this tunnel is up works exactly like scenario 3 —
see [below](#reaching-a-target-once-the-tunnel-is-up). The relay only
carries WireGuard datagrams between client and server; it plays no part in
how a target is addressed once they arrive.

## Reaching a target once the tunnel is up

The `ntwire` client runs `ntwire connect`, which opens a loopback listener
per tunnel (`local_host:local_port`) and forwards it into the tunnel for you.
An official WireGuard client has no such process — once the handshake
completes, `AllowedIPs` has already routed the whole `tunnel_cidr` into the
device's network stack, and you address a target directly at:

```
<server tunnel IP>:<virtual_port>
```

The server's tunnel IP is always the first usable address of
`network.tunnel_cidr` — `100.64.0.1` for the default `100.64.0.0/16` — never
`0.10` or any other peer address, and a native peer's `tunnel_ip` is refused
by config validation if it collides with it. It's the same address the
`ntwire` client shows as `{{.ServerTunnelIP}}` in a tunnel's `instructions`
(see [CONFIGURATION.md#tunnel-instructions](CONFIGURATION.md#tunnel-instructions)),
and `virtual_port` is the same per-tunnel field from `tunnels:` used
throughout this document.

1. **Fixed-target tunnel** (`target: host:port`) — point whatever tool the
   target speaks straight at `<server tunnel IP>:<virtual_port>`; the server
   proxies the connection to the configured `target` over its own ordinary
   network, and the official client never sees or needs that hostname:
   ```sh
   curl http://100.64.0.1:18080/reports/latest
   psql -h 100.64.0.1 -p 15432 mydb
   ```
2. **SOCKS tunnel** (`target: socks`) — point a SOCKS-aware client, or the
   OS/app's SOCKS proxy setting, at `<server tunnel IP>:<virtual_port>`
   (SOCKS4 or SOCKS5); the destination is whatever the SOCKS request names,
   filtered by the tunnel's `socks:` block instead of a fixed `target`:
   ```sh
   curl --socks5-hostname 100.64.0.1:11080 https://internal.example/
   ```
   See [CONFIGURATION.md#socks-proxy-tunnels](CONFIGURATION.md#socks-proxy-tunnels).
3. **Which targets a peer can actually reach** — an official client has no
   ntwire session, so the `allow:` grant list on a tunnel is never consulted
   for it. Instead, a native peer reaches only the tunnels named in its own
   `native_wireguard.peers[].tunnels:` list, further narrowed by the AND of
   its `destination_policy` and the tunnel's own `destination_policy`/
   `socks:` filters — every other tunnel's `virtual_port` refuses the
   connection even though WireGuard's `AllowedIPs` would otherwise let the
   packets reach it. See
   [NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md) and
   [DESTINATION-POLICIES.md#composing-with-native-wireguard-peer-policies](DESTINATION-POLICIES.md#composing-with-native-wireguard-peer-policies).

## 5. `ntwire-server` → `ntwire-relay` (registering as a tenant)

This is the prerequisite for scenarios 2 and 4 — it's what lets a server
with no inbound connectivity be reachable at all.

1. On the relay host, run the relay with a wildcard DNS name pointed at it:
   ```sh
   ntwire-relay --config ntwire-relay.yaml
   ```
   ```yaml
   # ntwire-relay.yaml
   listen:
     public: ":443"     # raw TCP; client TLS is spliced through, never terminated here
     agents: ":8444"    # HTTPS endpoint ntwire-servers dial outbound to and register on
   domain: relay.example.com
   ```
2. On the server host, generate a relay identity key — this is separate from
   `auth.authorized_keys_dir` and only authenticates the server to the relay:
   ```sh
   ntwire-server -generate-relay-key relay_id_ed25519
   ```
   This prints the `registrations[]` entry to add to `ntwire-relay.yaml`:
   ```yaml
   # ntwire-relay.yaml
   registrations:
     - name: home
       public_key: "ssh-ed25519 AAAA... admin@laptop"
   ```
3. Point the server at the relay and leave `listen.https` alone — it's never
   bound in relay mode:
   ```yaml
   # ntwire-server.yaml
   relay:
     enabled: true
     url: "wss://relay.example.com:8444"
     name: home                                 # must match the registrations[] entry above
     identity_file: /etc/ntwire/relay_id_ed25519
   network:
     advertised_endpoint: ""                    # must stay empty when relay.enabled is true
   ```
4. Start (or restart) both processes in either order — the server dials out
   and registers; no inbound port is needed on the server's network.

For an active-active relay pool, high-availability recovery behavior, and
Kubernetes deployment of either side, see
[RELAY.md#high-availability-and-recovery](RELAY.md#high-availability-and-recovery).
