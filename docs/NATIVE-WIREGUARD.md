# Native WireGuard peers

ntwire can admit an unmodified official WireGuard client into the same userspace WireGuard device and gVisor netstack used by authenticated ntwire clients. Native peers do not call `/v1/auth`, have no ntwire session or TTL, and are removed only by configuration/reload.

This whole mechanism is for one specific case: a device that must use the *official* WireGuard app rather than `ntwire`. Whenever the `ntwire` client is an option, prefer it — it needs no WireGuard key management at all and gets session auth, per-tunnel grants, TTLs, and revocation that a static native peer does not have. See [CONNECTING.md](CONNECTING.md) for a side-by-side of both paths.

```yaml
network:
  tunnel_cidr: 100.64.0.0/16
  wireguard_private_key_file: /etc/ntwire/wireguard.key
native_wireguard:
  enabled: true
  peers:
    - name: iphone
      public_key: "BASE64_WIREGUARD_PUBLIC_KEY"
      tunnel_ip: 100.64.0.10
      tunnels: [reports]
      destination_policy: mobile
```

`wireguard_private_key_file` is created mode `0600` when absent and keeps the server public key stable across restart. Keep it outside source control. Client private keys are generated and retained by the client/operator, never in ordinary server configuration — `wg genkey`/`wg pubkey`, an official app's own key generation on first tunnel creation, or `ntwire-server -generate-wireguard-key path` (a convenience wrapper with no server-config side effect, so the private key never has to touch `wireguard-tools`) all produce an equally valid pair; see [CONNECTING.md](CONNECTING.md#generating-a-wireguard-key-pair-for-an-official-client).

```ini
[Interface]
PrivateKey = <client private key>
Address = 100.64.0.10/32
[Peer]
PublicKey = <server public key>
Endpoint = vpn.example.com:51820
AllowedIPs = 100.64.0.0/16
PersistentKeepalive = 25
```

Use the narrow netstack/service range required by ntwire; `AllowedIPs` is WireGuard cryptographic routing, not an ntwire destination authorization rule. Do not use `0.0.0.0/0` or `::/0` unless full routing is explicitly intended. iOS, macOS, Windows, Android, and Linux official clients import this ordinary profile.

### Printing client configuration & QR code

To generate the ready-to-use client profile or a scannable QR code directly from your `ntwire-server` configuration:

```sh
# Print both the .conf configuration and a terminal QR code
ntwire-server -config ntwire.yaml -print-wireguard-config

# Print only the .conf file (for redirecting to a file)
ntwire-server -config ntwire.yaml -print-wireguard-conf > client.conf

# Print only the QR code (for quick mobile app scanning)
ntwire-server -config ntwire.yaml -print-wireguard-qr

# Generate configuration for a specific peer
ntwire-server -config ntwire.yaml -print-wireguard-config -wireguard-peer iphone
```

Native tunnel grants are checked before destination policy. Peer and tunnel policies compose with restrictive AND semantics. Unknown public keys are rejected by WireGuard itself. The direct listener is `listen.wireguard`. Behind a relay (no inbound UDP path to the server), a registered server can still admit native peers via a relay-mediated UDP endpoint — see [RELAY.md](RELAY.md#native-wireguard-udp-endpoints).

