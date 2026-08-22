# Native WireGuard peers

ntwire can admit an unmodified official WireGuard client into the same userspace WireGuard device and gVisor netstack used by authenticated ntwire clients. Native peers do not call `/v1/auth`, have no ntwire session or TTL, and are removed only by configuration/reload.

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

`wireguard_private_key_file` is created mode `0600` when absent and keeps the server public key stable across restart. Keep it outside source control. Client private keys are generated and retained by the client/operator, never in ordinary server configuration.

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

Native tunnel grants are checked before destination policy. Peer and tunnel policies compose with restrictive AND semantics. Unknown public keys are rejected by WireGuard itself. The direct listener is `listen.wireguard`. Behind a relay (no inbound UDP path to the server), a registered server can still admit native peers via a relay-mediated UDP endpoint — see [RELAY.md](RELAY.md#native-wireguard-udp-endpoints).
