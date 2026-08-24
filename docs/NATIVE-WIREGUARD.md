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
DNS = 100.64.0.1

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

# From a running Docker container (e.g. ntwire-server):
docker exec -it ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr
docker exec -it ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr -wireguard-peer iphone
docker exec ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-conf > client.conf

# Or via Docker Compose:
docker compose -f deploy/docker/docker-compose.yml exec -it ntwire-server /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr

# Or via Kubernetes (kubectl):
kubectl exec -it deployment/ntwire-server -- /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr
kubectl exec -it deployment/ntwire-server -- /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-qr -wireguard-peer iphone
kubectl exec deployment/ntwire-server -- /ntwire-server -config /etc/ntwire/ntwire.yaml -print-wireguard-conf > client.conf
```

### Using SOCKS egress with Proxy Auto-Configuration (PAC) on iOS

When native WireGuard peers have access to a `target: socks` tunnel, iOS devices can route Kubernetes internal services, internal DNS names, and private network ranges through the WireGuard tunnel automatically:

1. **Connect WireGuard:** Import the QR code or `.conf` profile in the official WireGuard app and activate the tunnel.
2. **Configure PAC in iOS Settings:**
   - Open **Settings** → **Wi-Fi** (or **Cellular** / mobile data profile).
   - Tap the **(i)** info icon next to your active network connection.
   - Scroll down to **HTTP Proxy** / **Configure Proxy** and choose **Automatic**.
   - Enter the iOS PAC URL: `https://<server>:8443/proxy-ios.pac` (or `/proxy-ios-<target>.pac`, or via relay `https://<tenant>.<relay-domain>/proxy-ios.pac`).
3. **Browse:** Safari and iOS apps will route internal destinations (e.g. `*.svc`, `*.cluster.local`, `*.internal`, `10.0.0.0/8`) through the SOCKS proxy at `100.64.0.1:<virtual_port>` over the WireGuard tunnel, while standard internet traffic goes direct.

### In-tunnel DNS and Target Discovery

`ntwire-server` includes an in-tunnel DNS server listening on UDP port 53 inside the WireGuard netstack (`100.64.0.1:53`). Official WireGuard clients configured with `DNS = 100.64.0.1` can resolve and discover available targets directly over the tunnel:

1. **Discover all available targets (SRV discovery):**
   ```sh
   # Returns SRV records for all tunnels granted to this peer, along with their virtual ports
   dig SRV _ntwire._tcp.ntwire @100.64.0.1
   # (also aliases: _ntwire._tcp.tunnel, _services._dns-sd._udp.ntwire)
   ```

2. **Discover targets via TXT records:**
   ```sh
   # Returns metadata (name, port, backend target, description) for all granted tunnels
   dig TXT _ntwire.ntwire @100.64.0.1
   ```

3. **Resolve tunnel names directly:**
   ```sh
   # Resolves to the server tunnel IP (100.64.0.1)
   dig A reports.ntwire @100.64.0.1
   # (.tunnel and .ntwire.internal are also supported as aliases)
   dig A reports.tunnel @100.64.0.1
   ```

4. **Look up a specific tunnel's port and metadata:**
   ```sh
   # Look up virtual port
   dig SRV _reports._tcp.ntwire @100.64.0.1
   dig SRV reports.ntwire @100.64.0.1

   # Look up target metadata
   dig TXT reports.ntwire @100.64.0.1
   ```

5. **Access control & Zero-trust discovery:**
   Target discovery and name resolution over DNS are strictly filtered by the querying peer's `tunnel_ip`. A native WireGuard peer only discovers and resolves tunnels listed in its `native_wireguard.peers[].tunnels` grant list; queries for ungranted tunnels return `NXDOMAIN`. Queries from unrecognized IP addresses return `REFUSED`.

Native tunnel grants are checked before destination policy. Peer and tunnel policies compose with restrictive AND semantics. Unknown public keys are rejected by WireGuard itself. The direct listener is `listen.wireguard`. Behind a relay (no inbound UDP path to the server), a registered server can still admit native peers via a relay-mediated UDP endpoint — see [RELAY.md](RELAY.md#native-wireguard-udp-endpoints).



