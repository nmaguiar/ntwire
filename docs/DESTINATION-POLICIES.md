# Destination policies

`destination_policies` is the reusable authorization layer for destinations opened after a principal has been granted a tunnel. It is not WireGuard AllowedIPs.

```yaml
destination_policies:
  corporate:
    filters: ["10.0.0.0/8", "192.168.0.0/16"]
    domain_filters: [".corp.example.com"]
    asn_filters: [12345]
    protocols: [tcp]
    ports: [443, 5432]
    allow_all: false
tunnels:
  - name: database
    target: db.corp.example.com:5432
    virtual_port: 15432
    destination_policy: corporate
```

Policies support legacy SOCKS fields (`filters`, `domain_filters`, `asn_filters`, `only_local`, `reverse_filters`, and `allow_all`) plus `protocols` and `ports`. CIDR/ASN tests use the selected destination IP. Fixed targets resolve, evaluate, and dial the same exact IP to avoid DNS rebinding between authorization and connect.

Existing `tunnels[].socks` filtering remains compatible and is evaluated first; a generic policy is an extra restriction. ASN data is held in a server-wide index rather than one updater per SOCKS tunnel.

## Composing with native WireGuard peer policies

A native WireGuard peer (see [NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md)) can
carry its own `destination_policy` in addition to a tunnel's. The two are
ANDed, restrictive-only: a destination must pass both the peer's policy and
the tunnel's `destination_policy` to be allowed, and neither side can widen
what the other denies. This peer-level policy only ever applies to native
WireGuard peers — an ordinary SSH/OIDC session has no peer-level policy of its
own, so a tunnel's `destination_policy` is the only lever for those sessions.
