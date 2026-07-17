# Security notes

Long-lived SSH keys authenticate requests only. Never log private keys,
bearer tokens, or signatures. Auth uses a timestamp, a bounded nonce replay
cache, canonical signed bytes, and constant-time public-key comparison.

Run the server behind TLS in production. The current bootstrap implements only
the control plane; it deliberately does not expose target TCP services until
the WireGuard/netstack data plane is complete.
