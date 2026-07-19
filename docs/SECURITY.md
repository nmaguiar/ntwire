# Security notes

## Current boundary

nwire protects control-plane requests with TLS and data-plane traffic with
WireGuard. The server can use configured TLS files or an in-memory self-signed
certificate; clients pin the latter on first use. TCP forwarding is limited to
YAML-granted targets. Where UDP is blocked, WireGuard datagrams can use the
token-authenticated WebSocket fallback on the HTTPS endpoint.

## Implemented protections

- Client requests are signed over a byte-exact canonical payload.
- The server validates key membership and compares public-key digests in
  constant time.
- Timestamps have a two-minute window and accepted nonces are retained for
  five minutes to prevent replay.
- YAML ACLs limit keys to configured tunnels. Optional hooks fail closed and
  can only narrow YAML grants or shorten a session TTL.
- Session tokens are random bearer credentials and expire when checked.
- The WebSocket fallback requires the session bearer token and accepts only
  bounded binary WireGuard datagrams.

## Operator guidance

- Never commit or log private keys, bearer tokens, request bodies, or hook
  output without redaction. `nwire keygen` writes private keys with mode 0600.
- Restrict writes to the authorized-key directory. Every readable file in it
  is considered a candidate public key.
- Prefer explicit fingerprint or key-comment `allow` entries over `"*"`.
- Synchronize server clocks; drift over two minutes rejects valid clients.
- Treat authorizer endpoints and executables as part of the access-control
  boundary: they receive key identity and client metadata.
