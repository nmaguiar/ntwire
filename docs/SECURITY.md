# Security notes

## Current boundary

nwire protects the control-plane authentication request, not the network path
or configured targets. The server starts a plain HTTP listener even though the
configuration contains `tls` fields; those fields are parsed but unused.
WireGuard, WebSocket fallback, and TCP forwarding are not implemented.

Run this bootstrap only on loopback during development, or behind a trusted
TLS-terminating proxy on a controlled network. Do not send private keys,
bearer tokens, or signed requests over an untrusted plain-HTTP connection.

## Implemented protections

- Client requests are signed over a byte-exact canonical payload.
- The server validates key membership and compares public-key digests in
  constant time.
- Timestamps have a two-minute window and accepted nonces are retained for
  five minutes to prevent replay.
- YAML ACLs limit keys to configured tunnels. Optional hooks fail closed and
  can only narrow YAML grants or shorten a session TTL.
- Session tokens are random bearer credentials and expire when checked.

## Operator guidance

- Never commit or log private keys, bearer tokens, request bodies, or hook
  output without redaction. `nwire keygen` writes private keys with mode 0600.
- Restrict writes to the authorized-key directory. Every readable file in it
  is considered a candidate public key.
- Prefer explicit fingerprint or key-comment `allow` entries over `"*"`.
- Synchronize server clocks; drift over two minutes rejects valid clients.
- Treat authorizer endpoints and executables as part of the access-control
  boundary: they receive key identity and client metadata.

The future data-plane design in [PLAN.md](../PLAN.md) is not a security claim
about the currently available code.
