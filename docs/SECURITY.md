# Security notes

## Current boundary

ntwire protects control-plane requests with TLS and data-plane traffic with
WireGuard. The server can use configured TLS files or an in-memory self-signed
certificate; clients pin the latter on first use. TCP forwarding is limited to
YAML-granted targets. Where UDP is blocked, WireGuard datagrams can use the
token-authenticated WebSocket fallback on the HTTPS endpoint. SSH keys and SSO
(OIDC) logins are parallel, equally-trusted authentication methods; both
produce the same opaque-bearer-token session.

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
- OIDC grant matching stays scoped to the authentication method: an SSH
  request is never compared against email/domain/group `allow` entries and an
  OIDC request is never compared against fingerprint/comment entries, even
  when both share a literal string (see docs/PROTOCOL.md).

## OIDC threat model

- **Bearer credential, not a signature.** Unlike the SSH flow, the ID token
  itself is a bearer credential presented once at `/v1/auth/oidc` — anyone who
  captures a still-valid token before it is used could redeem it. Transit is
  protected by the same TLS + TOFU pinning as the rest of the control plane;
  there is no additional proof-of-possession step. The token's short lifetime
  (typically under an hour) and single use at that endpoint bound the window.
- **Audience binding.** The server requires `aud` to equal the issuer's
  configured `client_id`, so an ID token minted for an unrelated application at
  the same IdP cannot be replayed against ntwire.
- **ntwire-server holds no IdP secret.** It is a public OAuth client (PKCE, no
  client secret) and never performs a token exchange itself; it only verifies
  ID tokens the client already obtained, against the issuer's published JWKS.
- **Token cache file permissions.** `~/.ntwire/tokens.json` holds a long-lived
  refresh token and is written mode `0600`. Treat it like a private key: a
  reader can mint fresh sessions until it is revoked. `ntwire logout` deletes
  a server's entries locally; it does not revoke the refresh token at the IdP.
- **Revocation is YAML/groups change + session TTL, not instantaneous.**
  Removing a user's email/domain/group grant, removing an issuer, or editing
  the groups a directory reports takes effect on the next config reload (which
  re-evaluates every live OIDC session against current grants) or, for a
  session already dropped from `allow`, immediately; a session that keeps its
  grant continues until `session_ttl` and does not need the ID token to
  remain valid, so IdP-side deprovisioning alone does not immediately end an
  already-established ntwire session — pair it with a YAML/group grant change
  for prompt revocation.
- **Per-identity session cap.** `max_sessions_per_key` applies per identity
  for OIDC too (the verified email), independent of the SSH fingerprint
  namespace.
- **`require_verified_email`** defaults to `true`; disabling it (per issuer)
  should only be done for IdPs known not to set `email_verified`, since an
  unverified email is not a reliable identity claim.

## Operator guidance

- Never commit or log private keys, bearer tokens, ID/refresh tokens, request
  bodies, or hook output without redaction. `ntwire keygen` writes private
  keys with mode 0600; the token cache is written with the same mode.
- Restrict writes to the authorized-key directory. Every readable file in it
  is considered a candidate public key.
- Prefer explicit fingerprint `allow` entries for SSH (the bundled client
  never sends a key comment, so comment-based entries only match
  purpose-built requests) and exact-email or `group:` entries over a bare
  `@domain` for OIDC, which grants everyone at that domain.
- Synchronize server clocks; drift over two minutes rejects valid clients on
  both the SSH and OIDC auth endpoints.
- Treat authorizer endpoints and executables as part of the access-control
  boundary: they receive key identity, or OIDC identity/issuer/groups, plus
  client metadata.
- Register ntwire as a **public** OAuth client (no client secret) with a
  loopback redirect URI for PKCE and, if used, device-flow support enabled at
  the IdP.
