---
title: Security Notes
description: TLS trust model, OIDC threat model, and relay trust model for ntwire
type: reference
---

# Security notes

## Current boundary

ntwire protects control-plane requests with TLS and data-plane traffic with
WireGuard. The server can use configured TLS files or a self-signed
certificate it persists across restarts; clients pin the latter on first use.
TCP forwarding is limited to
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
  when both share a literal string (see
  [PROTOCOL.md](PROTOCOL.md#grant-matching-and-the-sshoidc-namespace)).

## TLS trust model and avoiding repeated re-trust prompts

When `tls.cert_file`/`tls.key_file` are unset, the server generates a
self-signed certificate and, by default, **persists it** to
`tls.state_dir` (the configuration file's directory unless overridden) as
`selfsigned-cert.pem`/`selfsigned-key.pem`, mode `0600`
(`loadOrCreateSelfSigned` in `pkg/server/tls.go`). It is reused across
restarts and only regenerated if the stored pair is missing, unreadable, or
expiring within 30 days; the server logs its SHA-256 pin at startup as
`tls_fingerprint`. Set `tls.ephemeral: true` to opt back into a fresh
in-memory-only certificate on every start instead. A client that connects
for the first time computes the presented certificate's SHA-256 fingerprint
and stores it in `~/.ntwire/known_servers` (TOFU: trust on first use); every
later connection compares the presented certificate's fingerprint against
that pin and fails closed with `UnknownCertificateError` if it differs.

Because a persisted self-signed certificate keeps the same fingerprint
across restarts, the default configuration does not normally trigger a
re-trust prompt. `tls.ephemeral: true`, or a `state_dir` the server cannot
write to (it falls back to an in-memory certificate with a logged warning),
regenerates the certificate — and therefore its fingerprint — on every
start, and a client that pinned the previous fingerprint is correctly
locked out until an operator re-confirms the new one. **This is the pinning
working as intended** — a changed fingerprint is indistinguishable from a
machine-in-the-middle presenting its own certificate, so silently accepting
it would defeat the point of TOFU. Avoid "just trust the new one
automatically" workarounds; instead, use one of:

- **Keep the default persisted self-signed certificate**, which already
  keeps the fingerprint stable across restarts with no extra configuration.
  Make sure `tls.state_dir` (or the config file's directory) is writable and
  backed up if you want to survive rebuilding the host.
- **Configure a real certificate** (`tls.cert_file`/`tls.key_file`, e.g. from
  Let's Encrypt or an internal CA). This is the most robust fix for a
  long-lived deployment with a real hostname: it sidesteps TOFU entirely and
  is reloaded live from disk (see
  [Server configuration](CONFIGURATION.md#hot-reload)).
- **Pre-seed the client's pin out of band.** `known_servers` is a plain
  YAML file (`host: SHA256:...` entries; see `TrustServer` in
  `pkg/client/client.go`) that a client also writes to via
  `ntwire connect --insecure` on first trust. Read the pin from the server's
  startup log (`tls_fingerprint`), or compute it yourself with `openssl x509
  -in <state_dir>/selfsigned-cert.pem -noout -fingerprint -sha256` formatted
  to match the `SHA256:base64(...)` form the client stores, and write it into
  a new client's `~/.ntwire/known_servers` before the first connection so no
  prompt appears. This only stays useful if the fingerprint is stable (i.e.
  not combined with `tls.ephemeral: true`).
- **Distribute the certificate itself** with the client's `--ca` flag, which
  verifies the presented chain against that CA instead of a pinned
  fingerprint. The generated self-signed certificate's SANs are `localhost`,
  the server's hostname, and the loopback IPs (`pkg/server/tls.go`), so this
  works out of the box for `https://localhost:...` or `https://<hostname>:...`;
  a certificate meant to be distributed this way to a different hostname
  needs a matching SAN, which today means supplying your own
  `cert_file`/`key_file` rather than the built-in self-signed generator.
- Avoid `--insecure` (`InsecureSkipVerify`, no pin at all) outside a
  disposable local/dev server — it removes server authentication entirely,
  not just the restart friction.

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
- **Revocation is YAML/groups change + session TTL, not instantaneous —
  unless an operator revokes the session directly.** Removing a user's
  email/domain/group grant, removing an issuer, or editing the groups a
  directory reports takes effect on the next config reload (which
  re-evaluates every live OIDC session against current grants) or, for a
  session already dropped from `allow`, immediately; a session that keeps its
  grant continues until `session_ttl` and does not need the ID token to
  remain valid, so IdP-side deprovisioning alone does not immediately end an
  already-established ntwire session. For immediate revocation without
  waiting on a config change or TTL, an operator with `admin.web_ui_token`
  can end one session right away: read its `session_id` from
  `GET /v1/dashboard` (see [Server dashboard](CONFIGURATION.md#server-dashboard)),
  then `POST /v1/admin/sessions/{id}/revoke?token=...` on the metrics
  listener. This endpoint is deliberately not on the public control API — it
  shares the dashboard's token gate and listener, so it inherits the same
  "bind to loopback or place it behind an authenticating proxy" guidance.
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

## The relay's trust model

An ntwire-server behind NAT with no inbound connectivity can dial out to a
public `ntwire-relay` instead of listening directly (see [RELAY.md](RELAY.md)
for setup and the full design). This is safe with the same client TOFU pin described above,
because of one property that predates the relay entirely: the client verifies
the server's certificate by **SHA256 fingerprint only** (`InsecureSkipVerify`
plus a `VerifyConnection` hook, no hostname check —
`pkg/client/client.go`). The relay routes on the TLS ClientHello's SNI and
splices raw bytes; it never holds the origin server's private key and never
terminates the client's TLS session, so the fingerprint the client already
pins is unaffected by the relay hop.

**A malicious or compromised relay cannot:**

- MITM the client's TLS session — it does not have the origin's key, and
  presenting its own certificate would fail the client's fingerprint pin.
- Read or forge tunnel traffic — WireGuard's Noise handshake runs end-to-end
  inside the spliced TLS stream, opaque to the relay.
- Impersonate a tenant to claim a name — that requires a valid
  `RelayRegisterRequest` signature from the corresponding private key (see
  [PROTOCOL.md](PROTOCOL.md#relay-registration-protocol-ntwire-server-ntwire-relay)'s
  relay registration protocol).
- Authenticate as a client — it never sees `/v1/auth` traffic in cleartext.

**A malicious or compromised relay can:**

- Deny service to a tenant (drop the control connection, refuse to dial
  back, or simply not run).
- Observe timing, connection volume, and which tenant name (subdomain) each
  inbound client contacts — the SNI itself is necessarily plaintext.
- **Lie about the client's source IP.** The relay reports each inbound
  client's address in `RelayOpen.client_addr`, and the origin server trusts
  it for per-source-IP rate limiting (`allowSource`), audit logging, and the
  authorizer hook's `source_ip` field. This is a new trust requirement
  introduced by relay mode specifically, and it is the reason
  `relayConn.RemoteAddr()` exists (`pkg/server/relay.go`) — without it, every
  relayed client would collapse into one bucket keyed by the relay's own
  address, a functional outage under mild concurrent load. **Operators must
  not build IP allowlists against a relayed deployment's authorizer hook or
  audit log**, since a relay that misbehaves (or is itself compromised) can
  misreport this field. This does not let a malicious relay bypass
  authentication — it can only affect rate-limit bucketing and the address
  recorded in logs/hooks.

In short: **the relay is untrusted for confidentiality and integrity, and
trusted only for availability** (and, within that, for accurately reporting
client addresses used for rate limiting and logging — not a security boundary
strong enough to authorize based on).

**Operational notes:**

- The relay's own `listen.agents` TLS certificate is *not* what the ntwire
  client pins; it only protects the server↔relay control/data connections.
  Set `relay.fingerprint` on the server (or `tls.cert_file`/`key_file` on the
  relay with normal PKI) to authenticate that hop; leaving it empty falls
  back to normal certificate verification, which requires the relay's
  `listen.agents` certificate to chain to a trusted root.
- A scanner or unauthenticated connection to `listen.public` sees a TCP port
  that accepts, then resets without ever sending a byte — no certificate, no
  banner, no HTTP response, matching the behavior of an unregistered or
  offline tenant name (see below).
- An unregistered tenant name and a registered-but-offline one are
  deliberately indistinguishable from the outside: both simply reset the
  connection. This prevents enumerating which tenant names are configured
  on a given relay.
- **Encrypted Client Hello (ECH)** would hide the SNI the relay routes on,
  breaking routing entirely. ntwire's Go TLS stack does not send ECH by
  default, so this is not a concern today, but it is a known future
  incompatibility if ECH is ever adopted on the client side.
- Rate limiting on `listen.public` (`limits.max_new_conns_per_minute`) is
  **mandatory**, unlike the server's `allowSource`, because the relay is
  internet-facing and a relay is a **dial-back amplification vector**: every
  inbound connection with a valid, registered SNI forces the origin server to
  open an outbound data connection. `limits.max_pending_per_server` and
  `limits.max_conns_per_server` cap this per tenant, independent of the
  source-IP rate limit.
