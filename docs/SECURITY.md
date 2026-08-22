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
YAML-granted targets — with one deliberate exception: a `target: socks`
tunnel (see below and
[CONFIGURATION.md](CONFIGURATION.md#socks-proxy-tunnels)) grants access to a
class of destinations, filtered by its `socks:` block, rather than a single
fixed one. Where UDP is blocked, WireGuard datagrams can use the
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
- **Native credential storage with explicit fallback.** ntwire stores reusable
  OIDC credentials in macOS Keychain, Windows Credential Manager, or a
  Secret-Service-compatible Linux keyring when one is available. A legacy
  `~/.ntwire/tokens.json` entry is migrated only after the native write is
  read back successfully, then its secret is removed from the file. On a
  headless or otherwise unsupported system, the documented fallback remains
  that mode-`0600` file; treat it like a private key. `ntwire logout` removes
  a server's local entries but does not revoke the refresh token at the IdP.
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

## SOCKS proxy tunnels and egress risk

## Native WireGuard and destination policies

Native peers are static cryptographic peers in the existing userspace WireGuard device, not bearer-token sessions. Their configured IPs are reserved from dynamic allocation. Keep the persistent server WireGuard key and all client private keys out of source control. Tunnel grants are checked before destination policies; peer and tunnel policies compose as restrictive AND rules. Fixed-target policies evaluate the chosen resolved IP before it is dialled. See `NATIVE-WIREGUARD.md` and `DESTINATION-POLICIES.md`.

### Operator-visible risk capabilities

At startup and after a configuration reload, ntwire logs the stable
`security_capabilities` event. Its `capabilities` array contains only enabled
high-risk configuration classes, never tunnel names, identities, URLs, or
secrets. The same array is available to an authenticated operator in
`GET /v1/dashboard?token=...` as `security_capabilities`. Current values are
`authorization_hook`, `socks_unrestricted`, `socks_bind`,
`relay_mediated_udp`, and `direct_udp_relay_bypass`. An empty array means none
of these opt-ins is configured. Client-side `--insecure` emits the separate
`insecure_tls_enabled` warning when a connection is established.

A `target: socks` tunnel is a governed general-purpose egress proxy, not a
fixed-destination forward: every session holding its grant can reach every
destination the tunnel's `socks:` filters permit, and the server itself, not
just the client, initiates each of those outbound connections and DNS
resolutions. Weigh that before granting one broadly:

- **The default denies everything, not everything.** socksd (the filter set
  this re-implements) defaults to allowing every destination when no filters
  are configured; ntwire deliberately does not, because that default would
  turn an authenticated tunnel into a silent open proxy. Leaving
  `socks.filters`/`domain_filters`/`asn_filters`/`only_local`/
  `reverse_filters` all unset denies every destination (logged as a warning
  at startup) unless `allow_all: true` is set explicitly — treat setting it
  with the same scrutiny as granting an unrestricted fixed target.
- **Filters gate the destination, not the requester.** `allow:` still governs
  *who* can use the tunnel; `socks:` governs *where* their traffic can go.
  Both apply to every connection.
- **`socks.asn_filters` makes the server itself an internet client.** ASN
  filtering downloads and periodically refreshes an index from the internet
  (default `https://openaf.io/asnidx.json.gz`, overridable with
  `socks.asn_url`) — don't enable it on a server that otherwise has no
  outbound internet access, and pin `socks.asn_url` to a trusted source if
  you do.
- **SOCKS5 domain requests resolve on the server**, using the server's DNS
  resolver and `socks.dns_timeout`, before `socks.domain_filters` is
  matched against the requested hostname and `socks.filters`/`asn_filters`
  against the resolved IP; a client cannot force resolution elsewhere.
- **BIND is independently opt-in and opens a real, temporary *inbound*
  listener on the server host.** Set `socks.allow_bind: true` only when this
  legacy behavior is required; it remains disabled even when SOCKS CONNECT or
  `allow_all` is enabled. When enabled it is
  reachable from any address that can route to it (not just over the
  WireGuard tunnel), for up to two minutes while it waits for one peer to
  connect — the same `socks:` filters gate the request's declared target
  address beforehand, but, matching upstream, the peer that actually
  connects to that listener is never itself re-checked against them.

## Binding tunnel listeners beyond loopback (`--bind`)

By default `ntwire connect` binds every tunnel's local listener to
`127.0.0.1`: a tunneled target is reachable only from processes on the same
host. `--bind address` (or the persisted `bind_address` setting, or the GUI
profile's "Bind address" advanced field) is an opt-in escape hatch for
advanced use cases — e.g. reaching a tunnel from another device on your LAN,
or from inside a container that isn't on the host's loopback namespace.

This is a client-local trust-boundary change, not a server-side grant, so the
server's `allow:` ACLs and hooks are unaffected and keep gating who can open
the tunnel in the first place. What changes is *who on the local network can
reach the already-open tunnel's local listener*:

- `--bind 0.0.0.0` (or a specific non-loopback IP) makes the tunneled target
  reachable from any host that can route to that address — other machines on
  the same LAN, a VPN peer, or, if the interface has a public/forwarded
  address, the internet. There is no additional authentication at the
  listener itself; anyone who can reach it reaches the tunnel target exactly
  as the local user could.
- Prefer a specific interface IP over `0.0.0.0` where you can, so exposure is
  bounded to the network segment you intend rather than every interface the
  host has.
- `--bind` only accepts a numeric IP address — a hostname is rejected rather
  than resolved, so a typo or a stale DNS answer can't silently move a
  listener onto an unexpected interface.
- The local status UI's listener (used by `ntwire status`/`ntwire port` and
  the browser dashboard) always stays on `127.0.0.1` regardless of `--bind`;
  it is a control-plane endpoint, not a tunneled target.
- Pair a non-loopback bind with host firewall rules scoped to the source
  addresses that should reach it, the same way you would for any other
  locally-bound service.

## Server-suggested loopback address (`local_host`) stays loopback-only

A server can suggest a specific loopback address for a tunnel's local
listener via `tunnels[].local_host` (see
[CONFIGURATION.md](CONFIGURATION.md#tunnel-local-address-and-port)), e.g.
`127.70.0.1`, so two tunnels can share a memorable port without colliding.
This is a convenience, not a trust boundary the server controls: unlike
`--bind` above, which is a deliberate client-side opt-in, `local_host` is
data the server sends unprompted on every authentication and renewal.

To keep that asymmetry safe, `local_host` is restricted to `127.0.0.0/8` and
`::1` at two independent points:

- The server refuses to start with a non-loopback `local_host` in its
  config (`pkg/server/config.go`'s `LoadConfig` validation) — an operator
  cannot configure this even by mistake.
- The client re-validates it anyway before using it, and ignores (with a
  logged warning) any `local_host` that isn't loopback. This defense in
  depth means a compromised or buggy server cannot use `local_host` to move
  a client's tunnel listener onto a LAN-reachable interface — only the
  client's own `--bind` can do that, and only because the client itself
  chose it.

An explicit client-side host override (`--port name=host:port`, or the GUI/
config equivalent) is not restricted to loopback, matching `--bind`'s
permissiveness: the user is choosing their own exposure, same as always.

## Operator guidance

Release validation must exercise the security-sensitive parser boundaries as
well as ordinary tests. `ojob tasks.yaml op=release` runs bounded fuzzing of
the protocol, SOCKS, and WebSocket inputs; record any unavailable local
dependency separately from a failing assertion in the release sign-off
([RELEASE.md](RELEASE.md)).

- Never commit or log private keys, bearer tokens, ID/refresh tokens, request
  bodies, or hook output without redaction. `ntwire keygen` writes private
  keys with mode 0600; the credential-file fallback uses the same mode.
- Prometheus metrics deliberately aggregate by authentication method and
  tunnel name only. They never use identities, session IDs, targets, or other
  unbounded/sensitive values as labels; use the separately protected operator
  dashboard for per-session inspection.
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

**The opportunistic direct-UDP upgrade (`relay.advertise_direct`) is a
deliberate exception to relay mode's address-hiding property.** With it
enabled, the server's real, currently-mapped public UDP address is served to
*any authenticated client* via `POST /v1/punch` — there is no separate
per-client authorization for learning it, only the same session token that
already grants tunnel access. This matches the setting's documented purpose
(trading address secrecy for lower latency; see
[RELAY.md](RELAY.md#opportunistic-direct-udp-upgrade)), so it is not treated
as a bug, but it is a real trust boundary shift operators should make
deliberately rather than discover afterward: leave `advertise_direct` off if
every authenticated client should not be able to learn the server's real
network location. The relay's own reflector (`listen.reflect`) is stateless
and unauthenticated by design — it answers any UDP packet shaped like a
reflection request with that packet's observed source address, the same way
a public STUN server would — so it never becomes a party to a session and
never sees WireGuard traffic.

**The relay-mediated UDP forwarding tier (`listen.udp_relay`) is, by
contrast, not a trust step-change at all.** Unlike `advertise_direct`, the
relay stays in the data path for the session's entire life and the server's
real address is never revealed to a client — the trust exposure is
identical to the default WSS-through-relay path (the relay sees ciphertext
volume and timing, nothing else), which is exactly why it needs no matching
opt-in flag on the server (see [RELAY.md](RELAY.md#relay-mediated-udp-forwarding)
and `RelayConfig.AdvertiseDirect`'s doc comment in `pkg/server/config.go`).
The one genuinely unauthenticated surface this tier exposes is the shared
client-facing socket (`listen.udp_relay`) accepting a `FrameRelayBind` from
any source address — a bind carrying an unknown or expired token is simply
dropped with no reply, indistinguishable from an ordinary lost packet, and
only a bind with a valid, live token gets a `FrameRelayBindAck`. The same
rate limiter the reflector already uses (`pkg/relay/public.go`'s
`newRateLimiter`) caps how often an unrecognized sender's bind attempts are
even looked up, bounding this to a much smaller blast radius than the
dial-back amplification vector below: guessing or replaying a token costs the
relay a lookup, never an outbound connection to a tenant's origin server, and
a session's token is only ever handed to the two parties (client and origin
server) that already completed authenticated allocation over TLS.

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
