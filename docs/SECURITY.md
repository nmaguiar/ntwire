---
title: Security Notes
description: TLS trust model, OIDC threat model, and relay trust model for ntwire
type: reference
---

# Security notes

## In-tunnel DNS forwarding

DNS forwarding is disabled by default. When enabled, ntwire continues to bind
DNS only inside the WireGuard/netstack on the server tunnel IP; it never opens
a host or public `0.0.0.0:53` listener. Source tunnel IPs are mapped to an
existing principal before forwarding, so unknown sources receive `REFUSED` and
cannot use ntwire as an open resolver.

The configured ntwire DNS domain, aliases, service-discovery records, reverse
records, and single-label tunnel names are always authoritative/local. Unknown
or unauthorized local names return `NXDOMAIN` and are never sent upstream.
Only explicitly configured literal-IP upstreams receive non-ntwire queries.
They are part of the DNS trust and privacy model: the server operator can
observe resolver queries and the upstream provider receives forwarded public
queries. Keep upstream addresses away from the in-tunnel DNS listener to avoid
resolver loops.

## Kubernetes relay discovery

Kubernetes discovery is opt-in. Do not enable it with a broad selector unless
every matching namespace and Service is trusted to receive public TLS traffic.
The relay accepts only Services matching the configured label selector plus
the explicit `ntwire.io/relay-enabled: "true"` label, a valid non-wildcard
hostname annotation, permitted namespace scope, and required named port.
Duplicate hostnames fail closed. The Kubernetes ServiceAccount needs only
`get`, `list`, and `watch` on Services and (when namespace labels are used)
Namespaces; it never needs mutation permissions or cluster-admin.

Discovery is a routing decision, not an authorization boundary: the relay
does not decrypt client TLS. Use namespace-local server configuration and
NetworkPolicy so a tenant server can reach only its own workloads. The relay
should be allowed to reach only the ntwire-server TCP port; deny cross-tenant
server egress by default.

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

## Archived iOS/iPadOS Network Relay boundary

Work on the native iOS/iPadOS client is currently paused (see
[IOS.md](IOS.md)); the boundary below is retained as a design record. For
current iOS/iPadOS connectivity, use the official WireGuard app against
`ntwire-server`'s native peer support — see
[NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md) — which reuses the same
authentication/grant model described in [Current boundary](#current-boundary)
above rather than this Network Relay design.

The planned iOS/iPadOS client does not run a packet tunnel or repurpose a
background mode. It configures Apple’s system Network Relay and therefore
requires an optional MASQUE gateway before it can carry any ntwire traffic.
The gateway must authenticate every relay flow with a dedicated, short-lived,
revocable mobile relay credential and map it only to a server-authorized grant;
it must not accept a raw ntwire bearer token as a durable relay password or
turn a granted fixed-target tunnel into arbitrary proxy access. The existing
server remains authoritative for authentication, grants, expiry, and
revocation.

iOS OIDC refresh/session credentials, SSH key material, WireGuard material,
and TLS pins belong in Keychain. Do not put them in `UserDefaults`, relay
preferences, plaintext files, logs, metrics, support exports, or source
control. Native HTTPS networking must retain system certificate validation and
then enforce ntwire’s explicit TOFU/pin policy; a changed pin fails closed
pending an explicit user decision. An App Store application is a public OIDC
client and must not embed an IdP client secret.

The detailed platform constraints and proposed gateway boundary are in
[IOS.md](IOS.md). The server-side HTTP/2 CONNECT gateway and the iOS-side
identity packaging (local key/CSR generation, certificate issuance, PKCS#12
assembly, `NERelayManager` install) are both implemented and wired together —
see [IOS.md](IOS.md#delivery-gates). The gateway's MASQUE target mapping,
credential rotation, and revocation are covered by unit tests
(`pkg/server/masque_gateway_test.go`, `pkg/server/masque_test.go`), but none
of this has been proven against a physical iOS/iPadOS device. That real-device
interoperability gate — the acceptance criteria in
[IOS.md](IOS.md#identity-packaging-spike-required-acceptance-criteria) —
remains outstanding before an iOS data plane can be enabled by default.

## Implemented protections

- Client requests are signed over a byte-exact canonical payload.
- The server validates key membership and compares public-key digests in
  constant time.
- The key comment used for grant matching comes from the server's own
  `authorized_keys` file, never from the request, so the holder of one
  authorized key cannot claim a grant written for another
  ([PROTOCOL.md](PROTOCOL.md#authentication-request)).
- Timestamps have a two-minute window and accepted nonces are retained for
  five minutes to prevent replay. A nonce is consumed only **after** the
  signature verifies, so an unauthenticated request cannot churn the cache;
  the cache is size-capped as a backstop, as is the per-source rate limiter.
- YAML ACLs limit keys to configured tunnels. Optional hooks fail closed and
  can only narrow YAML grants or shorten a session TTL.
- Session tokens are random bearer credentials and expire when checked.
- The WebSocket fallback requires the session bearer token and accepts only
  bounded binary WireGuard datagrams.
- Opt-in transport promotion (`POST /v1/transport/primary`, off unless the
  server sets `transport.promotion` and the session negotiated
  `path-promote-v1`) requires the session bearer token. It can only select
  among carriers already registered for that session's own WireGuard peer and
  proven healthy by the server's own probes. It never accepts an address and
  cannot affect other peers. Attempts are rate-limited to one per session per
  10 seconds. An operator `transport.force` still takes precedence.
- OIDC grant matching stays scoped to the authentication method: an SSH
  request is never compared against email/domain/group `allow` entries and an
  OIDC request is never compared against fingerprint/comment entries, even
  when both share a literal string (see
  [PROTOCOL.md](PROTOCOL.md#grant-matching-and-the-sshoidc-namespace)).

## Inspecting certificates and possible TLS interception

The CLI and GUI trust prompts show the certificate actually presented on the
client's TLS connection: subject, issuer, validity dates, current SHA-256
fingerprint, and previous pin when present. The GUI offers expandable details
for the presented chain, SANs, serial number, and algorithms. The inspection
command also exposes these fields as JSON:

```sh
ntwire cert inspect --json https://server.example.com
```

Inspection uses the connect client's HTTP transport, proxy selection and IP
selection. Pass the same `--https-proxy`, `--no-system-proxy`, `--ip-version`
and `--known-servers` values as connect. It does not load a GUI profile or
connect's saved configuration automatically. It compares TOFU pins, so `--ca`
and `--insecure` are not supported on this command. Inspection always aborts
the TLS handshake after observing the certificate, including for a matching
pin, before sending an application request or ntwire authentication. HTTP
CONNECT or SOCKS proxy setup may still be required, including proxy credentials
when explicitly configured. It never writes `known_servers`.

First-time trust and changed certificates require explicit approval; the
CLI defaults to No and fails closed without a terminal. The GUI defaults to
Reject. A changed pin may indicate interception, but legitimate certificate
renewal, rotation, or replacing a TLS-terminating load balancer also changes
it. Confirm the new fingerprint independently with the administrator before
trusting it. Compare to the server startup `tls_fingerprint` over a separate
trusted channel, or compute the exact unpadded base64 fingerprint locally:

```sh
openssl x509 -in server-cert.pem -outform DER | openssl dgst -sha256 -binary | openssl base64 -A
```

Prefix the result with `SHA256:` and remove trailing `=` padding. For a
load balancer that terminates TLS, compare against its certificate instead
of the origin's certificate. Inspecting twice over the same suspect network
is not independent verification.

Case-insensitive, whole-name issuer patterns recognize Netskope, Zscaler,
Palo Alto Networks, Fortinet, Forcepoint, Symantec and Broadcom. These produce
an informational warning that the issuer resembles an enterprise
TLS-inspection authority. **Issuer text is untrusted and cannot prove
interception**: these vendors may also issue certificates for other purposes,
and an interceptor can omit any recognizable name. Ordinary private enterprise
CAs, self-signed certificates, and pin changes alone are not classified as
enterprise TLS interception. No external reputation service is contacted.

Hostname/IP mismatch, expired/not-yet-valid certificates, self-signatures,
and incomplete metadata are reported separately. Self-signed status requires
verification of the certificate's own signature. A presented chain is not
proof that any CA trusts it. The assessment does not change acceptance:
TOFU continues to authenticate the exact pinned leaf, even if its validity
or SANs would fail normal PKI checks; `--ca` continues to require normal
chain, hostname and validity verification. OS CA trust does not silently
approve a certificate in TOFU mode. `--insecure` disables both checks and
pinning and cannot provide protection against certificate substitution.

HTTPS control traffic and WSS initial dials and redials use the same HTTP
client and TLS verification policy. Pin failures retain a diagnostic error
identifying a changed certificate, with no fallback to insecure TLS and no
implicit trust change during transport failover. Existing connections do
not repeat TLS handshakes on every request; a changed certificate is observed
on the next handshake. Matching pinned certificates produce no recurring
metadata logs. Certificate details are not persisted in `known_servers`.

The relay's public listener passes TLS through; it does not acquire certificate
ownership or terminate TLS for inspection. Clients see the origin certificate,
or the certificate presented by an external TLS terminator/interceptor.
Server-to-relay registration certificates remain separate. Pinning protects
against substitution after a correctly verified first trust. It cannot prove
that a first-use certificate is authentic, detect every enterprise proxy,
or prevent inspection on an endpoint where software can access plaintext or
modify the client, trust decisions, keys, or runtime.

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
and, after explicit user approval, stores it in `~/.ntwire/known_servers`
(TOFU: trust on first use); every
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
  long-lived deployment with a real hostname: it is reloaded live from disk.
  Clients still use TOFU unless configured with `--ca` (see
  [Server configuration](CONFIGURATION.md#hot-reload)).
- **Pre-seed the client's pin out of band.** `known_servers` is a plain
  YAML file with a `servers` map (`host: SHA256:...` entries; see
  `TrustServer` in `pkg/client/client.go`). Explicit CLI or GUI trust writes
  that map; `--insecure` neither verifies nor records a pin. Read the pin from the server's
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
- **Deleting an authorized-key file revokes immediately.** The key directory
  is watched for removals as well as writes, so removing a `.pub` file both
  blocks new logins and drops that key's live sessions on the resulting
  reload, with an `authorization_revoked` audit record.
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
  then `POST /v1/admin/sessions/{id}/revoke` on the metrics listener with
  `Authorization: Bearer <admin.web_ui_token>`. This endpoint is deliberately
  not on the public control API — it shares the dashboard's token gate and
  listener, so it inherits the same "bind to loopback or place it behind an
  authenticating proxy" guidance.
- **Per-identity session cap.** `max_sessions_per_key` applies per identity
  for OIDC too (the verified issuer URL and stable subject), independent of
  the SSH fingerprint namespace. Email changes or configured issuer aliases
  do not reset the quota.
- **`require_verified_email`** defaults to `true`; disabling it (per issuer)
  should only be done for IdPs known not to set `email_verified`, since an
  unverified email is not a reliable identity claim.

## SOCKS proxy tunnels and egress risk

### Operator-visible risk capabilities

At startup and after a configuration reload, ntwire logs the stable
`security_capabilities` event. Its `capabilities` array contains only enabled
high-risk configuration classes, never tunnel names, identities, URLs, or
secrets. The same array is available to an authenticated operator in
`GET /v1/dashboard?token=...` as `security_capabilities`. Current values are
`authorization_hook`, `socks_unrestricted`, `socks_bind`,
`socks_local_egress`, `relay_mediated_udp`, and `direct_udp_relay_bypass`. An empty array means none
of these opt-ins is configured. Client-side `--insecure` emits the separate
`insecure_tls_enabled` warning when a connection is established.

A `target: socks` tunnel is a governed general-purpose egress proxy, not a
fixed-destination forward: every session holding its grant can reach every
destination the tunnel's `socks:` filters permit, and the server itself, not
just the client, initiates each of those outbound connections and DNS
resolutions. Weigh that before granting one broadly:

`target: socks` with `socks.transparent: true` is different: ntwire
authorizes and applies destination policy only to its configured
`socks.upstream` endpoint. The subsequent SOCKS5 requests are opaque to
ntwire, so use it only when that upstream service is trusted to enforce
destination and authentication policy.

Fixed `protocol: udp` tunnels are narrower: each source IP/port receives its
own connected upstream flow, replies are sent only to that source, and idle
flows expire after two minutes by default. The target is resolved, authorized,
and then dialled as that exact IP, so policy evaluation cannot be bypassed by
DNS rebinding.

- **Loopback and link-local destinations are denied unconditionally.** No
  `socks:` configuration reaches the server's own `127.0.0.0/8` or `::1`, the
  link-local range that carries cloud instance metadata
  (`169.254.169.254` and its IPv6 equivalent), or the unspecified address --
  not `allow_all`, not a `0.0.0.0/0` filter, and not `reverse_filters`, since
  the check runs before all three. Those destinations trust the *server's*
  network position rather than the requester's, so reaching them through a
  tunnel is request forgery. Set `socks.allow_local_egress: true` to opt back
  in for the legitimate "proxy to a service on the server host" case; it is
  reported as the `socks_local_egress` security capability when enabled.
  (Fixed `target:` tunnels are unaffected: their destination is chosen by the
  operator in configuration, not by the requester.)
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
  against the resolved IP. This is also the final address for direct and
  `socks5://` upstream connections. With an explicitly configured,
  trusted `socks5h://` upstream, ntwire sends the authorized original hostname
  to that upstream for final DNS resolution; use this only when that upstream
  is within the destination-policy trust boundary.
- **UDP ASSOCIATE is control-session-bound.** ntwire creates one private
  virtual UDP listener per SOCKS5 control connection, accepts packets only
  from that connection's authenticated tunnel IP, rejects fragmented SOCKS
  datagrams, and expires inactive destination flows. `socks.upstream` applies
  to TCP CONNECT only; UDP is never silently sent through another proxy.
- **BIND is independently opt-in and opens a real, temporary *inbound*
  listener on the server host.** Set `socks.allow_bind: true` only when this
  legacy behavior is required; it remains disabled even when SOCKS CONNECT or
  `allow_all` is enabled. When enabled it is
  reachable from any address that can route to it (not just over the
  WireGuard tunnel), for up to two minutes while it waits for one peer to
  connect — the same `socks:` filters gate the request's declared target
  address beforehand, but, matching upstream, the peer that actually
  connects to that listener is never itself re-checked against them.

## Native WireGuard and destination policies

Native peers are static cryptographic peers in the existing userspace WireGuard device, not bearer-token sessions. Their configured IPs are reserved from dynamic allocation. Keep the persistent server WireGuard key and all client private keys out of source control. Tunnel grants are checked before destination policies; peer and tunnel policies compose as restrictive AND rules. Fixed-target policies evaluate the chosen resolved IP before it is dialled. See `NATIVE-WIREGUARD.md` and `DESTINATION-POLICIES.md`.

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

## Operator and client-UI tokens are not query parameters

Two credentials guard local control surfaces: `admin.web_ui_token` on the
server's metrics listener, and the per-process access token on `ntwire
connect`'s local status UI. Both used to travel as `?token=`, which put them
in access logs, proxy logs, and browser history on every poll, and made them
available to any external link the page rendered via `Referer`.

Both now work the same way:

- **Presented as `Authorization: Bearer …`** by programmatic callers (`curl`,
  `ntwire status`, `ntwire list`).
- **Exchanged once at `GET /`** for an `HttpOnly; SameSite=Lax` cookie, with
  an immediate redirect that drops the parameter from the address bar before
  the page loads. This is why the URL `ntwire connect` prints still contains a
  token: it is the way in, used once.
- **State-changing routes require more than the cookie.** The server's
  `POST /v1/admin/sessions/{id}/revoke` requires the header specifically, and
  the client UI's write routes reject a foreign `Origin`. A browser attaches a
  cookie to a cross-site request but can attach neither, so the cookie cannot
  become a CSRF vector.

`admin.web_ui_token` must be at least 32 characters — the server refuses to
start otherwise — and the whole metrics listener is rate-limited per source
address. The client status UI additionally sends `Referrer-Policy:
no-referrer`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, and a CSP
whose `connect-src 'self'` bounds where script on that page could send the
token. Its `frame-src` permits only the configured numeric loopback Settings
origin (including its port); without a valid local Settings URL, frames are
blocked. The Settings URL's access token is never included in this policy.

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
- The inverse mistake is configuring that same `*.relay.example.com`
  certificate on the relay and assuming it now protects client traffic on
  `listen.public` — it does not. That port never terminates TLS (see
  [RELAY.md#tls-certificates-for-the-public-listener-pac-and-browser-clients](RELAY.md#tls-certificates-for-the-public-listener-pac-and-browser-clients)),
  so clients still see the origin server's own certificate, self-signed by
  default. The `ntwire` client's fingerprint pinning does not care, but an
  iOS/OS proxy auto-config fetch or a browser does ordinary hostname/chain
  validation with no TOFU step and fails closed against a self-signed
  certificate with no prompt. Put a CA-issued certificate on the **origin
  server** for that case — [LETSENCRYPT.md](LETSENCRYPT.md) covers obtaining
  one via DNS-01 when the server has no inbound connectivity of its own.
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
- `listen.agents` is rate-limited per source address
  (`limits.max_registrations_per_minute`), caps connections accepted but not
  yet registered (`limits.max_pending_registrations`), and requires the
  registration message within `limits.handshake_timeout`. All three are needed
  because that listener must be internet-facing for a NAT'd server to dial out
  to it, and `net/http`'s own header timeout stops applying once the
  connection is upgraded to a WebSocket: without them, anyone who can reach
  the port can hold goroutines and file descriptors open indefinitely and deny
  service to every tenant. Its TLS floor is 1.3, matching the server's.
- Rate limiting on `listen.public` (`limits.max_new_conns_per_minute`) is
  **mandatory**, unlike the server's `allowSource`, because the relay is
  internet-facing and a relay is a **dial-back amplification vector**: every
  inbound connection with a valid, registered SNI forces the origin server to
  open an outbound data connection. `limits.max_pending_per_server` and
  `limits.max_conns_per_server` cap this per tenant, independent of the
  source-IP rate limit.

## Portal security model

The ntwire Portal (see [PORTAL.md](PORTAL.md)) follows strict least-privilege and defense-in-depth principles:

### Untrusted template isolation
Portal templates are treated as untrusted declarative content. The template engine:
* Executes in a sandboxed, restricted AST evaluator with no runtime reflection, filesystem access, command execution, or network capabilities.
* Limits template evaluation output size to prevent memory exhaustion (DoS).
* Rejects raw HTML in template text outright (any `<` opening a tag), rather
  than enumerating dangerous tags and attributes. A portal template is
  Markdown, so no raw tag has a legitimate use, and an allowlist has no gaps
  to find — an earlier blocklist naming `onclick`/`onload`/`onerror` left
  `onmouseover`, `onfocus`, `srcdoc` and `formaction` through.

**Escaping, not validation, is what makes rendered content safe.** Template
validation runs at configuration load and sees only the template source, never
the values interpolated into it at render time — a target `description`, an
identity, a client-reported hostname. The Markdown renderer therefore
HTML-escapes every run of caller-supplied text *as it emits it*, and never
re-scans its own output for markup. There is no pass in which caller text and
generated markup share a string.

### Content-Security-Policy
The in-tunnel web portal's `script-src` is a **per-response nonce**, not
`'unsafe-inline'`. This matters because `'unsafe-inline'` permits inline event
handler attributes, which is exactly the shape an escaping bug would produce:
under a nonce, an injected `onmouseover=` cannot execute even if it reaches the
DOM. The page's own inline script carries the nonce; it has no inline handler
attributes of its own.

### The client never renders server HTML
The `/v1/portal` response carries both `markdown` and a rendered `html`. The
reference client **ignores `html`** and parses `markdown` with its own parser,
building DOM nodes from the resulting block tree. This is deliberately
independent of the server-side escaping above: the client's local status UI
origin holds that UI's own access token, and script running there could rebind
a tunnel listener onto a LAN interface (`PUT /tunnels/{name}`) or launch a
browser. A hostile server does not have to defeat any sanitizer to put markup
in a JSON field, so the client must not treat that field as markup at all.
`html` is deprecated; see [PROTOCOL.md](PROTOCOL.md#successful-response).

### Portal action URLs
A portal action resolves to a target the session is granted, and separately to
a URL. Authorization answers *which target*, never *what URL*, so the URL is
validated as an absolute `http(s)` URL at three points: the server drops an
unusable one from the action response, the client refuses one before
dispatching, and `pkg/browseropen` refuses one at the launcher and places any
URL after a `--` flag terminator. The launcher check is not redundant:
Chromium reads an argument beginning with `-` as a switch, so a target URL of
`--load-extension=…` or `--remote-debugging-port=…` would otherwise be honoured
as one, and `open`/`xdg-open` would act on a local path.

### Authorization-filtered context
Portal rendering occurs **exclusively** against pre-filtered target sets. A client receives only target metadata for tunnels granted to that specific session or peer identity. Target names, descriptions, and categories for unauthorized resources are never included in the JSON payload, Markdown, or HTML sent to the client.

### Action revalidation
Client portal actions (e.g. `ntwire://open/<target_id>`) do not execute arbitrary commands or URLs. Both the server action endpoint (`POST /v1/portal/action`) and the native client action dispatcher verify that `<target_id>` belongs to the user's active, granted tunnels before launching the isolated browser profile or proxy.

### WireGuard HTTP web portal defenses
The in-tunnel WireGuard web portal:
* Maps incoming TCP connections to authenticated identities via the client's overlay IP address (`r.RemoteAddr`).
* Fails closed: if the client IP address does not match an active authenticated session or native peer table entry, the request is immediately rejected with `403 Forbidden`.
* Applies strict HTTP security headers:
  * `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-<per-response>'; img-src 'self' data:; connect-src 'self'`
  * `X-Content-Type-Options: nosniff`
  * `X-Frame-Options: DENY`
  * `Referrer-Policy: no-referrer`
  * `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  * `Cache-Control: no-store, no-cache, must-revalidate`

## Security boundary enforcement

Control request bodies have a per-request read deadline and are decoded before
session lifecycle locking. WebSocket streams retain their independent lifetime.
Data-plane lookups reject expired records even before cleanup runs.

A dynamic WireGuard key is owned by its authenticated method, identity and OIDC
issuer. Reconnect cannot claim another owner's key or a configured native key.
Reload retires conflicting dynamic key/IP reservations before installing native
peers, and policy attachment changes rebuild affected TCP, UDP and SOCKS runtimes.
MASQUE uses the same destination authorization and exact-IP dialing as fixed tunnels.

Native relay handshake routing state has a hard 4096-entry FIFO bound with
constant-cost admission. Discovered Kubernetes routes share per-route pending/live
limits and retain accounting until outstanding connections are released.

Reusable GUI credentials stay out of browser-launch arguments. Browser fallback
uses a private temporary document (0700 directory, 0600 file), removed after the
startup window. The settings page retains query-token authentication and setup
parameters, issues no authentication cookies, and rejects foreign-origin writes.

Instruction templates allow field substitution, bounded `if`/`with` branches and
simple comparisons/boolean operations. Loops, template calls, variable declarations
and formatting functions are displayed literally. Output is capped during writing,
and rendering runs after releasing the connection lock.

## Client self-updates

The CLI and GUI trust only an embedded Ed25519 update-verification public key.
Stable release discovery is over HTTPS; installation requires a valid signed,
complete client manifest and the exact archive size/SHA-256. Missing trust keys,
invalid signatures, incomplete releases, unsupported platforms, equal/older
versions and development-build installation fail closed. Extraction rejects
traversal, links, special files, duplicate/case-colliding paths and unexpected
content, with bounded compressed and expanded sizes.

A separate helper waits for the GUI process to exit after it closes its windows
and tunnels. It re-verifies signed release evidence and a private destination-side
archive snapshot before replacing the standalone binary or complete macOS bundle.
Replacement is serialized and retains a previous installation for rollback;
forced termination during activation may require manual recovery. Background work
never requests elevation. Explicit elevated helpers run only after OS consent;
cache files and release metadata are not a source of trust. See
[UPDATES.md](UPDATES.md) for signing-secret provisioning, key rotation, recovery,
and native release acceptance. Update signatures do not provide Apple Developer
ID notarization or Windows Authenticode signing.

## GUI outbound proxy credentials

The authenticated loopback settings API exposes only the six HTTP(S)_PROXY and
NO_PROXY environment variants for proxy diagnostics. URL passwords are masked
in diagnostics, profile responses and SSE snapshots. No outbound request is
made by diagnostics. Custom proxy credentials are stored in `gui.yaml` under
the existing atomic mode-0600 profile-store policy; protect this file and backups.
A blank replacement field retains the saved URL. Supplying a complete replacement
URL explicitly replaces credentials; omitting userinfo clears them. Environment
and direct modes clear the custom URL. Direct mode changes only ntwire's
application proxy selection and does not override network security controls.

### Locally configured SOCKS browser switches

Extra browser arguments are an operator-controlled local setting, separate from
server-provided portal URLs. They are passed literally without a shell, validated
at save and launch, and cannot override ntwire's managed proxy and profile
switches. Server-provided URLs still require absolute HTTP(S) validation and are
placed after the flag terminator. Unknown browser switches are allowed, so local
configuration must be trusted: validation does not guarantee prevention of every
traffic leak or unsafe browser feature. See [configuration](CONFIGURATION.md#extra-browser-arguments).

## Mixed local proxy listener

Browser-capable SOCKS tunnel client ports also accept HTTP/1.x forward-proxy
requests and CONNECT. HTTP destinations are dialed only via the captured
WireGuard stack and the granted server SOCKS endpoint; hostnames are passed
unchanged for remote resolution. Environment proxies are not used for these
requests. Server-side SOCKS destination authorization applies equally to HTTP
and SOCKS, including denied destinations. Fixed and transparent tunnels retain
their existing behavior.

The listener retains its configured bind address and loopback default. There
is no additional HTTP authentication: exposing a client proxy port allows
reachable users to exercise that client's granted destination access. Proxy
credentials and hop-by-hop headers are removed before forwarding (upgrade
headers are preserved as required). No forwarded identity headers are added.
HTTP errors do not reveal raw upstream errors or internal tunnel addresses.
TLS-to-proxy and HTTP/2/3 proxy protocols are not supported; HTTPS destinations
use CONNECT without TLS interception.
