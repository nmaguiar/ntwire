# ntwire control protocol v1

This is the implemented control-plane protocol. It authenticates a client and
returns tunnel grants and the values needed to establish a WireGuard netstack
session and forward TCP traffic.

## Endpoints

The reference server serves HTTPS.

| Method and path | Authentication | Result |
| --- | --- | --- |
| `GET /v1/info` | None | Protocol version, capabilities, and OIDC issuers |
| `POST /v1/auth` | SSH request signature | New session and grants |
| `POST /v1/auth/oidc` | Verified OIDC ID token | New session and grants |
| `POST /v1/renew` | Bearer token | Replacement session and grants |
| `POST /v1/disconnect` | Bearer token | Deletes a session |
| `GET /v1/wg` | Bearer token | WireGuard datagrams over binary WebSocket messages |
| `POST /v1/punch` | Bearer token | Candidate exchange for the opportunistic direct-UDP upgrade; `404` unless `relay.advertise_direct` is enabled |

`GET /v1/info` returns:

```json
{
  "version": 1,
  "capabilities": ["ssh-auth", "oidc-auth", "tcp"],
  "oidc_issuers": [
    {
      "name": "google",
      "issuer": "https://accounts.google.com",
      "client_id": "1234-abc.apps.googleusercontent.com",
      "client_secret": "",
      "scopes": ["openid", "email", "profile"],
      "groups_claim": ""
    }
  ]
}
```

`ssh-auth` and `oidc-auth` are present only when the corresponding
`auth.authorized_keys_dir` / `auth.oidc.issuers` configuration is set; at
least one is always present. The `tcp` capability indicates TCP tunnel
forwarding support. `oidc_issuers` is omitted (or empty) when `oidc-auth` is
absent, and lets a client run the login flow with zero local configuration:
discovery, scopes, and `client_id` all come from the server. `client_secret`
is empty/omitted for most issuers; it's only populated for IdPs whose token
endpoint requires it even for a public/PKCE client (e.g. Google's "Desktop
app" type — see docs/OIDC-SETUP.md). It is not treated as confidential.

## Authentication request

`POST /v1/auth` accepts a JSON request no larger than 1 MiB:

```json
{
  "version": 1,
  "public_key": "ssh-ed25519 AAAA...",
  "wireguard_public_key": "",
  "timestamp": "2026-07-17T12:00:00Z",
  "nonce": "base64url-random-value",
  "client_info": {
    "os": "darwin",
    "arch": "arm64",
    "hostname": "laptop",
    "username": "alice",
    "client_version": "dev",
    "latency_millis": 18,
    "reconnections": 1,
    "extra": {"example": "value"}
  },
  "signature": "base64-encoded-ssh-signature"
}
```

`public_key` is OpenSSH `authorized_keys` text. The timestamp must be RFC 3339
and within two minutes of the server clock. A non-empty nonce is accepted only
once; accepted nonces are remembered for five minutes. The key must be in the
configured authorized-key directory.

### Signing payload

The signature is over binary data, never a JSON serialization:

1. Write ASCII `ntwire-auth-v1` followed by a zero byte.
2. For each string below, write its byte length as an unsigned 32-bit
   big-endian integer followed by its UTF-8 bytes.

The strings are, in order: `public_key`, `wireguard_public_key`, `timestamp`,
`nonce`, `client_info.os`, `client_info.arch`, `client_info.hostname`,
`client_info.username`, and `client_info.client_version`. Append each
`client_info.extra` key and value after that, sorted lexicographically by key.
No field may exceed 1 MiB.

`client_info.latency_millis` and `client_info.reconnections` are optional
client telemetry used for operator status and metrics. They are intentionally
not part of the signed payload so servers remain compatible with existing v1
clients; do not use them for authorization decisions.

## OIDC authentication request

`POST /v1/auth/oidc` accepts a JSON request no larger than 1 MiB:

```json
{
  "version": 1,
  "issuer_name": "google",
  "id_token": "eyJhbGciOi...",
  "wireguard_public_key": "",
  "timestamp": "2026-07-17T12:00:00Z",
  "client_info": {"os": "darwin", "arch": "arm64"}
}
```

`issuer_name` selects one of the issuers advertised by `/v1/info`. There is no
signature and no nonce cache: unlike the SSH request, the ID token is not a
value the client can forge, and it carries its own `exp`/`iat`, which bound
replay on their own. `timestamp` still must be RFC 3339 and within two minutes
of the server clock, as an extra freshness check, and the existing
per-source-IP rate limit applies identically to both auth endpoints.

The server verifies `id_token`'s signature against the issuer's JWKS (fetched
and cached via OIDC discovery), checks `aud` equals the issuer's configured
`client_id`, checks expiry, and — unless `require_verified_email: false` — the
`email_verified` claim. The resulting identity is the token's `email` claim;
`groups_claim`, when configured, supplies the `group:` values used for grant
matching. A failure at any step returns `401`.

## Successful response

SSH authentication, OIDC authentication, and renewal all return `200 OK` with
the same shape:

```json
{
  "session_id": "...",
  "token": "...",
  "ttl_seconds": 900,
  "tunnels": [{"name":"reports", "virtual_port":18080, "target_hint":"reports.internal:8080",
               "instructions":"curl http://{{.LocalHost}}:{{.LocalPort}}/", "docs_url":"https://wiki/reports"}],
  "udp_endpoint": "vpn.example:51820",
  "websocket_endpoint": "wss://vpn.example:8443/v1/wg"
}
```

`token` is a bearer credential and authenticates the WebSocket endpoint.
Each binary WebSocket message is one WireGuard datagram. `target_hint` comes from server configuration;
it is not a request to dial arbitrary targets. `instructions` and `docs_url` are
optional per-tunnel setup guidance for the client's status UI: the client
expands `instructions` as a Go template against its own bound port and renders
the result as Markdown (see [CONFIGURATION.md](CONFIGURATION.md#tunnel-instructions)),
and ignores a `docs_url` that is not an absolute `http(s)` URL. `udp_endpoint` mirrors
`network.advertised_endpoint`, which clients use for the WireGuard peer.

Errors are JSON objects of the form `{"error":"message"}`. Malformed input
returns `400`; authentication or session failures return `401`; an authorizer
denial returns `403`.

Authentication failures may include an additive `code` field in the JSON
error: `invalid_request`, `clock_skew`, `replayed_nonce`, `unknown_key`,
`bad_signature`, `rate_limited`, `not_allowed`, `max_sessions`,
`oidc_invalid_token`, `no_capacity`, or `invalid_wireguard_key`. Successful
authentication and renewal responses may include `identity` and `method`
(`ssh` or `oidc`). Older peers may omit all of these fields.

## Renewal and disconnect

`POST /v1/renew` requires `Authorization: Bearer TOKEN` and a body with
`client_info`. It runs the authorizer again against the old session's tunnels,
invalidates the old token, and returns a replacement response — for an OIDC
session this reuses the identity/issuer/groups established at authentication
time; it does not re-verify an ID token or require a fresh one, since renewal
is bound to the opaque session token, not the ID token's own expiry. `POST
/v1/disconnect` needs the same header, has no body, and returns `204 No
Content` after deletion.

The server reaps expired sessions in the background and removes their
WireGuard peers.

## Grant matching and the SSH/OIDC namespace

A tunnel's `allow` list is matched against the authenticated request's
*method*, never against raw strings alone: an SSH request is compared only to
fingerprint and `authorized_keys`-comment entries, and an OIDC request only to
exact-email, `@domain`, and `group:` entries. `"*"` matches either method.

This means an SSH key commented `alice@corp.com` and an OIDC identity
`alice@corp.com` can appear in the same `allow` list without one being able to
satisfy the other's grant — the SSH request is never compared against the
email-shaped entry as an email, and the OIDC request is never compared against
it as a comment. There is no code path where a party who controls one identity
can be granted access intended for the other.

In practice, the reference client never sends a key comment (a private key
file carries none), so comment-based SSH grants only work against requests
built to include one; prefer fingerprints for SSH `allow` entries.

## Authorizer hook additions for OIDC

The authorizer hook input (`POST` body or stdin JSON, see
[AUTHORIZATION.md](AUTHORIZATION.md)) gains:

| Field | SSH | OIDC |
| --- | --- | --- |
| `auth_method` | `"ssh"` | `"oidc"` |
| `key_fingerprint` / `key_comment` | populated | empty |
| `identity` | empty | verified email |
| `issuer` | empty | configured issuer name |
| `groups` | empty | from `groups_claim`, if configured |

## Relay registration protocol (ntwire-server ↔ ntwire-relay)

An ntwire-server behind NAT can dial out to a public `ntwire-relay` instead of
listening for inbound connections. This is a separate protocol from client
authentication above: it runs between an ntwire-server and an ntwire-relay
over the relay's `agents` HTTPS listener, and never involves the ntwire
client. See [SECURITY.md#the-relays-trust-model](SECURITY.md#the-relays-trust-model)
for the trust model — the relay is untrusted for confidentiality and
integrity, trusted only for availability.

`GET /v1/relay/control` upgrades to a long-lived WebSocket. The server sends
one JSON `RelayRegisterRequest` text message to claim a tenant name:

```json
{
  "version": 1,
  "public_key": "ssh-ed25519 AAAA... admin@laptop",
  "name": "home",
  "timestamp": "2026-07-17T12:00:00Z",
  "nonce": "base64url-random-value",
  "signature": "base64-encoded-ssh-signature"
}
```

The relay replies with `RelayRegisterResponse`:

```json
{"version": 1, "name": "home", "domain": "relay.example.com", "reflect_addr": "203.0.113.10:3480", "udp_relay_addr": "203.0.113.10:3481"}
```

or, on failure, `{"version":1,"error":"...","code":"..."}` and closes the
connection. `name` in the response is authoritative from the relay's own
`registrations` config, never an echo of the request. `reflect_addr` is the
relay's `listen.reflect` UDP address, empty when that is not configured; see
[below](#udp-address-reflection-and-v1punch) and
[RELAY.md](RELAY.md#opportunistic-direct-udp-upgrade). `udp_relay_addr` is the
relay's shared client-facing UDP address for the UDP-relay forwarding tier,
empty when `listen.udp_relay` is not configured; see
[below](#relay-mediated-udp-forwarding-and-v1udp-relay) and
[RELAY.md](RELAY.md#relay-mediated-udp-forwarding). Unlike `reflect_addr`,
a registered server acts on a non-empty `udp_relay_addr` unconditionally —
there is no `advertise_direct`-style opt-in to check first.

### Signing payload

Structured identically to `/v1/auth`'s signing payload, but with its own
domain separator, since `name` is a field `/v1/auth`'s payload does not cover:

1. Write ASCII `ntwire-relay-register-v1` followed by a zero byte.
2. Length-prefix (32-bit big-endian) and write, in order: `public_key`,
   `name`, `timestamp`, `nonce`.

A signature produced for `/v1/auth` does not verify as a relay registration,
and vice versa, even when field values overlap.

### Verification order

Timestamp within ±2 minutes of the relay's clock → fingerprint present in the
relay's `registrations` (else `unknown_key`) → signature valid (else
`bad_signature`) → nonce unseen (5-minute cache, size-capped as a backstop;
else `replayed_nonce`) → `name` matches the fingerprint's configured name
(else `relay_name_not_allowed`, a new error code). Nonce replay is checked
only after the signature verifies: consuming a nonce slot for an
unauthenticated request would let anyone who can merely reach `listen.agents`
exhaust the cache without ever presenting a valid key. A successful
registration evicts and closes any prior control
connection already registered under that name (last-writer-wins): this is
both how a duplicate claim is rejected and how a server reconnecting after a
drop replaces its own stale connection, with no separate timeout to tune.

### Data connections and `RelayOpen`

Once registered, the relay pushes a `RelayOpen` message over the control
connection for every inbound public TCP connection whose SNI resolves to that
server's tenant name:

```json
{"conn_id": "base64-random-32-bytes", "client_addr": "203.0.113.5:51422", "sni": "home.relay.example.com"}
```

The server then opens `GET /v1/relay/data?conn_id=...` — a second WebSocket,
one per inbound client connection — and the relay splices the raw TLS bytes
of that client connection into it verbatim, without ever terminating the
client's TLS session. `conn_id` is a single-use, 10-second-TTL bearer
capability minted by the relay and handed out only over the
already-authenticated control connection; it is not itself signed.

The origin ntwire-server observes the relayed connection through its normal
`net.Listener`/`http.Server.ServeTLS` path, with one difference: the
connection's `RemoteAddr()` reports `client_addr` from `RelayOpen`, not the
relay's own address, so per-source-IP rate limiting and audit logging remain
correct across a relay hop.

### Control-message dispatch: the `type`-sniff convention

`RelayOpen` above carries no `"type"` field — it predates every other message
that can arrive on this same control connection. Every message added since
(`RelayUDPAllocateRequest`/`Response`, `RelayUDPRelease`, described next) does
carry one, and the receiving side dispatches by sniffing it: a message with a
recognized `"type"` is handled as that message; a message with no `"type"`
field at all falls through and is unmarshaled as `RelayOpen`, unchanged from
today. This is the general convention for any future control-connection
message type, not just the ones this document currently describes — it lets
a relay and server mismatched by one version keep working for whichever
message shapes they both understand, rather than one side failing to parse
the connection at all.

### Relay-mediated UDP forwarding and `/v1/udp-relay`

When `listen.udp_relay` is configured, the relay also lets a registered
server allocate one UDP-relay session per connecting client over this same
control connection — the middle rung between the WebSocket fallback and the
full direct-UDP escape described next (see
[RELAY.md](RELAY.md#relay-mediated-udp-forwarding) for the design and the
anti-amplification/TURN-style permission model). The server sends
`RelayUDPAllocateRequest`:

```json
{"type": "udp_allocate", "request_id": "base64url-random-value"}
```

and the relay replies `RelayUDPAllocateResponse`, correlated by `request_id`
(the connection can carry more than one concurrent allocation in flight, one
per connecting client):

```json
{"type": "udp_allocate_reply", "request_id": "base64url-random-value", "token": "base64url-random-value", "server_addr": "203.0.113.10:20017"}
```

or, on failure (the pool is exhausted, or this tenant is already at
`limits.max_udp_relay_sessions_per_server`), an error/code pair instead of
`token`/`server_addr`: `{"type":"udp_allocate_reply","request_id":"...","error":"...","code":"udp_relay_pool_exhausted"}`
or `code: "udp_relay_tenant_at_capacity"`. `server_addr` is one of the
relay's pooled `listen.udp_relay_ports` addresses, dedicated to this session
until it is released or idle-swept.

The server then binds its own leg by sending a `FrameRelayBind` datagram (see
the frame table [below](#udp-address-reflection-and-v1punch)) carrying
`token` to `server_addr`, and resends it periodically as a keepalive — this
is the same `send-then-keepalive` shape `FramePrime` uses for the direct-UDP
upgrade, just carrying a token instead of being an empty ping. When the
server's session for a client ends, it sends `RelayUDPRelease` (one-way,
best-effort — the relay's `limits.udp_relay_idle_timeout` sweep is the
backstop if it never arrives):

```json
{"type": "udp_release", "token": "base64url-random-value"}
```

`POST /v1/udp-relay` (Bearer token, same session as `/v1/wg`) is the
client-facing endpoint that triggers this allocation — empty request body
(`UDPRelayRequest`), keyed server-side by the client's WireGuard public key
so a repeat call (every retry cycle, every `/v1/renew`) is idempotent and
returns the same session rather than consuming a second one:

```json
// response
{"relay_addr": "203.0.113.10:3481", "token": "base64url-random-value"}
```

All fields empty means the tier isn't available right now — no live relay
connection, the relay doesn't offer `listen.udp_relay`, or this server
predates the feature — and the client treats that exactly like a `404` from
`/v1/punch`, not a hard error. Note that none of this allocation dance
touches raw UDP itself: the server learns its assigned port entirely over
the already-TLS-protected control connection, and the client learns
`relay_addr`/`token` entirely over the already-TLS-protected `/v1/udp-relay`
call — the first UDP datagram either side ever sends is the bind frame
itself, sent only once each already holds a token minted over TLS, which is
also why the port-restricted-NAT "who sends the first packet" ordering
concern that a naive raw-UDP-first design would have to worry about does
not apply here.

Once both the server's and the client's leg have completed a bind for the
same token, the relay forwards ordinary WireGuard datagrams between them
verbatim; a datagram for a session with only one leg bound is dropped, never
buffered.

### UDP address reflection and `/v1/punch`

When `listen.reflect` is configured, the relay also answers a minimal,
stateless UDP address-reflection protocol on that port — used by a server
with `relay.advertise_direct` enabled, and by clients connecting to one, to
learn their own NAT-mapped UDP address for the opportunistic direct-UDP
upgrade (see [RELAY.md](RELAY.md#opportunistic-direct-udp-upgrade)). This is
independent of `/v1/relay/control` and `/v1/relay/data` above: the reflector
never authenticates callers, holds no per-sender state, and never sees
WireGuard traffic.

Every datagram in this protocol shares a 5-byte header: 4 magic bytes
(`0x00 'N' 'T' 'W'`, chosen so byte 0 can never collide with a real
WireGuard packet's first byte, always 1-4) followed by a 1-byte frame type.
The reflector only ever handles two of the three defined frame types:

| Frame type | Value | Direction | Payload |
| --- | --- | --- | --- |
| `FrameReflectRequest` | `1` | caller → reflector | none |
| `FrameReflectResponse` | `2` | reflector → caller | the caller's observed `ip:port`, as text |
| `FramePrime` | `3` | peer → peer, direct | none; a NAT-priming ping, never sent to the reflector |
| `FrameRelayBind` | `4` | server/client → relay | the session `token` |
| `FrameRelayBindAck` | `5` | relay → server/client | none; sent only for a bind with a valid, live token |

A caller (server or client) sends `FrameReflectRequest` to `reflect_addr`
and gets back `FrameReflectResponse` with its own address as the relay
observed it. Once both sides of a connection know each other's candidate —
exchanged via the ordinary, already-authenticated client↔server channel
below, not through the relay — they send a short burst of `FramePrime`
frames directly to each other before attempting a real WireGuard handshake,
to open both NAT mappings first.

`FrameRelayBind`/`FrameRelayBindAck` belong to the UDP-relay forwarding tier
described [above](#relay-mediated-udp-forwarding-and-v1udp-relay), not the
reflector — they carry a session token rather than being addressed by the
reflector's request/response shape, and each is sent to one of the tier's
own sockets (`listen.udp_relay` from the client, or the session's own pooled
`listen.udp_relay_ports` address from the server), never to `reflect_addr`.

`POST /v1/punch` (Bearer token, same session as `/v1/wg`) is the
client↔server exchange that carries those candidates:

```json
// request
{"client_addr": "203.0.113.5:51422"}
// response
{"server_addr": "198.51.100.7:51820", "relay_reflect_addr": "203.0.113.10:3480"}
```

`client_addr` is empty on a client's first call, made only to learn
`relay_reflect_addr`; it self-reflects off that address and calls again with
`client_addr` filled in. `server_addr` is the server's own most recently
self-reflected candidate, empty if it has none yet. A server without
`relay.advertise_direct` enabled (or predating this feature) answers `404`
to `/v1/punch` entirely.
