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
discovery, scopes, and `client_id` all come from the server.

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
  "tunnels": [{"name":"reports", "virtual_port":18080, "target_hint":"reports.internal:8080"}],
  "udp_endpoint": "vpn.example:51820",
  "websocket_endpoint": "wss://vpn.example:8443/v1/wg"
}
```

`token` is a bearer credential and authenticates the WebSocket endpoint.
Each binary WebSocket message is one WireGuard datagram. `target_hint` comes from server configuration;
it is not a request to dial arbitrary targets. `udp_endpoint` mirrors
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
{"version": 1, "name": "home", "domain": "relay.example.com"}
```

or, on failure, `{"version":1,"error":"...","code":"..."}` and closes the
connection. `name` in the response is authoritative from the relay's own
`registrations` config, never an echo of the request.

### Signing payload

Structured identically to `/v1/auth`'s signing payload, but with its own
domain separator, since `name` is a field `/v1/auth`'s payload does not cover:

1. Write ASCII `ntwire-relay-register-v1` followed by a zero byte.
2. Length-prefix (32-bit big-endian) and write, in order: `public_key`,
   `name`, `timestamp`, `nonce`.

A signature produced for `/v1/auth` does not verify as a relay registration,
and vice versa, even when field values overlap.

### Verification order

Timestamp within ±2 minutes of the relay's clock → nonce unseen (5-minute
cache) → fingerprint present in the relay's `registrations` (else
`unknown_key`) → signature valid (else `bad_signature`) → `name` matches the
fingerprint's configured name (else `relay_name_not_allowed`, a new error
code). A successful registration evicts and closes any prior control
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
