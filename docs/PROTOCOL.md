# nwire control protocol v1

This is the implemented control-plane protocol. It authenticates a client and
returns tunnel grants and the values needed to establish a WireGuard netstack
session and forward TCP traffic.

## Endpoints

The reference server serves HTTPS.

| Method and path | Authentication | Result |
| --- | --- | --- |
| `GET /v1/info` | None | Protocol version and capabilities |
| `POST /v1/auth` | SSH request signature | New session and grants |
| `POST /v1/renew` | Bearer token | Replacement session and grants |
| `POST /v1/disconnect` | Bearer token | Deletes a session |
| `GET /v1/wg` | Bearer token | WireGuard datagrams over binary WebSocket messages |

`GET /v1/info` returns `{"version":1,"capabilities":["ssh-auth","tcp"]}`.
The `tcp` capability indicates TCP tunnel forwarding support.

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

1. Write ASCII `nwire-auth-v1` followed by a zero byte.
2. For each string below, write its byte length as an unsigned 32-bit
   big-endian integer followed by its UTF-8 bytes.

The strings are, in order: `public_key`, `wireguard_public_key`, `timestamp`,
`nonce`, `client_info.os`, `client_info.arch`, `client_info.hostname`,
`client_info.username`, and `client_info.client_version`. Append each
`client_info.extra` key and value after that, sorted lexicographically by key.
No field may exceed 1 MiB.

## Successful response

Authentication and renewal return `200 OK` with:

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

## Renewal and disconnect

`POST /v1/renew` requires `Authorization: Bearer TOKEN` and a body with
`client_info`. It runs the authorizer again against the old session's tunnels,
invalidates the old token, and returns a replacement response. `POST
/v1/disconnect` needs the same header, has no body, and returns `204 No
Content` after deletion.

The server reaps expired sessions in the background and removes their
WireGuard peers.
