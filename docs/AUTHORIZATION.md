# Authorization hooks

With no `authorizer` configured, YAML grants (the `tunnels[].allow` lists in
[CONFIGURATION.md](CONFIGURATION.md)) are accepted directly. A webhook or
executable can additionally deny a request, narrow its tunnel list, and
shorten its session lifetime:

```yaml
authorizer:
  webhook_url: ""   # POST request JSON to this URL for a per-connection allow/deny decision; takes precedence when both hook options are set
  exec: ""           # path to an executable that reads the same JSON on stdin and returns a decision when webhook_url is empty
  timeout: 5s         # deadline for the webhook call or executable run; a timeout denies the request; default: 5s
```

Errors, timeouts, malformed responses, non-2xx webhook responses, and
non-zero executable exits deny the request — the hook fails closed.

## Request

The hook receives JSON by HTTP POST or standard input. An SSH session looks
like:

```json
{
  "source_ip": "127.0.0.1:50123",
  "session_id": "",
  "key_fingerprint": "SHA256:...",
  "key_comment": "alice@laptop",
  "auth_method": "ssh",
  "client_info": {"os": "darwin", "arch": "arm64"},
  "granted_tunnels_by_yaml": ["reports"],
  "requested_at": "2026-07-17T12:00:00Z"
}
```

An OIDC session sends `auth_method: "oidc"` with `key_fingerprint`/`key_comment`
empty and adds `identity` (the verified email), `issuer` (the configured issuer
name), and `groups` (from `groups_claim`, when configured):

```json
{
  "source_ip": "127.0.0.1:50123",
  "session_id": "",
  "auth_method": "oidc",
  "identity": "alice@corp.com",
  "issuer": "google",
  "groups": ["engineering"],
  "client_info": {"os": "darwin", "arch": "arm64"},
  "granted_tunnels_by_yaml": ["reports"],
  "requested_at": "2026-07-17T12:00:00Z"
}
```

`session_id` is always present but empty on the initial `/v1/auth`(`/oidc`)
call; a `/v1/renew` call for an existing session populates it, letting a hook
tell an initial authorization from a renewal.

## Response

A successful response is, for example:

```json
{"allow": true, "allowed_tunnels": ["reports"], "ttl_seconds": 300}
```

Set `allowed_tunnels` to `"*"` to preserve all YAML grants. An array can only
narrow them. `ttl_seconds` applies only when it is shorter than the configured
session TTL.

## Example

[`examples/hooks/oidc-group-risk.py`](../examples/hooks/oidc-group-risk.py) is
a runnable executable hook that trusts SSH sessions as-is, fully trusts a set
of OIDC groups, narrows tunnels and shortens the session for a "contractors"
group, and returns a higher `risk_score` for any other OIDC identity. As of
this writing the server decodes `risk_score` but does not yet forward it into
its own `audit` log line (every audit event is logged with `risk: 0`
regardless of what the hook returns) — a hook can still act on it via
`allow`/`allowed_tunnels`/`ttl_seconds`, but a `risk_score`-only signal is not
currently observable outside the hook itself. Wire it up with:

```yaml
authorizer:
  exec: examples/hooks/oidc-group-risk.py
  timeout: 5s
```

## See also

- [CONFIGURATION.md](CONFIGURATION.md) — the full `authorizer:` and `tunnels:` reference
- [PROTOCOL.md](PROTOCOL.md#authorizer-hook-additions-for-oidc) — field-by-field authorizer schema
- [SECURITY.md](SECURITY.md) — treat authorizer endpoints/executables as part of the access-control boundary
