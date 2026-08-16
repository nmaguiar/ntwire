# Logging and CLI output

`ntwire-server` and `ntwire-relay` log through Go's `log/slog`, in either a
human-readable text format or Logstash-format JSON suitable for shipping to
Elasticsearch/Logstash via [fluent-bit](https://fluentbit.io/) or similar.
The `ntwire` client colorizes its interactive output and help text the same
way, and honors the same terminal-capability conventions.

## Configuring log format and level

Both daemons accept:

| Source | Example |
| --- | --- |
| `-log-format` / `-log-level` flags | `ntwire-server -log-format json -log-level debug` |
| `log:` section in the YAML config | `log: {format: json, level: debug}` |
| `NTWIRE_LOG_FORMAT` / `NTWIRE_LOG_LEVEL` env vars | `NTWIRE_LOG_FORMAT=json ntwire-relay` |

`-log-format`/`log.format` accept `text` (the default outside containers) or
`json`. `-log-level`/`log.level` accept `debug`, `info`, `warn`, or `error`
(default `info`).

**Precedence: flag > config file > env var > built-in default.** This is
deliberately not the more common "env beats file" order: it lets a mounted
config file override a container image's baked-in `NTWIRE_LOG_FORMAT=json`
default (see below), while `docker run -e NTWIRE_LOG_FORMAT=text` still
works whenever no config value is set. An explicit `-log-format`/`-log-level`
flag always wins, matching how `-config` already behaves.

Run `ntwire-server -print-sample-config` or `ntwire-relay -print-sample-config`
to see the commented `log:` block in context.

## Container images default to JSON

The published `ntwire-server`, `ntwire-relay`, and `ntwire` (client) container
images set `ENV NTWIRE_LOG_FORMAT=json`, so logs are structured JSON by
default when running under an orchestrator. Override it at run time:

```sh
docker run -e NTWIRE_LOG_FORMAT=text nmaguiar/ntwire-server:build
```

or by setting `log.format: text` in a mounted config file, which takes
precedence over the image's env default.

## JSON (Logstash) format

Each line is a single JSON object:

```json
{"@timestamp":"2026-07-21T12:00:00.123456789Z","@version":"1","level":"info","message":"ntwire server listening","https":":8443","wireguard":":51820"}
```

- `@timestamp` — RFC3339 with nanosecond precision, for correct event ordering.
- `@version` — always `"1"`, the Logstash schema-version convention.
- `level` — lowercased (`debug`, `info`, `warn`, `error`).
- `message` — the log line.
- All other fields are the structured attributes passed to the log call.

## Lifecycle events

Lifecycle logs use a stable `event` field. Current server events include
`configuration_reloaded`, `websocket_connected`,
`websocket_disconnected`, `authentication_failed`, and
`authorization_hook_denied`; transport events
include the low-cardinality `transport` and `relay` fields. Session audit
records additionally cover authentication, renewal, expiration, disconnect,
administrative revocation, reload-driven authorization/tunnel-grant revocation,
and authorization-hook denial. Hook-denial records use only the stable
`hook_error` or `hook_denied` reason category, not an external error string.
Credentials, bearer tokens, private keys, and OAuth artifacts are never
included in these fields.

`/metrics` also exposes the process-lifetime counter
`ntwire_lifecycle_events_total{event,method}`. Both labels are bounded:
`event` is an ntwire-defined lifecycle name and `method` is `ssh`, `oidc`, or
`unknown`; neither can contain an identity, session ID, target, tunnel grant,
or error text. Existing session and traffic values remain snapshots of active
state.

### fluent-bit example

Both daemons write logs to stderr, not to a file, so under a container
runtime fluent-bit typically reads them via the container log driver (or
the Docker/Kubernetes filesystem input) rather than an ntwire-owned path.
For example, tailing Docker's default JSON-file log driver output:

```ini
[INPUT]
    Name              tail
    Path              /var/lib/docker/containers/*/*-json.log
    Parser            docker
    Tag               ntwire.server

[FILTER]
    Name              parser
    Match             ntwire.*
    Key_Name          log
    Parser            json
    Reserve_Data      On

[OUTPUT]
    Name              es
    Match             ntwire.*
    Host              elasticsearch
    Port              9200
    Logstash_Format   On
    Logstash_Prefix   ntwire
```

If a supervisor instead redirects a daemon's stderr to a plain file, tail
that file directly with `Parser json` and skip the Docker-log unwrapping
step above. Because the JSON already uses `@timestamp`/`@version`, no
additional `[FILTER] modify` step is needed to reshape fields for
Logstash-compatible consumers.

## Terminal colors and symbols

`ntwire`, `ntwire-relay`, and `ntwire-server` colorize interactive text
output and `-h` help using ANSI colors and UTF-8 symbols (`✓ ✗ ⚠ →`) when the
terminal supports them, falling back to plain ASCII (`OK FAIL ! ->`)
otherwise. This applies to `-log-format text` logs too: level-coded colors
on a TTY, plain `slog` text when piped or redirected.

Detection order:

1. `--no-color` (or `-no-color`) flag — always disables color.
2. [`NO_COLOR`](https://no-color.org) env var (any value) — disables color.
3. `CLICOLOR_FORCE` env var (any value other than `0`) — forces color on,
   even when output isn't a terminal.
4. Otherwise, color and UTF-8 symbols are enabled only when the output
   stream is an actual terminal.

Piped or redirected output (`ntwire status > file`, `| cat`, CI logs) never
contains ANSI escapes or UTF-8 symbols unless `CLICOLOR_FORCE` is set.
