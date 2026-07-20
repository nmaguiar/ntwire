# Repository Guidelines

## Project Structure & Module Organization

`cmd/ntwire` and `cmd/ntwire-server` contain the client and server entry points. Keep reusable implementation in `pkg/`, grouped by responsibility: `client`, `server`, `protocol`, `wgnet`, `wstransport`, and authentication/key packages. Put tests beside the package they exercise (for example, `pkg/server/session_test.go`). The browser UI is embedded from `pkg/client/webui/static/`. Deployment examples live in `deploy/docker` and `deploy/k8s`; protocol and security details belong in `docs/`.

## Build, Test, and Development Commands

Use Go 1.26 or the version declared in `go.mod`.

- `go test ./...` runs the full unit/integration test suite.
- `go test -race ./...` checks tests for data races before concurrency-sensitive changes.
- `go vet ./...` catches common Go correctness issues.
- `go build ./cmd/...` confirms both CLI binaries compile; `go build -o bin/ntwire ./cmd/ntwire` builds just the client.
- `ojob tasks.yaml op=check` runs dependency verification, formatting checks, vet, and tests. Use `ojob tasks.yaml op=all` to also build both binaries.
- `ojob tasks.yaml op=compose-up` starts the Docker Compose example; use `compose-down` when finished.

The task file defaults to `/tmp/ntwire-gocache`; set `goCache=/path` when the default is not writable.

## Coding Style & Naming Conventions

Run `gofmt -w $(find cmd pkg -name '*.go' -type f)` (or `ojob tasks.yaml op=format`) before committing. Use tabs and standard Go formatting; do not hand-align code. Name exported identifiers in `PascalCase`, unexported identifiers in `camelCase`, and Go test files `*_test.go`. Keep package APIs focused and carry protocol changes through `pkg/protocol`, implementation, tests, and `docs/PROTOCOL.md` together.

## Testing Guidelines

Add or update focused tests with every behavior change. Prefer table-driven tests for configuration and protocol variants; use descriptive `TestFeature_Condition` names. Run the affected package during iteration, then `go test ./...`; run the race suite for session, reload, transport, or concurrent server changes. There is no stated coverage threshold, so protect new branches with meaningful assertions and error-path tests.

## Commit & Pull Request Guidelines

Follow the existing Conventional Commit-like history: `feat(protocol): ...`, `fix(server): ...`, `docs(tls): ...`, or `chore(build): ...`. Keep each commit scoped and imperative. Pull requests should explain the user-visible change, list validation performed, link relevant issues, and update docs or deployment examples when interfaces or configuration change. Include screenshots only for Web UI changes.

## Security & Configuration

Never commit private keys, tokens, or local runtime output. Treat configuration and authentication changes as security-sensitive; review `docs/SECURITY.md` and `deploy/OIDC-SETUP.md`, and add tests for authorization, TLS, or OIDC behavior.
