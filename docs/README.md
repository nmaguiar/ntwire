# Documentation

Start with the [project README](../README.md) for installation and a working
quick start. This directory holds the reference material the top-level README
links out to.

| Doc | Read it for |
| --- | --- |
| [CONFIGURATION.md](CONFIGURATION.md) | The complete `ntwire.yaml` option reference, grant matching, hot reload behavior, and the server dashboard |
| [RELAY.md](RELAY.md) | Reaching an `ntwire-server` behind NAT via `ntwire-relay`, and its trust model |
| [AUTHORIZATION.md](AUTHORIZATION.md) | The `authorizer:` webhook/executable hook: request/response schema and a worked example |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Release binaries, Docker Compose, and Kubernetes manifests |
| [LOGGING.md](LOGGING.md) | Text vs. Logstash-format JSON logs, the container default, and terminal color/UTF-8 behavior |
| [OIDC-SETUP.md](OIDC-SETUP.md) | Registering ntwire as a public OAuth client with Google, Microsoft Entra ID, or Keycloak |
| [PROTOCOL.md](PROTOCOL.md) | The wire-level control protocol: endpoints, signing payloads, and relay registration |
| [SECURITY.md](SECURITY.md) | The TLS trust model, OIDC threat model, and operator guidance |
| [UI-THEME.md](UI-THEME.md) | Design tokens and guidance for the client status UI |

For contributor workflow (build, test, formatting, commit conventions), see
[AGENTS.md](../AGENTS.md) at the repository root.
