# Documentation

Start with the [project README](../README.md) for installation and a working
quick start. This directory holds the reference material the top-level README
links out to.

| Doc | Read it for |
| --- | --- |
| [CONNECTING.md](CONNECTING.md) | Step-by-step setup for every client/endpoint combination: `ntwire` or official WireGuard, against a direct `ntwire-server` or one behind `ntwire-relay` |
| [CLIENT.md](CLIENT.md) | `ntwire` CLI commands, local dashboard/settings, GUI client, and SSO credential behavior |
| [CONFIGURATION.md](CONFIGURATION.md) | The complete `ntwire.yaml` option reference, grant matching, hot reload behavior, and the server dashboard |
| [RELAY.md](RELAY.md) | Reaching an `ntwire-server` behind NAT via `ntwire-relay`, and its trust model |
| [AUTHORIZATION.md](AUTHORIZATION.md) | The `authorizer:` webhook/executable hook: request/response schema and a worked example |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Release binaries, Docker Compose, Kubernetes manifests, and the Helm chart |
| [RELEASE.md](RELEASE.md) | Release-readiness checks and sign-off record |
| [GUI.md](GUI.md) | `ntwire-gui`: the tray/menu-bar client, its two build modes, profile storage, and autostart |
| [NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md) | Connecting official WireGuard clients (iOS, macOS, Windows, Android, Linux) straight to `ntwire-server` as native peers |
| [DESTINATION-POLICIES.md](DESTINATION-POLICIES.md) | Destination filtering rules for native WireGuard peers and SOCKS tunnels |
| [IOS.md](IOS.md) | **Archived** — native iOS/iPadOS Network Relay feasibility, MASQUE gateway architecture, entitlement requirements, and delivery gates |
| [LOGGING.md](LOGGING.md) | Text vs. Logstash-format JSON logs, the container default, and terminal color/UTF-8 behavior |
| [OIDC-SETUP.md](OIDC-SETUP.md) | Registering ntwire as a public OAuth client with Google, Microsoft Entra ID, Keycloak, and Cognito compatibility guidance |
| [OIDC-RELAY-DEPLOYMENT.md](OIDC-RELAY-DEPLOYMENT.md) | Deploying OIDC securely over direct HTTPS or `ntwire-relay` |
| [PROTOCOL.md](PROTOCOL.md) | The wire-level control protocol: endpoints, signing payloads, and relay registration |
| [SECURITY.md](SECURITY.md) | The TLS trust model, OIDC threat model, and operator guidance |
| [LETSENCRYPT.md](LETSENCRYPT.md) | Getting a CA-trusted certificate onto `ntwire-server`, alone or behind `ntwire-relay`, so browsers/OS proxy auto-config (PAC) endpoints accept it |
| [PORTAL.md](PORTAL.md) | Portal configuration, template authoring, action authorization, and CLI tooling |
| [UI-THEME.md](UI-THEME.md) | Design tokens and guidance for the client status UI |

For contributor workflow (build, test, formatting, commit conventions), see
[AGENTS.md](../AGENTS.md) at the repository root.
