# ntwire-relay configuration guide

Complete reference for ntwire-relay YAML configuration.

## Low-context LLM skill

Generate a portable `ntwire-relay-config` folder with:

```sh
ntwire-relay -write-config-skill /path/to/ntwire-relay-config
```

The folder contains a short `SKILL.md`, feature references that an agent loads only when needed, the complete reference, and the strict JSON Schema. Move the whole generated folder to one of these locations:

| Tool | Skill folder |
| --- | --- |
| VS Code / GitHub Copilot | `.github/skills/ntwire-relay-config/` |
| Claude Code | `.claude/skills/ntwire-relay-config/` |
| Codex | `~/.codex/skills/ntwire-relay-config/` |
| Google Antigravity (`agy`) | `.agents/skills/ntwire-relay-config/` |
| mini-a | `~/.openaf-mini-a/skills/ntwire-relay-config/` |

Restart or refresh the agent after copying the folder. Regenerate it after upgrading the ntwire binary; it requires neither this repository nor network access.

## LLM configuration checklist

Collect unanswered required choices before producing YAML. Retain the displayed YAML style and key spelling; never invent keys or secrets. Validate the conditional rules below before returning YAML. JSON Schema validates YAML after conversion to JSON; the binary remains the final semantic validator.

| Question | Answer |
| --- | --- |
| What domain and TLS are required? | Set domain to the wildcard suffix and configure TLS for listen.agents; public client TLS is spliced, never terminated. |
| Which listeners are needed? | listen.public and listen.agents have defaults. reflect and udp_relay are optional UDP services. |
| How are tenants registered? | Each registration needs a lowercase DNS-label name and an authorized SSH public key; optional dedicated TCP/UDP listeners bypass shared routing. |
| Need direct UDP or UDP relay? | reflect supports server opt-in direct-UDP discovery; udp_relay needs udp_relay_ports and retains the relay in the data path. |
| How should capacity be set? | Set limits for handshake, dial-back, connections, rate, and UDP relay sessions; the UDP port range bounds the relay pool. |
| Need native WireGuard? | Set registration native_wireguard.listen for a dedicated UDP endpoint per tenant. |
| Need Kubernetes discovery? | Enable it only with valid namespace/service selectors and the required service port name. |

## Complete YAML reference

```yaml
# ntwire-relay configuration
#
# A relay lets an ntwire-server behind NAT (no inbound connectivity) dial out
# to a public relay instead of listening for inbound connections. The relay
# never terminates client TLS: it routes on the ClientHello SNI and splices
# raw bytes to the origin server, which is why it is trusted only for
# availability, not confidentiality or integrity. See docs/SECURITY.md.

listen:
  public: ":443"                          # raw TCP; client TLS is spliced through, never terminated here
  agents: ":8444"                          # HTTPS endpoint ntwire-servers dial outbound to and register on
  reflect: ""                              # optional UDP address-reflection endpoint, e.g. ":3480"; empty disables it (default). Only needed by servers using relay.advertise_direct -- see docs/RELAY.md
  udp_relay: ""                            # optional shared client-facing UDP address for the UDP-relay forwarding tier, e.g. ":3481"; empty disables it (default). No server-side opt-in needed -- see docs/RELAY.md
  udp_relay_ports: "40000-40999"           # inclusive port range the relay allocates one dedicated per-session UDP port from (server leg); required when udp_relay is set. Every port in range is bound at startup: size this to your expected concurrent UDP-relay session count, not maximally -- it is a direct tradeoff between max concurrent sessions and how large a firewall rule you must open
  udp_buffer_bytes: 4194304                 # requested kernel UDP read/write buffer per relay socket; the OS may clamp it. Zero uses this default

tls:                                        # applies to listen.agents only
  cert_file: ""                            # PEM certificate; set together with key_file, or leave both empty for a generated self-signed certificate
  key_file: ""                             # PEM private key paired with cert_file; required whenever cert_file is set
  state_dir: ""                            # directory for a generated self-signed certificate and key; empty uses this YAML file's directory
  ephemeral: false                          # generate a new in-memory self-signed certificate on every start instead of persisting it in state_dir

domain: relay.example.com                 # wildcard suffix; a server registered as "home" is reached at home.relay.example.com

# Optional Kubernetes Service discovery. Disabled by default. The relay uses
# Service DNS and only splices TLS after SNI selects an explicitly enabled
# Service; it never terminates client TLS.
kubernetes:
  enabled: false
  namespaces:
    mode: all                             # all, or selected with names and/or selector
    names: []
    selector: ""                          # optional Namespace label selector
  service:
    selector: "app.kubernetes.io/name=ntwire-server"
    port_name: ntwire-relay
  registration:
    hostname_annotation: ntwire.io/hostname
    tenant_annotation: ntwire.io/tenant   # informational, exposed in logs/status

limits:
  handshake_timeout: 5s                    # deadline for reading an inbound client's ClientHello
  dial_back_timeout: 10s                   # deadline for a registered server to redeem a conn_id with a data connection; also the conn_id's TTL
  max_pending_per_server: 32                # un-dialed-back connections per tenant
  max_conns_per_server: 256                 # live spliced connections per tenant (roughly half that many clients, since each client opens 2+ connections)
  max_new_conns_per_minute: 60               # per source IP on listen.public
  udp_relay_idle_timeout: 60s                # reclaims an allocated udp_relay port if neither leg has sent traffic (including keepalives) this long
  max_udp_relay_sessions_per_server: 64      # concurrent UDP-relay sessions per tenant, independent of the udp_relay_ports pool size

registrations:
  - name: home                              # first DNS label; clients use https://home.relay.example.com
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINA2Gh3ezOG8R0iaD0WVnVsJTQGHqjI96LwGrIc/Kwgc admin@laptop" # authorized_keys line identifying the ntwire-server allowed to claim this name; replace with your own
    listen: ""                             # optional dedicated TCP public listener for this tenant (e.g. ":8443"); bypasses wildcard DNS and SNI matching
    native_wireguard:
      listen: ""                           # optional dedicated UDP endpoint for ordinary WireGuard clients, e.g. ":51821" or "relay.example.com:51821" (a hostname is resolved when the relay starts)

log:
  format: text                              # text or json (Logstash-format, for fluent-bit/Logstash); container images default to json via NTWIRE_LOG_FORMAT
  level: info                                # debug, info, warn, or error
  # Precedence: -log-format/-log-level flags > this file > NTWIRE_LOG_FORMAT/NTWIRE_LOG_LEVEL env > built-in default (text, info). See docs/LOGGING.md.
```

## Rules and conditional validation

- domain is required and must be a normalized DNS name; registration names are lowercase DNS labels and registration public keys must parse.
- listen.udp_relay_ports is required and must be a valid 1-65535 range whenever listen.udp_relay is set.
- When kubernetes.enabled is true, service.selector and service.port_name are required; selected namespaces need names or selector.
- cert_file and key_file must be set together or both left empty for generated TLS.

## JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "description": "Complete reference for ntwire-relay YAML configuration.",
  "properties": {
    "domain": {
      "type": "string"
    },
    "kubernetes": {
      "additionalProperties": false,
      "properties": {
        "enabled": {
          "type": "boolean"
        },
        "namespaces": {
          "additionalProperties": false,
          "properties": {
            "mode": {
              "default": "all",
              "enum": [
                "all",
                "selected"
              ],
              "type": "string"
            },
            "names": {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            "selector": {
              "type": "string"
            }
          },
          "type": "object"
        },
        "registration": {
          "additionalProperties": false,
          "properties": {
            "hostname_annotation": {
              "type": "string"
            },
            "tenant_annotation": {
              "type": "string"
            }
          },
          "type": "object"
        },
        "service": {
          "additionalProperties": false,
          "properties": {
            "port_name": {
              "type": "string"
            },
            "selector": {
              "type": "string"
            }
          },
          "type": "object"
        }
      },
      "type": "object"
    },
    "limits": {
      "additionalProperties": false,
      "properties": {
        "dial_back_timeout": {
          "default": "10s",
          "format": "duration",
          "type": "string"
        },
        "handshake_timeout": {
          "default": "5s",
          "format": "duration",
          "type": "string"
        },
        "max_conns_per_server": {
          "default": 256,
          "minimum": 1,
          "type": "integer"
        },
        "max_new_conns_per_minute": {
          "default": 60,
          "minimum": 1,
          "type": "integer"
        },
        "max_pending_per_server": {
          "default": 32,
          "minimum": 1,
          "type": "integer"
        },
        "max_udp_relay_sessions_per_server": {
          "default": 64,
          "minimum": 1,
          "type": "integer"
        },
        "udp_relay_idle_timeout": {
          "default": "60s",
          "format": "duration",
          "type": "string"
        }
      },
      "type": "object"
    },
    "listen": {
      "additionalProperties": false,
      "properties": {
        "agents": {
          "default": ":8444",
          "type": "string"
        },
        "public": {
          "default": ":443",
          "type": "string"
        },
        "reflect": {
          "type": "string"
        },
        "udp_buffer_bytes": {
          "type": "integer"
        },
        "udp_relay": {
          "type": "string"
        },
        "udp_relay_ports": {
          "pattern": "^[0-9]+(-[0-9]+)?$",
          "type": "string"
        }
      },
      "type": "object"
    },
    "log": {
      "additionalProperties": false,
      "properties": {
        "format": {
          "default": "text",
          "enum": [
            "text",
            "json"
          ],
          "type": "string"
        },
        "level": {
          "default": "info",
          "enum": [
            "debug",
            "info",
            "warn",
            "error"
          ],
          "type": "string"
        }
      },
      "type": "object"
    },
    "registrations": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "listen": {
            "type": "string"
          },
          "name": {
            "type": "string"
          },
          "native_wireguard": {
            "additionalProperties": false,
            "properties": {
              "listen": {
                "type": "string"
              }
            },
            "type": "object"
          },
          "public_key": {
            "type": "string"
          }
        },
        "type": "object"
      },
      "type": "array"
    },
    "tls": {
      "additionalProperties": false,
      "properties": {
        "cert_file": {
          "type": "string"
        },
        "ephemeral": {
          "type": "boolean"
        },
        "key_file": {
          "type": "string"
        },
        "state_dir": {
          "type": "string"
        }
      },
      "type": "object"
    }
  },
  "title": "ntwire-relay configuration guide",
  "type": "object"
}
```
