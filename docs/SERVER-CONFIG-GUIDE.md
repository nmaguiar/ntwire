# ntwire-server configuration guide

Complete reference for ntwire-server YAML configuration.

## Low-context LLM skill

Generate a portable `ntwire-server-config` folder with:

```sh
ntwire-server -write-config-skill /path/to/ntwire-server-config
```

The folder contains a short `SKILL.md`, feature references that an agent loads only when needed, the complete reference, and the strict JSON Schema. Move the whole generated folder to one of these locations:

| Tool | Skill folder |
| --- | --- |
| VS Code / GitHub Copilot | `.github/skills/ntwire-server-config/` |
| Claude Code | `.claude/skills/ntwire-server-config/` |
| Codex | `~/.codex/skills/ntwire-server-config/` |
| Google Antigravity (`agy`) | `.agents/skills/ntwire-server-config/` |
| mini-a | `~/.openaf-mini-a/skills/ntwire-server-config/` |

Restart or refresh the agent after copying the folder. Regenerate it after upgrading the ntwire binary; it requires neither this repository nor network access.

## LLM configuration checklist

Collect unanswered required choices before producing YAML. Retain the displayed YAML style and key spelling; never invent keys or secrets. Validate the conditional rules below before returning YAML. JSON Schema validates YAML after conversion to JSON; the binary remains the final semantic validator.

| Question | Answer |
| --- | --- |
| How should clients reach the server? | Use direct listen.https, or relay.enabled with a registered relay tenant; relay.direct_clients explicitly enables both. |
| How do users authenticate? | Configure authorized_keys_dir, OIDC issuers, or native_wireguard.enabled. OIDC client_secret is deliberately rejected. |
| Which TLS/listeners are needed? | Set cert_file and key_file together, or allow generated TLS. listen.https and listen.wireguard have defaults. |
| Which tunnel type is needed? | Use a fixed host:port target, target: socks for the embedded filtered proxy, or target: external_socks with external_socks.url for an opaque upstream. |
| How are destinations controlled? | Use tunnel allow lists, destination_policies, and SOCKS filters; an unfiltered embedded SOCKS tunnel denies all unless allow_all is explicit. |
| Need ordinary WireGuard clients? | Enable native_wireguard and configure peers; it is independent from authenticated HTTP sessions. |
| Need observability or Portal? | Configure log/audit for records and portal for operator presentation metadata; do not put tokens or secrets in generated examples. |
| Need Apple Network Relay/MASQUE? | Enable masque only with its fixed tunnel mapping and certificate inputs; it is opt-in and separate from other transports. |

## Complete YAML reference

```yaml
# ntwire server configuration
#
# At least one authentication method is required: auth.authorized_keys_dir,
# auth.oidc.issuers, or both. Uncomment and adapt the OIDC example below to
# enable single sign-on alongside SSH public-key authentication.

listen:
  https: ":8443"                         # TLS control API and WebSocket fallback listener; default: :8443
  wireguard: ":51820"                    # UDP listener for the userspace WireGuard data plane; default: :51820
  metrics: ""                             # optional plaintext metrics/dashboard listener; exposes /metrics and, with admin.web_ui_token, /?token=... (for example, 127.0.0.1:9090)
  name: ""                                # friendly label shown in the client's local status UI and logs, to tell apart several ntwire clients running locally; empty falls back to the host:port the client connected to

tls:
  cert_file: ""                          # PEM certificate; set together with key_file, or leave both empty for a generated self-signed certificate
  key_file: ""                           # PEM private key paired with cert_file; required whenever cert_file is set
  state_dir: ""                          # directory for a generated self-signed certificate and key; empty uses this YAML file's directory
  ephemeral: false                        # generate a new in-memory self-signed certificate on every start instead of persisting it in state_dir

auth:
  authorized_keys_dir: /etc/ntwire/keys  # directory of SSH public-key files; optional only when oidc.issuers is configured
  session_ttl: 15m                        # bearer-token lifetime before renewal is required; default: 15m
  max_sessions_per_key: 5                 # concurrent-session cap per SSH fingerprint or OIDC email; 0 means unlimited
  oidc:
    issuers: []                           # OIDC providers; leave empty to use SSH keys only
    # - name: google                      # stable provider ID shown to clients and selected with --provider
    #   issuer: https://accounts.google.com # issuer URL; its discovery document and JWKS are fetched
    #   client_id: 1234-abc.apps.googleusercontent.com # public OAuth client ID (PKCE; most IdPs need no client secret)
    # Do not add client_secret here. It is rejected to prevent disclosure via
    # unauthenticated server metadata; see docs/OIDC-SETUP.md for Google.
    #   scopes: [openid, email, profile]  # requested OAuth scopes; defaults to these three when omitted
    #   groups_claim: groups               # ID-token claim with group membership; empty disables group: grants
    #   require_verified_email: true       # reject tokens lacking email_verified=true; default: true

network:
  tunnel_cidr: 100.64.0.0/16              # private IPv4 range or an IPv6 prefix (pick one; a deployment is single-family) used to allocate peer tunnel addresses; default shown; for IPv6 use /64 or no shorter than /112
  advertised_endpoint: ""                 # UDP host:port returned to clients when it differs from listen.wireguard, such as behind NAT; host may be a hostname (resolved fresh on every client connect/renew) or a literal IP; must be empty when relay.enabled is true
  wireguard_private_key_file: ""          # optional persistent server WireGuard private key; use for native official WireGuard clients
  # dns:
  #   enabled: true                       # run an in-tunnel DNS server on UDP port 53 for service discovery; default: true
  #   domain: ntwire                      # top-level domain suffix for tunnel resolution and discovery (e.g. <tunnel>.ntwire); default: ntwire

transport:
  # V3 keeps the healthy incumbent and changes carrier only on proven failure.
  multipath: true                         # negotiate WebSocket/UDP scheduling when both legs are available; default: true; set false for legacy single-path behavior
  force: auto                              # optional server-side preference: auto, wss, udp-relay, or direct-udp; falls back automatically if unavailable

# Named reusable egress policy. A tunnel and a native peer can each name one;
# when both do, both must allow the selected destination.
destination_policies: {}

native_wireguard:
  enabled: false
  peers: []                              # name, public_key, tunnel_ip, tunnels, optional destination_policy

relay:
  enabled: false                          # when true, listen.https is never bound; the server dials out to an ntwire-relay instead (see PLAN-RELAY.md)
  url: ""                                 # wss://relay.example.com:8444, the relay's listen.agents endpoint
  name: home                              # tenant label; must match this key's registrations[] entry on the relay
  identity_file: /etc/ntwire/relay_id_ed25519 # private key used to sign relay registration, separate from auth.authorized_keys_dir; generate with: ntwire-server -generate-relay-key /etc/ntwire/relay_id_ed25519
  fingerprint: ""                         # SHA256:... pin of the relay's listen.agents TLS certificate; empty verifies against normal PKI instead
  # For active-active relay HA, replace url/fingerprint above with endpoints.
  # Every endpoint must register the same tenant name and serve the same
  # wildcard client domain; clients race that shared DNS name on failure.
  # endpoints:
  #   - url: "wss://relay-a.example.com:8444"
  #     fingerprint: "SHA256:..."
  #   - url: "wss://relay-b.example.com:8444"
  #     fingerprint: "SHA256:..."
  reconnect_min: 1s                        # initial backoff after a dropped control connection; default: 1s
  reconnect_max: 1m                        # backoff ceiling; default: 1m
  advertise_direct: false                  # opt into self-reflecting off the relay's listen.reflect UDP endpoint and offering the result to clients over /v1/punch, so a client that can NAT hole-punch bypasses the relay's data plane entirely; requires the relay to have listen.reflect configured. See docs/RELAY.md. Leave false to keep this server's real address hidden, which is otherwise relay mode's whole point.
  direct_clients: false                    # also bind listen.https for direct ntwire clients; default false so relay mode does not expose an inbound listener unexpectedly. The TLS certificate must cover the direct hostname.
  # multipath: overrides v3's bounded reactive-duplication budget.
  # multipath:
  #   duplicate_rate_bytes_per_sec: 262144    # cap reactive duplication toward a healthy alternate while the incumbent degrades
  # When relay.enabled is true and advertise_direct is false, consider
  # setting listen.wireguard to "127.0.0.1:0": WireGuard rides the /v1/wg
  # WebSocket fallback in relay mode, so the UDP socket StartDataPlane still
  # opens is unused. Leave it reachable on the network if advertise_direct is
  # true -- that socket is exactly what self-reflection and the direct
  # upgrade use.

authorizer:
  webhook_url: ""                         # URL that receives a JSON POST for each connection and returns an allow/deny decision; takes precedence when both hook options are set
  exec: ""                                # executable that receives the same JSON on stdin and returns an allow/deny decision when webhook_url is empty
  timeout: 5s                              # deadline for the webhook or executable; errors and timeouts deny the request; default: 5s

admin:
  web_ui_token: ""                         # optional secret that enables the server dashboard at /?token=...; leave empty to disable it

# The optional Portal presents only the tunnels the authenticated user may
# access. The native ntwire client renders it when enabled; web adds an HTTP
# listener inside the WireGuard overlay, never a public listener.
portal:
  enabled: false
  title: "Internal Services Portal"
  template: ""                              # empty uses the safe built-in template; otherwise inline Markdown or a path relative to this YAML file
  variables: {}
  web:
    enabled: false
    listen: ""                              # required overlay host:port (for example 100.64.0.1:8080) when web.enabled is true

# A tunnel's instructions can also be kept in its own file: a single-line
# instructions value with no newline (e.g. "instructions: examples/instructions/ssh.md")
# is tried as a file path, and if it names an existing file, that file's
# content is used instead of the literal string. See "Loading instructions
# from a file" in docs/CONFIGURATION.md and examples/instructions/ for
# ready-to-adapt files (SSH, kubectl, and SOCKS-proxy clients).
tunnels:
  - name: reports                          # unique identifier shown to clients
    target: reports.internal:8080          # host:port the server proxies to after traffic reaches its virtual port
    description: Reporting service         # optional free-text description shown to clients
    virtual_port: 18080                    # required port exposed inside the WireGuard tunnel; 1 through 65535
    local_port: 58080                      # preferred client loopback port; 0 chooses any free port, and an occupied value falls back to one
    local_host: ""                           # optional preferred loopback address (e.g. "127.70.0.1"), letting distinct tunnels share a memorable port without colliding; must be 127.0.0.0/8 or ::1, and the client falls back to 127.0.0.1 if it can't be bound (on macOS this needs an "ifconfig lo0 alias" first; Linux binds it out of the box). Empty means 127.0.0.1.
    docs_url: ""                             # optional absolute http(s) link offered as "See more" beside the instructions below
    instructions: |                          # optional Markdown shown in the client status UI, expanded there as a Go template
      Fetch a report through the tunnel:

      ~~~sh
      curl -s http://{{.LocalHost}}:{{.LocalPort}}/reports/latest
      ~~~

      Fields: .Name, .Description, .LocalAddress, .LocalHost, .LocalPort, .VirtualPort,
      .TargetHint, .TunnelIP, .ServerTunnelIP, .Server. Fenced blocks get a copy button.
    portal:                                  # optional presentation metadata when portal.enabled is true
      name: "Reports"
      description: "Reporting service"
      category: "Operations"
      icon: "chart"
      url: ""                                # optional absolute http(s) URL for a browser action
      socks_tunnel: ""                       # optional name of an authorized embedded SOCKS tunnel for the browser action
      applications: []
    allow:
      - "*"                                # any authenticated identity
      # - "SHA256:..."                     # SSH public-key fingerprint (preferred for SSH grants)
      # - "alice@laptop"                   # SSH authorized_keys comment
      # - "alice@corp.com"                 # exact verified OIDC email
      # - "@corp.com"                      # OIDC email domain
      # - "group:engineering"              # OIDC membership in auth.oidc.issuers[].groups_claim
  # - name: egress                          # an embedded SOCKS4/5 proxy tunnel instead of a fixed target
  #   target: socks                         # required sentinel value that selects the SOCKS target type
  #   virtual_port: 11080
  #   allow: ["group:engineering"]
  #   socks:
  #     only_local: false                   # true restricts to private ranges only (10/8, 172.16/12, 192.168/16, fc00::/7) and ignores every other socks.* filter below
  #     filters: []                         # destination CIDR allow-list, e.g. ["10.0.0.0/8", "fc00::/7"]
  #     domain_filters: []                  # destination hostname-suffix allow-list, e.g. [".svc.cluster.local"]
  #     asn_filters: []                     # destination ASN allow-list (IPv4 only), e.g. [15169]
  #     asn_updates: null                   # periodically refresh the ASN index; defaults to true when asn_filters is non-empty
  #     asn_url: ""                         # override the ASN index download URL; default: https://openaf.io/asnidx.json.gz
  #     reverse_filters: false              # invert the above from an allow-list into a deny-list
  #     dns_timeout: 10s                    # timeout for resolving SOCKS5 domain requests
  #     allow_all: false                    # required to permit every destination when no filters above are set; otherwise an unfiltered SOCKS tunnel denies everything (unlike socksd, which defaults to allow-all)
  #     allow_bind: false                   # explicitly allow SOCKS4/5 BIND; it opens a temporary inbound listener on the server host

log:
  format: text                             # text or json (Logstash-format, for fluent-bit/Logstash); container images default to json via NTWIRE_LOG_FORMAT
  level: info                               # debug, info, warn, or error
  # Precedence: -log-format/-log-level flags > this file > NTWIRE_LOG_FORMAT/NTWIRE_LOG_LEVEL env > built-in default (text, info). See docs/LOGGING.md.

audit:
  log_file: ""                             # optional path for a dedicated JSON-lines audit log (auth_allowed, session_disconnected, session_expired, session_revoked); in addition to, not instead of, the main log
```

## Rules and conditional validation

- At least one of auth.authorized_keys_dir, auth.oidc.issuers, or native_wireguard.enabled must be configured.
- TLS cert_file and key_file must be set together; client_secret is a legacy key that always fails semantic validation.
- relay.url/fingerprint cannot be combined with relay.endpoints; relay.advertise_direct requires relay mode.
- target: socks and target: external_socks each require their corresponding configuration; external SOCKS URLs are credential-free socks5://host:port.

## JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "description": "Complete reference for ntwire-server YAML configuration.",
  "properties": {
    "admin": {
      "additionalProperties": false,
      "properties": {
        "web_ui_token": {
          "type": "string"
        }
      },
      "type": "object"
    },
    "audit": {
      "additionalProperties": false,
      "properties": {
        "log_file": {
          "type": "string"
        }
      },
      "type": "object"
    },
    "auth": {
      "additionalProperties": false,
      "properties": {
        "authorized_keys_dir": {
          "type": "string"
        },
        "max_sessions_per_key": {
          "type": "integer"
        },
        "oidc": {
          "additionalProperties": false,
          "properties": {
            "issuers": {
              "items": {
                "additionalProperties": false,
                "properties": {
                  "client_id": {
                    "type": "string"
                  },
                  "client_secret": {
                    "type": "string"
                  },
                  "groups_claim": {
                    "type": "string"
                  },
                  "issuer": {
                    "type": "string"
                  },
                  "name": {
                    "type": "string"
                  },
                  "require_verified_email": {
                    "type": "boolean"
                  },
                  "scopes": {
                    "items": {
                      "type": "string"
                    },
                    "type": "array"
                  }
                },
                "type": "object"
              },
              "type": "array"
            }
          },
          "type": "object"
        },
        "session_ttl": {
          "default": "15m",
          "format": "duration",
          "type": "string"
        }
      },
      "type": "object"
    },
    "authorizer": {
      "additionalProperties": false,
      "properties": {
        "exec": {
          "type": "string"
        },
        "timeout": {
          "default": "5s",
          "format": "duration",
          "type": "string"
        },
        "webhook_url": {
          "type": "string"
        }
      },
      "type": "object"
    },
    "destination_policies": {
      "additionalProperties": {
        "additionalProperties": false,
        "properties": {
          "allow_all": {
            "type": "boolean"
          },
          "asn_filters": {
            "items": {
              "type": "integer"
            },
            "type": "array"
          },
          "domain_filters": {
            "items": {
              "type": "string"
            },
            "type": "array"
          },
          "filters": {
            "items": {
              "type": "string"
            },
            "type": "array"
          },
          "only_local": {
            "type": "boolean"
          },
          "ports": {
            "items": {
              "type": "integer"
            },
            "type": "array"
          },
          "protocols": {
            "items": {
              "type": "string"
            },
            "type": "array"
          },
          "reverse_filters": {
            "type": "boolean"
          }
        },
        "type": "object"
      },
      "type": "object"
    },
    "listen": {
      "additionalProperties": false,
      "properties": {
        "https": {
          "default": ":8443",
          "type": "string"
        },
        "metrics": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "wireguard": {
          "default": ":51820",
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
    "masque": {
      "additionalProperties": false,
      "properties": {
        "certificate_ttl": {
          "format": "duration",
          "type": "string"
        },
        "client_ca_file": {
          "type": "string"
        },
        "enabled": {
          "type": "boolean"
        },
        "http2_url": {
          "type": "string"
        },
        "http3_url": {
          "type": "string"
        },
        "issuer_cert_file": {
          "type": "string"
        },
        "issuer_key_file": {
          "type": "string"
        },
        "listen": {
          "type": "string"
        },
        "match_domains": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "tunnels": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        }
      },
      "type": "object"
    },
    "native_wireguard": {
      "additionalProperties": false,
      "properties": {
        "enabled": {
          "type": "boolean"
        },
        "peers": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "destination_policy": {
                "type": "string"
              },
              "name": {
                "type": "string"
              },
              "public_key": {
                "type": "string"
              },
              "tunnel_ip": {
                "type": "string"
              },
              "tunnels": {
                "items": {
                  "type": "string"
                },
                "type": "array"
              }
            },
            "type": "object"
          },
          "type": "array"
        }
      },
      "type": "object"
    },
    "network": {
      "additionalProperties": false,
      "properties": {
        "advertised_endpoint": {
          "type": "string"
        },
        "dns": {
          "additionalProperties": false,
          "properties": {
            "domain": {
              "type": "string"
            },
            "enabled": {
              "type": "boolean"
            }
          },
          "type": "object"
        },
        "tunnel_cidr": {
          "default": "100.64.0.0/16",
          "type": "string"
        },
        "wireguard_private_key_file": {
          "type": "string"
        }
      },
      "type": "object"
    },
    "portal": {
      "additionalProperties": false,
      "properties": {
        "enabled": {
          "type": "boolean"
        },
        "template": {
          "type": "string"
        },
        "title": {
          "type": "string"
        },
        "variables": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        },
        "web": {
          "additionalProperties": false,
          "properties": {
            "enabled": {
              "type": "boolean"
            },
            "listen": {
              "type": "string"
            }
          },
          "type": "object"
        }
      },
      "type": "object"
    },
    "relay": {
      "additionalProperties": false,
      "properties": {
        "advertise_direct": {
          "type": "boolean"
        },
        "direct_clients": {
          "type": "boolean"
        },
        "enabled": {
          "type": "boolean"
        },
        "endpoints": {
          "items": {
            "additionalProperties": false,
            "properties": {
              "fingerprint": {
                "type": "string"
              },
              "url": {
                "type": "string"
              }
            },
            "type": "object"
          },
          "type": "array"
        },
        "fingerprint": {
          "type": "string"
        },
        "identity_file": {
          "type": "string"
        },
        "multipath": {
          "additionalProperties": false,
          "properties": {
            "duplicate_rate_bytes_per_sec": {
              "type": "integer"
            }
          },
          "type": "object"
        },
        "name": {
          "type": "string"
        },
        "reconnect_max": {
          "format": "duration",
          "type": "string"
        },
        "reconnect_min": {
          "format": "duration",
          "type": "string"
        },
        "url": {
          "type": "string"
        }
      },
      "type": "object"
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
    },
    "transport": {
      "additionalProperties": false,
      "properties": {
        "force": {
          "default": "auto",
          "enum": [
            "auto",
            "wss",
            "udp-relay",
            "direct-udp"
          ],
          "type": "string"
        },
        "multipath": {
          "type": "boolean"
        }
      },
      "type": "object"
    },
    "tunnels": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "allow": {
            "items": {
              "type": "string"
            },
            "type": "array"
          },
          "description": {
            "type": "string"
          },
          "destination_policy": {
            "type": "string"
          },
          "docs_url": {
            "type": "string"
          },
          "external_socks": {
            "additionalProperties": false,
            "properties": {
              "url": {
                "type": "string"
              }
            },
            "type": "object"
          },
          "instructions": {
            "type": "string"
          },
          "local_host": {
            "type": "string"
          },
          "local_port": {
            "type": "integer"
          },
          "name": {
            "type": "string"
          },
          "portal": {
            "additionalProperties": false,
            "properties": {
              "applications": {
                "items": {
                  "type": "string"
                },
                "type": "array"
              },
              "category": {
                "type": "string"
              },
              "description": {
                "type": "string"
              },
              "icon": {
                "type": "string"
              },
              "name": {
                "type": "string"
              },
              "socks_tunnel": {
                "type": "string"
              },
              "url": {
                "type": "string"
              }
            },
            "type": "object"
          },
          "protocol": {
            "type": "string"
          },
          "socks": {
            "additionalProperties": false,
            "properties": {
              "allow_all": {
                "type": "boolean"
              },
              "allow_bind": {
                "type": "boolean"
              },
              "asn_filters": {
                "items": {
                  "type": "integer"
                },
                "type": "array"
              },
              "asn_updates": {
                "type": "boolean"
              },
              "asn_url": {
                "type": "string"
              },
              "dns_timeout": {
                "format": "duration",
                "type": "string"
              },
              "domain_filters": {
                "items": {
                  "type": "string"
                },
                "type": "array"
              },
              "filters": {
                "items": {
                  "type": "string"
                },
                "type": "array"
              },
              "only_local": {
                "type": "boolean"
              },
              "reverse_filters": {
                "type": "boolean"
              },
              "udp_idle_timeout": {
                "format": "duration",
                "type": "string"
              },
              "upstream": {
                "type": "string"
              }
            },
            "type": "object"
          },
          "target": {
            "type": "string"
          },
          "udp_idle_timeout": {
            "format": "duration",
            "type": "string"
          },
          "virtual_port": {
            "type": "integer"
          }
        },
        "type": "object"
      },
      "minItems": 0,
      "type": "array"
    }
  },
  "title": "ntwire-server configuration guide",
  "type": "object"
}
```
