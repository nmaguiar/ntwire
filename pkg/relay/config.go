package relay

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/configguide"
	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
)

type Config struct {
	Listen struct {
		Public string `yaml:"public"`
		Agents string `yaml:"agents"`
		// Reflect is an optional UDP address-reflection endpoint (see
		// pkg/relay's reflector). Empty disables it, which is also the
		// default: it only matters to a registered server that opts into
		// the direct-connection upgrade via relay.advertise_direct, and
		// enabling it is a deliberate operator choice since it lets such a
		// server (and its clients) learn their own public UDP mapping
		// through the relay.
		Reflect string `yaml:"reflect"`
		// UDPRelay is the shared, client-facing UDP address for the
		// UDP-relay forwarding tier (see pkg/relay's datagramRelay). Empty
		// disables the tier entirely, which is also the default. Unlike
		// Reflect, no server-side flag gates participation once this is
		// set: the tier never reveals a relayed server's real address (the
		// relay stays in the data path throughout), so there is no
		// advertise_direct-style trust step-change to opt into. See
		// docs/RELAY.md.
		UDPRelay string `yaml:"udp_relay"`
		// UDPRelayPorts is the inclusive "min-max" port range the relay
		// draws one dedicated server-leg UDP socket from per live
		// UDP-relay session (TURN-style per-session allocation -- see
		// docs/RELAY.md). Every port in range is bound eagerly at Start,
		// the same style as Public/Agents/Reflect, so an operator's
		// firewall rule for this range is complete and static from the
		// moment the relay starts. Required whenever UDPRelay is set.
		UDPRelayPorts string `yaml:"udp_relay_ports"`
		// UDPBufferBytes is the requested kernel read and write buffer size
		// for relay UDP sockets. Zero uses the conservative production
		// default. The operating system may clamp it; a clamp is diagnostic,
		// never a startup failure.
		UDPBufferBytes int `yaml:"udp_buffer_bytes"`
	} `yaml:"listen"`
	TLS struct {
		CertFile  string `yaml:"cert_file"`
		KeyFile   string `yaml:"key_file"`
		StateDir  string `yaml:"state_dir"`
		Ephemeral bool   `yaml:"ephemeral"`
	} `yaml:"tls"`
	Domain string `yaml:"domain"`
	Limits struct {
		HandshakeTimeout     time.Duration `yaml:"handshake_timeout"`
		DialBackTimeout      time.Duration `yaml:"dial_back_timeout"`
		MaxPendingPerServer  int           `yaml:"max_pending_per_server"`
		MaxConnsPerServer    int           `yaml:"max_conns_per_server"`
		MaxNewConnsPerMinute int           `yaml:"max_new_conns_per_minute"`
		// UDPRelayIdleTimeout reclaims a UDP-relay session (and its pooled
		// port) that has seen no bind/keepalive/forwarded traffic on either
		// leg for this long. Comfortably above the client/server keepalive
		// interval (~15s) so one missed keepalive tick doesn't tear down a
		// healthy session.
		UDPRelayIdleTimeout time.Duration `yaml:"udp_relay_idle_timeout"`
		// MaxUDPRelaySessionsPerServer caps concurrent UDP-relay sessions
		// per tenant, independent of the relay-wide pool size
		// (listen.udp_relay_ports) -- the same relationship
		// MaxConnsPerServer has to the relay's overall fd/connection
		// budget.
		MaxUDPRelaySessionsPerServer int `yaml:"max_udp_relay_sessions_per_server"`
	} `yaml:"limits"`
	Registrations []RegistrationConfig `yaml:"registrations"`
	Kubernetes    KubernetesConfig     `yaml:"kubernetes"`
	Log           logging.Config       `yaml:"log"`
}

// KubernetesConfig enables opt-in Service discovery. Services are selected
// deliberately: a matching label, relay-enabled=true, and a hostname
// annotation are all required before a Service can receive public traffic.
type KubernetesConfig struct {
	Enabled    bool `yaml:"enabled"`
	Namespaces struct {
		Mode     string   `yaml:"mode"` // all or selected
		Names    []string `yaml:"names"`
		Selector string   `yaml:"selector"`
	} `yaml:"namespaces"`
	Service struct {
		Selector string `yaml:"selector"`
		PortName string `yaml:"port_name"`
	} `yaml:"service"`
	Registration struct {
		HostnameAnnotation string `yaml:"hostname_annotation"`
		TenantAnnotation   string `yaml:"tenant_annotation"`
	} `yaml:"registration"`
}

type RegistrationConfig struct {
	Name            string `yaml:"name"`
	PublicKey       string `yaml:"public_key"`
	Listen          string `yaml:"listen"`
	NativeWireGuard struct {
		Listen string `yaml:"listen"`
	} `yaml:"native_wireguard"`
}

// SampleConfig returns a complete, commented relay configuration template,
// mirroring the style of pkg/server/config.go's SampleConfig.
func SampleConfig() string {
	return `# ntwire-relay configuration
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
`
}

// ConfigGuide renders the relay configuration reference from the canonical
// SampleConfig YAML template.
func ConfigGuide() (string, error) { return relayGuide().Markdown() }

// ConfigJSONSchema renders the strict Draft 2020-12 schema used by tooling.
func ConfigJSONSchema() ([]byte, error) { return relayGuide().JSONSchema() }

// WriteConfigSkill creates a portable, low-context Agent Skill folder for
// generating and reviewing ntwire-relay configuration.
func WriteConfigSkill(dir string) error { return relayGuide().WriteSkill(dir) }

func relayGuide() configguide.Guide {
	return configguide.Guide{
		Title:       "ntwire-relay configuration guide",
		Description: "Complete reference for ntwire-relay YAML configuration.",
		Sample:      SampleConfig(), Root: Config{},
		Skill: relayConfigSkill(),
		QA: []configguide.QA{
			{Question: "What domain and TLS are required?", Answer: "Set domain to the wildcard suffix and configure TLS for listen.agents; public client TLS is spliced, never terminated."},
			{Question: "Which listeners are needed?", Answer: "listen.public and listen.agents have defaults. reflect and udp_relay are optional UDP services."},
			{Question: "How are tenants registered?", Answer: "Each registration needs a lowercase DNS-label name and an authorized SSH public key; optional dedicated TCP/UDP listeners bypass shared routing."},
			{Question: "Need direct UDP or UDP relay?", Answer: "reflect supports server opt-in direct-UDP discovery; udp_relay needs udp_relay_ports and retains the relay in the data path."},
			{Question: "How should capacity be set?", Answer: "Set limits for handshake, dial-back, connections, rate, and UDP relay sessions; the UDP port range bounds the relay pool."},
			{Question: "Need native WireGuard?", Answer: "Set registration native_wireguard.listen for a dedicated UDP endpoint per tenant."},
			{Question: "Need Kubernetes discovery?", Answer: "Enable it only with valid namespace/service selectors and the required service port name."},
		},
		Rules: []string{
			"domain is required and must be a normalized DNS name; registration names are lowercase DNS labels and registration public keys must parse.",
			"listen.udp_relay_ports is required and must be a valid 1-65535 range whenever listen.udp_relay is set.",
			"When kubernetes.enabled is true, service.selector and service.port_name are required; selected namespaces need names or selector.",
			"cert_file and key_file must be set together or both left empty for generated TLS.",
		},
		SchemaOverrides: map[string]map[string]any{
			"listen.public": {"default": ":443"}, "listen.agents": {"default": ":8444"},
			"listen.udp_relay_ports":   {"pattern": "^[0-9]+(-[0-9]+)?$"},
			"limits.handshake_timeout": {"default": "5s"}, "limits.dial_back_timeout": {"default": "10s"},
			"limits.max_pending_per_server": {"default": 32, "minimum": 1}, "limits.max_conns_per_server": {"default": 256, "minimum": 1},
			"limits.max_new_conns_per_minute": {"default": 60, "minimum": 1}, "limits.udp_relay_idle_timeout": {"default": "60s"},
			"limits.max_udp_relay_sessions_per_server": {"default": 64, "minimum": 1},
			"kubernetes.namespaces.mode":               {"enum": []string{"all", "selected"}, "default": "all"},
			"log.format":                               {"enum": []string{"text", "json"}, "default": "text"}, "log.level": {"enum": []string{"debug", "info", "warn", "error"}, "default": "info"},
		},
	}
}

func relayConfigSkill() configguide.Skill {
	return configguide.Skill{
		Name:        "ntwire-relay-config",
		Description: "Generate or review safe ntwire-relay YAML from a user's public relay, tenant registration, UDP, capacity, and Kubernetes requirements.",
		Binary:      "ntwire-relay",
		Workflow: []string{
			"Read references/core.md, then match the requested capability to one additional reference below. Do not preload unrelated references.",
			"Ask only for missing values required by the selected feature. If an existing YAML file is supplied, preserve unrelated fields and report assumptions separately.",
			"Return the proposed YAML or a minimal patch, the unresolved choices, and any DNS, certificate, firewall, or key-installation work that remains. Never put private keys, bearer tokens, or a real registration public-key value in generated YAML.",
			"Validate the resulting file with ntwire-relay -check-config -config <path> before deployment.",
		},
		References: []configguide.SkillReference{
			{Path: "references/core.md", When: "public relay, wildcard domain, TLS, or basic listeners", Content: `# Core relay configuration

Ask for the wildcard client domain, public TCP listener, server-agent listener, and TLS certificate source. The public listener only splices client TLS based on SNI; the relay does not terminate it. TLS settings apply to listen.agents.

~~~yaml
listen:
  public: ":443"
  agents: ":8444"
tls:
  cert_file: "/etc/ntwire/agents.crt"
  key_file: "/etc/ntwire/agents.key"
domain: "relay.example.com"
~~~

domain is required and must be a normalized DNS name. A tenant named home is reached as home.relay.example.com when it has a matching registration. Set cert_file and key_file together, or leave both empty only when generated TLS is acceptable.`},
			{Path: "references/registrations.md", When: "tenant, server registration, dedicated listener, or native WireGuard endpoint", Content: `# Tenant registrations

Ask for every tenant's lowercase DNS-label name, an operator-provided SSH public key, and whether it needs a dedicated TCP listener or native WireGuard UDP endpoint. A registration authorizes one server identity to claim the tenant name.

~~~yaml
registrations:
  - name: "home"
    public_key: "<operator-provided-ssh-public-key>"
    listen: ""
    native_wireguard:
      listen: ""
~~~

The ntwire-server relay.name and relay.identity_file must match this registration. A non-empty registration.listen bypasses the shared wildcard DNS and SNI route. Do not use a placeholder key as a deployed value.`},
			{Path: "references/udp.md", When: "direct UDP discovery, UDP relay, firewall range, or UDP socket tuning", Content: `# UDP features

Ask whether the deployment needs direct-address discovery, relayed UDP data, or both. listen.reflect supports direct-UDP discovery only for servers that explicitly set relay.advertise_direct: true; it can expose the server's mapped address. listen.udp_relay keeps the relay in the data path and requires an open, sized server-leg port range.

~~~yaml
listen:
  reflect: ":3480"
  udp_relay: ":3481"
  udp_relay_ports: "40000-40999"
  udp_buffer_bytes: 4194304
limits:
  udp_relay_idle_timeout: 60s
  max_udp_relay_sessions_per_server: 64
~~~

When udp_relay is set, udp_relay_ports is mandatory and every port in the inclusive range is bound at startup. The firewall must allow the shared client port and the entire server-leg range. Keep reflect empty unless direct discovery is explicitly wanted.`},
			{Path: "references/capacity.md", When: "tenant limits, rate limits, connection capacity, or relay sizing", Content: `# Capacity and limits

Ask for expected concurrent client connections, peak new connections per minute per source IP, and expected simultaneous UDP-relay sessions per tenant. Size the UDP port range and max_udp_relay_sessions_per_server together; neither setting alone establishes capacity.

~~~yaml
limits:
  handshake_timeout: 5s
  dial_back_timeout: 10s
  max_pending_per_server: 32
  max_conns_per_server: 256
  max_new_conns_per_minute: 60
  udp_relay_idle_timeout: 60s
  max_udp_relay_sessions_per_server: 64
~~~

These limits fail closed under load. Do not increase them without confirming file-descriptor, CPU, memory, and firewall capacity.`},
			{Path: "references/kubernetes.md", When: "Kubernetes Service discovery", Content: `# Kubernetes Service discovery

Use Kubernetes discovery only when the relay should route to selected Services instead of, or alongside, authenticated outbound server registrations. Ask for the namespaces, namespace selector, Service selector, named Service port, and the hostname annotation. It is TCP TLS-passthrough only; it does not enable native WireGuard or UDP discovery.

~~~yaml
kubernetes:
  enabled: true
  namespaces:
    mode: "selected"
    names: ["production"]
    selector: ""
  service:
    selector: "app.kubernetes.io/name=ntwire-server"
    port_name: "ntwire-relay"
  registration:
    hostname_annotation: "ntwire.io/hostname"
    tenant_annotation: "ntwire.io/tenant"
~~~

When enabled, service.selector and service.port_name are required. With namespaces.mode set to selected, provide names or a selector. The selected Service also needs ntwire.io/relay-enabled=true and a valid hostname annotation.`},
		},
	}
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err = decoder.Decode(&c); err != nil {
		return c, err
	}
	if c.TLS.StateDir == "" {
		c.TLS.StateDir = filepath.Dir(path)
	}
	if c.Listen.Public == "" {
		c.Listen.Public = ":443"
	}
	if c.Listen.Agents == "" {
		c.Listen.Agents = ":8444"
	}
	if c.Domain == "" {
		return c, fmt.Errorf("domain is required")
	}
	// resolveTenant (public.go) compares the ClientHello SNI -- already
	// lowercased and trailing-dot-trimmed by peekClientHello -- against
	// this domain with a case-sensitive suffix match. An un-normalized
	// domain here (mixed case, or a stray trailing dot) would never match
	// any real SNI, silently resetting every client connection with no log
	// line to explain why.
	c.Domain = normalizeSNI(c.Domain)
	if c.Domain == "" || strings.HasPrefix(c.Domain, ".") || strings.HasSuffix(c.Domain, ".") || strings.Contains(c.Domain, "..") {
		return c, fmt.Errorf("domain %q is not a valid DNS name", c.Domain)
	}
	if c.Limits.HandshakeTimeout == 0 {
		c.Limits.HandshakeTimeout = 5 * time.Second
	}
	if c.Limits.DialBackTimeout == 0 {
		c.Limits.DialBackTimeout = 10 * time.Second
	}
	if c.Limits.MaxPendingPerServer == 0 {
		c.Limits.MaxPendingPerServer = 32
	}
	if c.Limits.MaxConnsPerServer == 0 {
		c.Limits.MaxConnsPerServer = 256
	}
	if c.Limits.MaxNewConnsPerMinute == 0 {
		c.Limits.MaxNewConnsPerMinute = 60
	}
	if c.Limits.UDPRelayIdleTimeout == 0 {
		c.Limits.UDPRelayIdleTimeout = 60 * time.Second
	}
	if c.Limits.MaxUDPRelaySessionsPerServer == 0 {
		c.Limits.MaxUDPRelaySessionsPerServer = 64
	}
	if c.Listen.UDPRelay != "" {
		if c.Listen.UDPRelayPorts == "" {
			return c, fmt.Errorf("listen.udp_relay_ports is required when listen.udp_relay is set")
		}
		if _, _, err := parsePortRange(c.Listen.UDPRelayPorts); err != nil {
			return c, fmt.Errorf("listen.udp_relay_ports: %w", err)
		}
	}
	if c.Kubernetes.Enabled {
		if c.Kubernetes.Namespaces.Mode == "" {
			c.Kubernetes.Namespaces.Mode = "all"
		}
		if c.Kubernetes.Namespaces.Mode != "all" && c.Kubernetes.Namespaces.Mode != "selected" {
			return c, fmt.Errorf("kubernetes.namespaces.mode must be all or selected")
		}
		if c.Kubernetes.Namespaces.Mode == "selected" && len(c.Kubernetes.Namespaces.Names) == 0 && c.Kubernetes.Namespaces.Selector == "" {
			return c, fmt.Errorf("kubernetes.namespaces.selected requires names or selector")
		}
		if c.Kubernetes.Service.Selector == "" {
			return c, fmt.Errorf("kubernetes.service.selector is required when kubernetes.enabled is true")
		}
		if _, err := labels.Parse(c.Kubernetes.Service.Selector); err != nil {
			return c, fmt.Errorf("kubernetes.service.selector: %w", err)
		}
		if c.Kubernetes.Namespaces.Selector != "" {
			if _, err := labels.Parse(c.Kubernetes.Namespaces.Selector); err != nil {
				return c, fmt.Errorf("kubernetes.namespaces.selector: %w", err)
			}
		}
		if c.Kubernetes.Service.PortName == "" {
			return c, fmt.Errorf("kubernetes.service.port_name is required when kubernetes.enabled is true")
		}
		if c.Kubernetes.Registration.HostnameAnnotation == "" {
			c.Kubernetes.Registration.HostnameAnnotation = "ntwire.io/hostname"
		}
		if c.Kubernetes.Registration.TenantAnnotation == "" {
			c.Kubernetes.Registration.TenantAnnotation = "ntwire.io/tenant"
		}
	}
	seen := map[string]bool{}
	seenListen := map[string]bool{}
	seenNative := map[string]bool{}
	for _, r := range c.Registrations {
		if r.Name == "" || r.PublicKey == "" {
			return c, fmt.Errorf("registrations require name and public_key")
		}
		// resolveTenant (public.go) only ever matches a lowercase
		// [a-z0-9-]+ label against the SNI's leading component. A name
		// that fails validLabel here would register successfully and then
		// never match any client connection, again with nothing logged to
		// explain the silent reset.
		if !validLabel(r.Name) {
			return c, fmt.Errorf("registration name %q must be a lowercase DNS label ([a-z0-9-]+)", r.Name)
		}
		if seen[r.Name] {
			return c, fmt.Errorf("duplicate registration name %q", r.Name)
		}
		seen[r.Name] = true
		if r.Listen != "" {
			if _, _, err := net.SplitHostPort(r.Listen); err != nil {
				return c, fmt.Errorf("registration %q listen: %w", r.Name, err)
			}
			if r.Listen == c.Listen.Public {
				return c, fmt.Errorf("registration %q listen %q conflicts with listen.public", r.Name, r.Listen)
			}
			if r.Listen == c.Listen.Agents {
				return c, fmt.Errorf("registration %q listen %q conflicts with listen.agents", r.Name, r.Listen)
			}
			if seenListen[r.Listen] {
				return c, fmt.Errorf("duplicate TCP listener %q", r.Listen)
			}
			seenListen[r.Listen] = true
		}
		if r.NativeWireGuard.Listen != "" {
			if _, _, err := net.SplitHostPort(r.NativeWireGuard.Listen); err != nil {
				return c, fmt.Errorf("registration %q native_wireguard.listen: %w", r.Name, err)
			}
			if seenNative[r.NativeWireGuard.Listen] {
				return c, fmt.Errorf("duplicate native WireGuard listener %q", r.NativeWireGuard.Listen)
			}
			seenNative[r.NativeWireGuard.Listen] = true
		}
		if _, _, err := sshkey.ParsePublicString(r.PublicKey); err != nil {
			return c, fmt.Errorf("registration %q: invalid public_key: %w", r.Name, err)
		}
	}
	return c, nil
}

// parsePortRange parses an inclusive "min-max" port range as used by
// listen.udp_relay_ports. Both bounds must be valid, non-zero TCP/UDP ports
// with min <= max; a single port ("N-N" or bare "N") is allowed.
func parsePortRange(s string) (min, max uint16, err error) {
	before, after, found := strings.Cut(s, "-")
	if !found {
		before, after = s, s
	}
	minI, err1 := strconv.Atoi(strings.TrimSpace(before))
	maxI, err2 := strconv.Atoi(strings.TrimSpace(after))
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("invalid port range %q: must be \"min-max\"", s)
	}
	if minI < 1 || minI > 65535 || maxI < 1 || maxI > 65535 {
		return 0, 0, fmt.Errorf("invalid port range %q: ports must be in 1-65535", s)
	}
	if minI > maxI {
		return 0, 0, fmt.Errorf("invalid port range %q: min must be <= max", s)
	}
	return uint16(minI), uint16(maxI), nil
}

// ParseRegistrations resolves configured registrations to parsed public
// keys, ready for NewRegistry. LoadConfig already validated that every
// public_key parses, so an error here indicates the config was constructed
// programmatically rather than through LoadConfig.
func ParseRegistrations(cfgs []RegistrationConfig) ([]Registration, error) {
	out := make([]Registration, 0, len(cfgs))
	for _, r := range cfgs {
		key, _, err := sshkey.ParsePublicString(r.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("registration %q: invalid public_key: %w", r.Name, err)
		}
		out = append(out, Registration{Name: r.Name, PublicKey: key, Listen: r.Listen})
	}
	return out, nil
}
