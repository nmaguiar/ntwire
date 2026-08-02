package relay

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"gopkg.in/yaml.v3"
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
	Log           logging.Config       `yaml:"log"`
}

type RegistrationConfig struct {
	Name      string `yaml:"name"`
	PublicKey string `yaml:"public_key"`
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

tls:                                        # applies to listen.agents only
  cert_file: ""                            # PEM certificate; set together with key_file, or leave both empty for a generated self-signed certificate
  key_file: ""                             # PEM private key paired with cert_file; required whenever cert_file is set
  state_dir: ""                            # directory for a generated self-signed certificate and key; empty uses this YAML file's directory
  ephemeral: false                          # generate a new in-memory self-signed certificate on every start instead of persisting it in state_dir

domain: relay.example.com                 # wildcard suffix; a server registered as "home" is reached at home.relay.example.com

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

log:
  format: text                              # text or json (Logstash-format, for fluent-bit/Logstash); container images default to json via NTWIRE_LOG_FORMAT
  level: info                                # debug, info, warn, or error
  # Precedence: -log-format/-log-level flags > this file > NTWIRE_LOG_FORMAT/NTWIRE_LOG_LEVEL env > built-in default (text, info). See docs/LOGGING.md.
`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = yaml.Unmarshal(b, &c); err != nil {
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
	seen := map[string]bool{}
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
		out = append(out, Registration{Name: r.Name, PublicKey: key})
	}
	return out, nil
}
