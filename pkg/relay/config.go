package relay

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen struct {
		Public string `yaml:"public"`
		Agents string `yaml:"agents"`
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
	} `yaml:"limits"`
	Registrations []RegistrationConfig `yaml:"registrations"`
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

registrations:
  - name: home                              # first DNS label; clients use https://home.relay.example.com
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINA2Gh3ezOG8R0iaD0WVnVsJTQGHqjI96LwGrIc/Kwgc admin@laptop" # authorized_keys line identifying the ntwire-server allowed to claim this name; replace with your own
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
	seen := map[string]bool{}
	for _, r := range c.Registrations {
		if r.Name == "" || r.PublicKey == "" {
			return c, fmt.Errorf("registrations require name and public_key")
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
