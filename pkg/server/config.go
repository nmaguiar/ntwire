package server

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/nmaguiar/ntwire/pkg/instructions"
	"github.com/nmaguiar/ntwire/pkg/logging"
)

type Config struct {
	TLS struct {
		CertFile  string `yaml:"cert_file"`
		KeyFile   string `yaml:"key_file"`
		StateDir  string `yaml:"state_dir"`
		Ephemeral bool   `yaml:"ephemeral"`
	} `yaml:"tls"`
	Listen struct {
		HTTPS     string `yaml:"https"`
		WireGuard string `yaml:"wireguard"`
		Metrics   string `yaml:"metrics"`
	} `yaml:"listen"`
	Auth struct {
		AuthorizedKeysDir string        `yaml:"authorized_keys_dir"`
		OIDC              OIDCConfig    `yaml:"oidc"`
		SessionTTL        time.Duration `yaml:"session_ttl"`
		MaxSessionsPerKey int           `yaml:"max_sessions_per_key"`
	} `yaml:"auth"`
	Admin struct {
		WebUIToken string `yaml:"web_ui_token"`
	} `yaml:"admin"`
	Network struct {
		TunnelCIDR         string `yaml:"tunnel_cidr"`
		AdvertisedEndpoint string `yaml:"advertised_endpoint"`
	} `yaml:"network"`
	Authorizer AuthorizerConfig `yaml:"authorizer"`
	Relay      RelayConfig      `yaml:"relay"`
	Tunnels    []TunnelConfig   `yaml:"tunnels"`
	Log        logging.Config   `yaml:"log"`
	Audit      struct {
		LogFile string `yaml:"log_file"`
	} `yaml:"audit"`
}

// RelayConfig configures ntwire-server to dial out to an ntwire-relay
// instead of listening for inbound connections directly (see PLAN-RELAY.md).
// When Enabled, listen.https is never bound; the server instead maintains an
// outbound control connection and serves its unchanged Handler() over
// dial-back data connections.
type RelayConfig struct {
	Enabled      bool          `yaml:"enabled"`
	URL          string        `yaml:"url"`
	Name         string        `yaml:"name"`
	IdentityFile string        `yaml:"identity_file"`
	Fingerprint  string        `yaml:"fingerprint"`
	ReconnectMin time.Duration `yaml:"reconnect_min"`
	ReconnectMax time.Duration `yaml:"reconnect_max"`
}
type OIDCConfig struct {
	Issuers []OIDCIssuerConfig `yaml:"issuers"`
}
type OIDCIssuerConfig struct {
	Name                 string   `yaml:"name"`
	Issuer               string   `yaml:"issuer"`
	ClientID             string   `yaml:"client_id"`
	Scopes               []string `yaml:"scopes"`
	GroupsClaim          string   `yaml:"groups_claim"`
	RequireVerifiedEmail *bool    `yaml:"require_verified_email"`
}

func (c OIDCIssuerConfig) RequireVerified() bool {
	return c.RequireVerifiedEmail == nil || *c.RequireVerifiedEmail
}

type AuthorizerConfig struct {
	WebhookURL string        `yaml:"webhook_url"`
	Exec       string        `yaml:"exec"`
	Timeout    time.Duration `yaml:"timeout"`
}
type TunnelConfig struct {
	Name        string   `yaml:"name"`
	Target      string   `yaml:"target"`
	Description string   `yaml:"description"`
	VirtualPort int      `yaml:"virtual_port"`
	LocalPort   int      `yaml:"local_port"`
	Allow       []string `yaml:"allow"`

	// Instructions is optional Markdown shown to clients in their local
	// status UI, describing how to point a tool at this tunnel. It is
	// expanded as a Go template on the client, where the real loopback port
	// is known: see pkg/client/instructions for the available fields.
	Instructions string `yaml:"instructions"`
	// DocsURL is an optional http(s) link offered next to Instructions for
	// users who want the full setup documentation.
	DocsURL string `yaml:"docs_url"`

	// Socks configures this tunnel as an embedded SOCKS4/5 proxy instead of
	// a fixed-target forward. It is used, and required, when Target is the
	// sentinel value "socks"; see SocksConfig.
	Socks *SocksConfig `yaml:"socks"`
}

// socksTarget is the TunnelConfig.Target sentinel that marks a tunnel as an
// embedded SOCKS proxy rather than a fixed host:port forward.
const socksTarget = "socks"

// IsSocks reports whether t is an embedded-SOCKS-server tunnel.
func (t TunnelConfig) IsSocks() bool {
	return t.Target == socksTarget
}

// SocksConfig configures an embedded SOCKS tunnel's destination filtering,
// re-implementing (not vendoring -- it isn't Go) the filter/feature set of
// github.com/nmaguiar/socksd: see pkg/socks for the ported filter engine.
//
// Unlike socksd, an unfiltered SOCKS tunnel defaults to denying every
// destination rather than allowing all of them: socksd's allow-all default
// would silently turn an authenticated ntwire session into an open egress
// proxy. Set AllowAll to opt into socksd's original behavior.
type SocksConfig struct {
	OnlyLocal      bool          `yaml:"only_local"`
	Filters        []string      `yaml:"filters"`
	DomainFilters  []string      `yaml:"domain_filters"`
	ASNFilters     []uint32      `yaml:"asn_filters"`
	ASNUpdates     *bool         `yaml:"asn_updates"`
	ASNURL         string        `yaml:"asn_url"`
	ReverseFilters bool          `yaml:"reverse_filters"`
	DNSTimeout     time.Duration `yaml:"dns_timeout"`
	AllowAll       bool          `yaml:"allow_all"`
}

// WantsASNUpdates reports whether the background ASN index refresh should
// run: explicitly enabled, or implicitly whenever ASN filters are in use
// and the setting was left unspecified.
func (c SocksConfig) WantsASNUpdates() bool {
	if c.ASNUpdates != nil {
		return *c.ASNUpdates
	}
	return len(c.ASNFilters) > 0
}

// deniesAllByDefault reports whether this configuration has no filters at
// all (and did not opt into AllowAll), meaning pkg/socks.Filter.Allowed
// will deny every destination. Mirrors the "no filters configured" branch
// of pkg/socks's ported filter engine, used only to emit a startup warning.
func (c SocksConfig) deniesAllByDefault() bool {
	return !c.OnlyLocal && !c.AllowAll &&
		len(c.Filters) == 0 && len(c.DomainFilters) == 0 && len(c.ASNFilters) == 0 && !c.ReverseFilters
}

// SampleConfig returns a complete, commented server configuration template.
// The template is valid YAML and uses a key-based authentication example so it
// can be used as a starting point without configuring an OIDC provider.
func SampleConfig() string {
	return `# ntwire server configuration
#
# At least one authentication method is required: auth.authorized_keys_dir,
# auth.oidc.issuers, or both. Uncomment and adapt the OIDC example below to
# enable single sign-on alongside SSH public-key authentication.

listen:
  https: ":8443"                         # TLS control API and WebSocket fallback listener; default: :8443
  wireguard: ":51820"                    # UDP listener for the userspace WireGuard data plane; default: :51820
  metrics: ""                             # optional plaintext metrics/dashboard listener; exposes /metrics and, with admin.web_ui_token, /?token=... (for example, 127.0.0.1:9090)

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
    #   client_id: 1234-abc.apps.googleusercontent.com # public OAuth client ID (PKCE; no client secret)
    #   scopes: [openid, email, profile]  # requested OAuth scopes; defaults to these three when omitted
    #   groups_claim: groups               # ID-token claim with group membership; empty disables group: grants
    #   require_verified_email: true       # reject tokens lacking email_verified=true; default: true

network:
  tunnel_cidr: 100.64.0.0/16              # private IPv4 range or an IPv6 prefix (pick one; a deployment is single-family) used to allocate peer tunnel addresses; default shown; for IPv6 use /64 or no shorter than /112
  advertised_endpoint: ""                 # UDP host:port returned to clients when it differs from listen.wireguard, such as behind NAT; must be empty when relay.enabled is true

relay:
  enabled: false                          # when true, listen.https is never bound; the server dials out to an ntwire-relay instead (see PLAN-RELAY.md)
  url: ""                                 # wss://relay.example.com:8444, the relay's listen.agents endpoint
  name: home                              # tenant label; must match this key's registrations[] entry on the relay
  identity_file: /etc/ntwire/relay_id_ed25519 # private key used to sign relay registration, separate from auth.authorized_keys_dir
  fingerprint: ""                         # SHA256:... pin of the relay's listen.agents TLS certificate; empty verifies against normal PKI instead
  reconnect_min: 1s                        # initial backoff after a dropped control connection; default: 1s
  reconnect_max: 1m                        # backoff ceiling; default: 1m
  # When relay.enabled is true, consider setting listen.wireguard to
  # "127.0.0.1:0": WireGuard rides the /v1/wg WebSocket fallback in relay
  # mode, so the UDP socket StartDataPlane still opens is unused.

authorizer:
  webhook_url: ""                         # URL that receives a JSON POST for each connection and returns an allow/deny decision; takes precedence when both hook options are set
  exec: ""                                # executable that receives the same JSON on stdin and returns an allow/deny decision when webhook_url is empty
  timeout: 5s                              # deadline for the webhook or executable; errors and timeouts deny the request; default: 5s

admin:
  web_ui_token: ""                         # optional secret that enables the server dashboard at /?token=...; leave empty to disable it

tunnels:
  - name: reports                          # unique identifier shown to clients
    target: reports.internal:8080          # host:port the server proxies to after traffic reaches its virtual port
    description: Reporting service         # optional free-text description shown to clients
    virtual_port: 18080                    # required port exposed inside the WireGuard tunnel; 1 through 65535
    local_port: 58080                      # preferred client loopback port; 0 chooses any free port, and an occupied value falls back to one
    docs_url: ""                             # optional absolute http(s) link offered as "See more" beside the instructions below
    instructions: |                          # optional Markdown shown in the client status UI, expanded there as a Go template
      Fetch a report through the tunnel:

      ~~~sh
      curl -s http://{{.LocalHost}}:{{.LocalPort}}/reports/latest
      ~~~

      Fields: .Name, .Description, .LocalAddress, .LocalHost, .LocalPort, .VirtualPort,
      .TargetHint, .TunnelIP, .ServerTunnelIP, .Server. Fenced blocks get a copy button.
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

log:
  format: text                             # text or json (Logstash-format, for fluent-bit/Logstash); container images default to json via NTWIRE_LOG_FORMAT
  level: info                               # debug, info, warn, or error
  # Precedence: -log-format/-log-level flags > this file > NTWIRE_LOG_FORMAT/NTWIRE_LOG_LEVEL env > built-in default (text, info). See docs/LOGGING.md.

audit:
  log_file: ""                             # optional path for a dedicated JSON-lines audit log (auth_allowed, session_disconnected, session_expired, session_revoked); in addition to, not instead of, the main log
`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = yaml.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if c.TLS.StateDir == "" {
		c.TLS.StateDir = filepath.Dir(path)
	}
	if c.Listen.HTTPS == "" {
		c.Listen.HTTPS = ":8443"
	}
	if c.Listen.WireGuard == "" {
		c.Listen.WireGuard = ":51820"
	}
	if c.Auth.SessionTTL == 0 {
		c.Auth.SessionTTL = 15 * time.Minute
	}
	if c.Authorizer.Timeout == 0 {
		c.Authorizer.Timeout = 5 * time.Second
	}
	if c.Auth.AuthorizedKeysDir == "" && len(c.Auth.OIDC.Issuers) == 0 {
		return c, fmt.Errorf("at least one of auth.authorized_keys_dir or auth.oidc.issuers is required")
	}
	seenIssuers := map[string]bool{}
	for i := range c.Auth.OIDC.Issuers {
		iss := &c.Auth.OIDC.Issuers[i]
		if iss.Name == "" || iss.Issuer == "" || iss.ClientID == "" {
			return c, fmt.Errorf("auth.oidc.issuers require name, issuer, and client_id")
		}
		if seenIssuers[iss.Name] {
			return c, fmt.Errorf("duplicate oidc issuer %q", iss.Name)
		}
		seenIssuers[iss.Name] = true
		if len(iss.Scopes) == 0 {
			iss.Scopes = []string{"openid", "email", "profile"}
		}
	}
	if c.Network.TunnelCIDR == "" {
		c.Network.TunnelCIDR = "100.64.0.0/16"
	}
	if _, _, e = net.ParseCIDR(c.Network.TunnelCIDR); e != nil {
		return c, fmt.Errorf("network.tunnel_cidr: %w", e)
	}
	if c.Relay.Enabled {
		if c.Relay.URL == "" || c.Relay.Name == "" || c.Relay.IdentityFile == "" {
			return c, fmt.Errorf("relay.enabled requires relay.url, relay.name, and relay.identity_file")
		}
		if c.Network.AdvertisedEndpoint != "" {
			return c, fmt.Errorf("relay.enabled cannot be combined with network.advertised_endpoint: a relayed server has no UDP endpoint to advertise")
		}
	}
	if c.Relay.ReconnectMin == 0 {
		c.Relay.ReconnectMin = time.Second
	}
	if c.Relay.ReconnectMax == 0 {
		c.Relay.ReconnectMax = time.Minute
	}
	seen := map[string]bool{}
	for _, t := range c.Tunnels {
		if t.Name == "" || t.Target == "" {
			return c, fmt.Errorf("tunnels require name and target")
		}
		if seen[t.Name] {
			return c, fmt.Errorf("duplicate tunnel %q", t.Name)
		}
		seen[t.Name] = true
		if t.VirtualPort < 1 || t.VirtualPort > 65535 {
			return c, fmt.Errorf("tunnel %q requires virtual_port in 1..65535", t.Name)
		}
		if t.LocalPort < 0 || t.LocalPort > 65535 {
			return c, fmt.Errorf("tunnel %q requires local_port in 0..65535", t.Name)
		}
		if t.DocsURL != "" && !instructions.SafeURL(t.DocsURL) {
			return c, fmt.Errorf("tunnel %q requires an absolute http(s) docs_url", t.Name)
		}
		if t.IsSocks() {
			if t.Socks == nil {
				return c, fmt.Errorf("tunnel %q: target: socks requires a socks: block", t.Name)
			}
			for _, cidr := range t.Socks.Filters {
				if _, _, e := net.ParseCIDR(cidr); e != nil {
					return c, fmt.Errorf("tunnel %q: socks.filters: %w", t.Name, e)
				}
			}
			if t.Socks.DNSTimeout < 0 {
				return c, fmt.Errorf("tunnel %q: socks.dns_timeout must not be negative", t.Name)
			}
		} else if t.Socks != nil {
			return c, fmt.Errorf("tunnel %q: socks: block requires target: socks", t.Name)
		}
	}
	return c, nil
}
