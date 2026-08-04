package server

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"path/filepath"
	"strings"
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
		// Name is an optional friendly label advertised to clients in
		// AuthResponse.ServerName, so a client running a local status UI for
		// several servers at once can tell them apart. Clients that get an
		// empty name fall back to displaying the host:port they connected to.
		Name string `yaml:"name"`
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
	Enabled      bool   `yaml:"enabled"`
	URL          string `yaml:"url"`
	Name         string `yaml:"name"`
	IdentityFile string `yaml:"identity_file"`
	Fingerprint  string `yaml:"fingerprint"`
	// Endpoints enables active-active relay operation. Every endpoint is an
	// agents listener for the same relay tenant/domain; ntwire-server keeps a
	// control connection to each one. URL/Fingerprint remain supported for a
	// single-relay deployment and must not be combined with Endpoints.
	Endpoints    []RelayEndpoint `yaml:"endpoints"`
	ReconnectMin time.Duration   `yaml:"reconnect_min"`
	ReconnectMax time.Duration   `yaml:"reconnect_max"`
	// AdvertiseDirect opts into the opportunistic direct-UDP WireGuard
	// upgrade (see docs/RELAY.md): when true, and the relay has a UDP
	// reflector configured, this server periodically learns its own
	// NAT-mapped UDP address and offers it to authenticated clients via
	// /v1/punch, letting a client that can complete NAT hole-punching bypass
	// the relay for the data plane entirely. Default false: relay mode's
	// whole point for many operators is that the server's real address
	// stays hidden, and this flag is what trades that away for speed.
	//
	// There is deliberately no equivalent flag gating the relay's UDP-relay
	// forwarding tier (see docs/RELAY.md): that tier keeps the relay in the
	// data path for the session's whole life, so it never reveals this
	// server's real address the way AdvertiseDirect does. It carries the
	// same trust exposure as the default WSS-through-relay path, not a new
	// one, so cmd/ntwire-server enables it unconditionally whenever the
	// relay itself offers it (RelayRegisterResponse.UDPRelayAddr != "").
	AdvertiseDirect bool `yaml:"advertise_direct"`
}

// RelayEndpoint is one independently reachable relay agents endpoint. Its
// TLS pin is deliberately per endpoint: an HA pool commonly uses distinct
// certificates even though clients enter through one shared wildcard name.
type RelayEndpoint struct {
	URL         string `yaml:"url"`
	Fingerprint string `yaml:"fingerprint"`
}
type OIDCConfig struct {
	Issuers []OIDCIssuerConfig `yaml:"issuers"`
}
type OIDCIssuerConfig struct {
	Name     string `yaml:"name"`
	Issuer   string `yaml:"issuer"`
	ClientID string `yaml:"client_id"`
	// ClientSecret is only needed for IdPs whose token endpoint requires it
	// even for a public/PKCE client registration (e.g. Google's "Desktop
	// app" client type); see docs/OIDC-SETUP.md. Leave empty for IdPs that
	// don't require it (Entra, Keycloak, ...).
	ClientSecret         string   `yaml:"client_secret"`
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
	//
	// As a convenience for longer instructions, a value with no "\n" is
	// treated as a candidate file path: LoadConfig reads it (relative to the
	// current working directory, like auth.authorized_keys_dir) and uses its
	// content in place of the literal string. A single-line value that does
	// not name an existing file is kept as-is, so short inline instructions
	// still work unchanged.
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
    #   client_secret: ""                  # only needed for IdPs whose token endpoint requires it even for a public client (e.g. Google's "Desktop app" type); see docs/OIDC-SETUP.md
    #   scopes: [openid, email, profile]  # requested OAuth scopes; defaults to these three when omitted
    #   groups_claim: groups               # ID-token claim with group membership; empty disables group: grants
    #   require_verified_email: true       # reject tokens lacking email_verified=true; default: true

network:
  tunnel_cidr: 100.64.0.0/16              # private IPv4 range or an IPv6 prefix (pick one; a deployment is single-family) used to allocate peer tunnel addresses; default shown; for IPv6 use /64 or no shorter than /112
  advertised_endpoint: ""                 # UDP host:port returned to clients when it differs from listen.wireguard, such as behind NAT; host may be a hostname (resolved fresh on every client connect/renew) or a literal IP; must be empty when relay.enabled is true

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

// maxInstructionsFileSize bounds what loadInstructionsFile will read. Without
// it, a tunnel's instructions -- previously bounded by whatever an operator
// typed into YAML -- could balloon to the size of any file on disk the
// server process can read; pkg/instructions.Render truncates to the same
// size, but only after the oversized text has already been shipped to every
// client over /v1/auth and /v1/renew.
const maxInstructionsFileSize = 64 << 10

// loadInstructionsFile resolves TunnelConfig.Instructions as a file path when
// it looks like one rather than inline Markdown: a single-line value (no
// "\n") that names an existing, readable regular file no larger than
// maxInstructionsFileSize. Multi-line values are always literal text, since a
// real file path cannot contain a newline -- this is what lets an operator
// switch from an inline snippet to a longer, separately maintained file
// without an extra config key. Any error (missing file, a directory,
// permissions, too large) leaves t.Instructions untouched, so the original
// string is used as literal instructions text.
func loadInstructionsFile(t *TunnelConfig) {
	if t.Instructions == "" || strings.Contains(t.Instructions, "\n") {
		return
	}
	fi, err := os.Stat(t.Instructions)
	if err != nil || fi.IsDir() || fi.Size() > maxInstructionsFileSize {
		return
	}
	if b, err := os.ReadFile(t.Instructions); err == nil {
		t.Instructions = string(b)
	}
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
	c.Listen.Name = strings.TrimSpace(c.Listen.Name)
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
		if c.Relay.Name == "" || c.Relay.IdentityFile == "" {
			return c, fmt.Errorf("relay.enabled requires relay.name and relay.identity_file")
		}
		if len(c.Relay.Endpoints) > 0 {
			if c.Relay.URL != "" || c.Relay.Fingerprint != "" {
				return c, fmt.Errorf("relay.endpoints cannot be combined with relay.url or relay.fingerprint")
			}
			seenRelayURLs := map[string]bool{}
			for _, endpoint := range c.Relay.Endpoints {
				if endpoint.URL == "" {
					return c, fmt.Errorf("relay.endpoints require url")
				}
				if seenRelayURLs[endpoint.URL] {
					return c, fmt.Errorf("duplicate relay endpoint %q", endpoint.URL)
				}
				seenRelayURLs[endpoint.URL] = true
			}
		} else if c.Relay.URL == "" {
			return c, fmt.Errorf("relay.enabled requires relay.url or relay.endpoints")
		}
		if c.Network.AdvertisedEndpoint != "" {
			return c, fmt.Errorf("relay.enabled cannot be combined with network.advertised_endpoint: a relayed server has no UDP endpoint to advertise")
		}
	} else if c.Relay.AdvertiseDirect {
		return c, fmt.Errorf("relay.advertise_direct requires relay.enabled: it has nothing to do for a server that isn't relaying in the first place")
	}
	if c.Relay.ReconnectMin == 0 {
		c.Relay.ReconnectMin = time.Second
	}
	if c.Relay.ReconnectMax == 0 {
		c.Relay.ReconnectMax = time.Minute
	}
	seen := map[string]bool{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		loadInstructionsFile(t)
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
