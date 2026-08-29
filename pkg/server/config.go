package server

import (
	"bytes"
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/configguide"
	"github.com/nmaguiar/ntwire/pkg/instructions"
	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/portal"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
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
		TunnelCIDR              string    `yaml:"tunnel_cidr"`
		AdvertisedEndpoint      string    `yaml:"advertised_endpoint"`
		WireGuardPrivateKeyFile string    `yaml:"wireguard_private_key_file"`
		DNS                     DNSConfig `yaml:"dns"`
	} `yaml:"network"`
	Transport struct {
		// Multipath controls the scheduler when both WebSocket and UDP legs
		// are available. Nil is enabled for backward-compatible defaults;
		// set false only to retain the legacy one-leg data plane.
		Multipath *bool `yaml:"multipath"`
		// Force pins every negotiated multipath peer to this candidate while it
		// is healthy. Valid values are auto (the default), wss, udp-relay, and
		// direct-udp. An unavailable forced path safely falls back to automatic
		// scheduling rather than disconnecting the peer.
		Force string `yaml:"force"`
	} `yaml:"transport"`
	Authorizer          AuthorizerConfig             `yaml:"authorizer"`
	DestinationPolicies map[string]DestinationPolicy `yaml:"destination_policies"`
	NativeWireGuard     NativeWireGuardConfig        `yaml:"native_wireguard"`
	Relay               RelayConfig                  `yaml:"relay"`
	MASQUE              MASQUEConfig                 `yaml:"masque"`
	Portal              portal.PortalConfig          `yaml:"portal"`
	Tunnels             []TunnelConfig               `yaml:"tunnels"`
	Log                 logging.Config               `yaml:"log"`
	Audit               struct {
		LogFile string `yaml:"log_file"`
	} `yaml:"audit"`
}

// MultipathEnabled reports the effective transport.multipath setting.
func (c Config) MultipathEnabled() bool {
	return c.Transport.Multipath == nil || *c.Transport.Multipath
}

// MASQUEConfig configures the opt-in Network Relay gateway. It is deliberately
// independent from the existing WireGuard and WebSocket data planes.
type MASQUEConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Listen         string        `yaml:"listen"`
	HTTP2URL       string        `yaml:"http2_url"`
	HTTP3URL       string        `yaml:"http3_url"`
	MatchDomains   []string      `yaml:"match_domains"`
	ClientCAFile   string        `yaml:"client_ca_file"`
	IssuerCertFile string        `yaml:"issuer_cert_file"`
	IssuerKeyFile  string        `yaml:"issuer_key_file"`
	CertificateTTL time.Duration `yaml:"certificate_ttl"`
	// Tunnels maps a synthetic relay FQDN to one fixed ntwire tunnel name.
	// There is deliberately no wildcard or arbitrary destination mapping.
	Tunnels map[string]string `yaml:"tunnels"`
}

// RelayConfig configures ntwire-server to dial out to an ntwire-relay
// (see PLAN-RELAY.md). By default, relay mode does not bind listen.https:
// the server serves its unchanged Handler() over dial-back data connections.
// DirectClients is the explicit opt-in for also serving that handler on
// listen.https.
type RelayConfig struct {
	Enabled      bool   `yaml:"enabled"`
	URL          string `yaml:"url"`
	Name         string `yaml:"name"`
	IdentityFile string `yaml:"identity_file"`
	Fingerprint  string `yaml:"fingerprint"`
	// DirectClients also binds listen.https while relay mode is active. It is
	// default-off so enabling relay never unexpectedly exposes a previously
	// unused local HTTPS listener. The certificate must cover the hostname
	// direct clients use.
	DirectClients bool `yaml:"direct_clients"`
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
	// Multipath overrides v3's bounded reactive-duplication budget.
	Multipath MultipathConfig `yaml:"multipath"`
}

// MultipathConfig is RelayConfig.Multipath's field set.
type MultipathConfig struct {
	DuplicateRateBytesPerSec int `yaml:"duplicate_rate_bytes_per_sec"`
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
	// DeprecatedClientSecret is retained only to give an actionable error for
	// unsafe legacy configuration. It must never be sent by the server.
	DeprecatedClientSecret string   `yaml:"client_secret"`
	Scopes                 []string `yaml:"scopes"`
	GroupsClaim            string   `yaml:"groups_claim"`
	RequireVerifiedEmail   *bool    `yaml:"require_verified_email"`
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
	Name        string `yaml:"name"`
	Target      string `yaml:"target"`
	Description string `yaml:"description"`
	VirtualPort int    `yaml:"virtual_port"`
	// Protocol selects the fixed-target transport. Empty retains TCP.
	Protocol       string        `yaml:"protocol"`
	UDPIdleTimeout time.Duration `yaml:"udp_idle_timeout"`
	LocalPort      int           `yaml:"local_port"`
	// LocalHost is an optional preferred loopback address for the client's
	// local listener for this tunnel (e.g. "127.70.0.1"), so distinct
	// tunnels can share a memorable port without colliding. Must be a
	// loopback address (127.0.0.0/8 or ::1): the client, not the server,
	// controls whether tunneled targets are reachable beyond localhost.
	// The client may override it and falls back to 127.0.0.1 if the
	// address cannot be bound (e.g. on macOS, without a lo0 alias).
	LocalHost         string   `yaml:"local_host"`
	Allow             []string `yaml:"allow"`
	DestinationPolicy string   `yaml:"destination_policy"`

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
	// Portal configures optional presentation metadata for this tunnel when
	// rendered in the ntwire Portal.
	Portal *portal.TargetPortalConfig `yaml:"portal"`
}

// NativeWireGuardConfig statically admits unmodified WireGuard clients into
// the existing userspace device. These are not HTTP sessions.
type NativeWireGuardConfig struct {
	Enabled bool                  `yaml:"enabled"`
	Peers   []NativeWireGuardPeer `yaml:"peers"`
}
type NativeWireGuardPeer struct {
	Name              string   `yaml:"name"`
	PublicKey         string   `yaml:"public_key"`
	TunnelIP          string   `yaml:"tunnel_ip"`
	Tunnels           []string `yaml:"tunnels"`
	DestinationPolicy string   `yaml:"destination_policy"`
}

// DNSConfig configures the in-tunnel DNS discovery server on UDP port 53.
type DNSConfig struct {
	Enabled *bool  `yaml:"enabled"`
	Domain  string `yaml:"domain"`
}

// IsEnabled reports whether the in-tunnel DNS server is enabled (defaults to true).
func (d DNSConfig) IsEnabled() bool {
	return d.Enabled == nil || *d.Enabled
}

// EffectiveDomain returns the normalized DNS top-level domain suffix (defaults to "ntwire").
func (d DNSConfig) EffectiveDomain() string {
	if d.Domain != "" {
		return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Domain)), ".")
	}
	return "ntwire"
}

// socksTarget is the TunnelConfig.Target sentinel that marks a tunnel as an
// embedded SOCKS proxy rather than a fixed host:port forward.
const socksTarget = "socks"

// IsSocks reports whether t is an embedded-SOCKS-server tunnel.
func (t TunnelConfig) IsSocks() bool {
	return t.Target == socksTarget
}

// IsBrowserSocks reports whether a local tunnel listener can proxy browser
// SOCKS5 traffic.
func (t TunnelConfig) IsBrowserSocks() bool {
	return t.IsSocks()
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
	// Transparent relays the client's SOCKS stream unchanged to Upstream.
	// It deliberately bypasses ntwire's destination filters; the upstream
	// SOCKS service is responsible for authorization and destination policy.
	Transparent    bool          `yaml:"transparent"`
	OnlyLocal      bool          `yaml:"only_local"`
	Filters        []string      `yaml:"filters"`
	DomainFilters  []string      `yaml:"domain_filters"`
	ASNFilters     []uint32      `yaml:"asn_filters"`
	ASNUpdates     *bool         `yaml:"asn_updates"`
	ASNURL         string        `yaml:"asn_url"`
	ReverseFilters bool          `yaml:"reverse_filters"`
	DNSTimeout     time.Duration `yaml:"dns_timeout"`
	AllowAll       bool          `yaml:"allow_all"`
	// AllowBind enables SOCKS4/5 BIND, which creates a temporary inbound
	// listener on the server host. It is independent of allow_all and false
	// by default.
	AllowBind bool `yaml:"allow_bind"`
	// Upstream optionally sends SOCKS CONNECT/BIND TCP traffic through an
	// existing socks5:// or socks5h:// proxy. UDP ASSOCIATE remains local.
	Upstream string `yaml:"upstream"`
	// UDPIdleTimeout bounds inactive SOCKS5 UDP ASSOCIATE flows.
	UDPIdleTimeout time.Duration `yaml:"udp_idle_timeout"`
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
  https    : ":8443"                     # TLS control API and WebSocket fallback listener; default: :8443
  wireguard: ":51820"                    # UDP listener for the userspace WireGuard data plane; default: :51820
  metrics  : ""                          # optional plaintext metrics/dashboard listener; exposes /metrics and, with admin.web_ui_token, /?token=... (for example, 127.0.0.1:9090)
  name     : ""                          # friendly label shown in the client's local status UI and logs, to tell apart several ntwire clients running locally; empty falls back to the host:port the client connected to

tls:
  cert_file: ""                          # PEM certificate; set together with key_file, or leave both empty for a generated self-signed certificate
  key_file : ""                          # PEM private key paired with cert_file; required whenever cert_file is set
  state_dir: ""                          # directory for a generated self-signed certificate and key; empty uses this YAML file's directory
  ephemeral: false                       # generate a new in-memory self-signed certificate on every start instead of persisting it in state_dir

auth:
  authorized_keys_dir : /etc/ntwire/keys  # directory of SSH public-key files; optional only when oidc.issuers is configured
  session_ttl         : 15m               # bearer-token lifetime before renewal is required; default: 15m
  max_sessions_per_key: 5                 # concurrent-session cap per SSH fingerprint or OIDC email; 0 means unlimited
  oidc:
    issuers:                                   # OIDC providers; leave empty to use SSH keys only
    # - name     : google                      # stable provider ID shown to clients and selected with --provider
    #   issuer   : https://accounts.google.com # issuer URL; its discovery document and JWKS are fetched
    #   client_id: 1234-abc.apps.googleusercontent.com # public OAuth client ID (PKCE; most IdPs need no client secret)
    # Do not add client_secret here. It is rejected to prevent disclosure via
    # unauthenticated server metadata; see docs/OIDC-SETUP.md for Google.
    #   scopes:                                # requested OAuth scopes; defaults to openid, email, profile when omitted
    #   - openid
    #   - email
    #   - profile
    #   groups_claim          : groups     # ID-token claim with group membership; empty disables group: grants
    #   require_verified_email: true       # reject tokens lacking email_verified=true; default: true

network:
  tunnel_cidr               : 100.64.0.0/16 # private IPv4 range or an IPv6 prefix (pick one; a deployment is single-family) used to allocate peer tunnel addresses; default shown; for IPv6 use /64 or no shorter than /112
  advertised_endpoint       : ""            # UDP host:port returned to clients when it differs from listen.wireguard, such as behind NAT; host may be a hostname (resolved fresh on every client connect/renew) or a literal IP; must be empty when relay.enabled is true
  wireguard_private_key_file: ""            # optional persistent server WireGuard private key; use for native official WireGuard clients
  # dns                       :
  #   enabled: true                         # run an in-tunnel DNS server on UDP port 53 for service discovery; default: true
  #   domain : ntwire                       # top-level domain suffix for tunnel resolution and discovery (e.g. <tunnel>.ntwire); default: ntwire

transport:
  # V3 keeps the healthy incumbent and changes carrier only on proven failure.
  multipath: true                         # negotiate WebSocket/UDP scheduling when both legs are available; default: true; set false for legacy single-path behavior
  force    : auto                         # optional server-side preference: auto, wss, udp-relay, or direct-udp; falls back automatically if unavailable

# Named reusable egress policies. A tunnel and a native peer can each name
# one; when both do, both must allow the selected destination.
destination_policies:
  # internal-only:
  #   filters       :                      # destination CIDR allow-list
  #   - 10.0.0.0/8
  #   - fc00::/7
  #   domain_filters:                      # destination hostname-suffix allow-list
  #   - .svc.cluster.local
  #   asn_filters   :                      # destination ASN allow-list (IPv4 only)
  #   - 64512
  #   only_local     : false               # restrict to private ranges only
  #   reverse_filters: false               # invert the destination filters into a deny-list
  #   allow_all      : false               # allow every destination when no other filter is configured
  #   protocols      :                     # allowed transports; empty allows TCP and UDP
  #   - tcp
  #   - udp
  #   ports          :                     # allowed destination ports; empty allows every port
  #   - 443

native_wireguard:
  enabled: false                          # accept unmodified official WireGuard clients
  peers  :                                # requires enabled: true
  # - name      : laptop
  #   public_key: BASE64_WIREGUARD_PUBLIC_KEY
  #   tunnel_ip : 100.64.0.10
  #   tunnels   :
  #   - reports
  #   destination_policy: internal-only   # optional named destination policy

# Opt-in MASQUE Network Relay gateway. Keep disabled unless all TLS and
# client-certificate settings below are configured; HTTP/3 is reserved for a
# future implementation and must remain empty today.
masque:
  enabled      : false
  listen       : ""                       # HTTPS listener for MASQUE CONNECT, e.g. :4433
  http2_url    : ""                       # public absolute https URL clients use for HTTP/2 CONNECT
  http3_url    : ""                       # reserved; must remain empty
  match_domains:                          # certificate names allowed for synthetic relay hosts
  # - private.example.test
  client_ca_file  : ""                    # PEM CA that verifies client certificates
  issuer_cert_file: ""                    # PEM certificate used to issue short-lived client certificates
  issuer_key_file : ""                    # PEM private key matching issuer_cert_file
  certificate_ttl : 15m                   # 1m through 24h; default 15m when enabled
  tunnels         :                       # synthetic FQDN to fixed ntwire tunnel-name mapping
  # reports.private.example.test: reports

relay:
  enabled      : false                        # when true, listen.https is never bound; the server dials out to an ntwire-relay instead (see PLAN-RELAY.md)
  url          : ""                           # wss://relay.example.com:8444, the relay's listen.agents endpoint
  name         : home                         # tenant label; must match this key's registration entry on the relay
  identity_file: /etc/ntwire/relay_id_ed25519 # private key used to sign relay registration, separate from auth.authorized_keys_dir; generate with: ntwire-server -generate-relay-key /etc/ntwire/relay_id_ed25519
  fingerprint  : ""                           # SHA256:... pin of the relay's listen.agents TLS certificate; empty verifies against normal PKI instead
  # For active-active relay HA, replace url/fingerprint above with endpoints.
  # Every endpoint must register the same tenant name and serve the same
  # wildcard client domain; clients race that shared DNS name on failure.
  # endpoints:
  # - url        : "wss://relay-a.example.com:8444"
  #   fingerprint: "SHA256:..."
  # - url        : "wss://relay-b.example.com:8444"
  #   fingerprint: "SHA256:..."
  reconnect_min  : 1s                      # initial backoff after a dropped control connection; default: 1s
  reconnect_max  : 1m                      # backoff ceiling; default: 1m
  advertise_direct: false                  # opt into self-reflecting off the relay's listen.reflect UDP endpoint and offering the result to clients over /v1/punch, so a client that can NAT hole-punch bypasses the relay's data plane entirely; requires the relay to have listen.reflect configured. See docs/RELAY.md. Leave false to keep this server's real address hidden, which is otherwise relay mode's whole point.
  direct_clients : false                   # also bind listen.https for direct ntwire clients; default false so relay mode does not expose an inbound listener unexpectedly. The TLS certificate must cover the direct hostname.
  # multipath      : overrides v3's bounded reactive-duplication budget.
  # multipath      :
  #   duplicate_rate_bytes_per_sec: 262144    # cap reactive duplication toward a healthy alternate while the incumbent degrades
  # When relay.enabled is true and advertise_direct is false, consider
  # setting listen.wireguard to "127.0.0.1:0": WireGuard rides the /v1/wg
  # WebSocket fallback in relay mode, so the UDP socket StartDataPlane still
  # opens is unused. Leave it reachable on the network if advertise_direct is
  # true -- that socket is exactly what self-reflection and the direct
  # upgrade use.

authorizer:
  webhook_url: ""                         # URL that receives a JSON POST for each connection and returns an allow/deny decision; takes precedence when both hook options are set
  exec       : ""                         # executable that receives the same JSON on stdin and returns an allow/deny decision when webhook_url is empty
  timeout    : 5s                         # deadline for the webhook or executable; errors and timeouts deny the request; default: 5s

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
  # - "group:engineering"              # OIDC membership in an issuer groups_claim
# - name        : egress                  # an embedded SOCKS4/5 proxy tunnel instead of a fixed target
#   target      : socks                   # required sentinel value that selects the SOCKS target type
#   virtual_port: 11080
#   allow       :
#   - group:engineering
#   socks       :
#     transparent   : false              # true copies the client SOCKS stream directly to upstream; upstream then owns DNS, filtering, and SOCKS auth
#     only_local    : false              # true restricts to private ranges only (10/8, 172.16/12, 192.168/16, fc00::/7) and ignores every other socks.* filter below
#     filters       :                    # destination CIDR allow-list
#     - 10.0.0.0/8
#     - fc00::/7
#     domain_filters:                    # destination hostname-suffix allow-list
#     - .svc.cluster.local
#   asn_filters :                       # destination ASN allow-list (IPv4 only)
#   - 15169
#   asn_updates : null                  # periodically refresh the ASN index; defaults to true when asn_filters is non-empty
#     asn_url         : ""                 # override the ASN index download URL; default: https://openaf.io/asnidx.json.gz
#     reverse_filters : false              # invert the above from an allow-list into a deny-list
#     dns_timeout     : 10s                # timeout for resolving SOCKS5 domain requests
#     allow_all       : false              # required to permit every destination when no filters above are set; otherwise an unfiltered SOCKS tunnel denies everything (unlike socksd, which defaults to allow-all)
#     allow_bind      : false              # explicitly allow SOCKS4/5 BIND; it opens a temporary inbound listener on the server host
#     upstream        : socks5h://proxy.example:1080 # optional upstream for governed TCP CONNECT/BIND; socks5h preserves the client hostname after ntwire authorization
#     udp_idle_timeout: 2m                # idle timeout for SOCKS5 UDP ASSOCIATE flows; 0 uses the default
#     # With transparent: true, upstream is required; do not set any other
#     # socks filtering, DNS, BIND, or UDP option. socks5:// and socks5h://
#     # both work and the client/upstream decide destination DNS behavior.
#   portal:                               # optional presentation metadata for this tunnel in the Portal
#     name        : Corporate egress
#     description : Browser proxy
#     category    : Network
#     icon        : globe
#     url         : ""                    # optional absolute http(s) launch URL
#     socks_tunnel: egress                # optional SOCKS tunnel to use when launching url
#     applications:                       # application IDs offered for this target
#     - chrome
#     - firefox

# Optional Portal landing page and separate web listener.
portal:
  enabled      : false
  title        : ntwire Portal
  template     : ""                             # inline template or a path relative to this YAML file
  variables    :                                # string substitutions exposed to the portal template
  # environment  : production
  web          :
    enabled: false
    listen : ""                           # required host:port when portal.web.enabled is true

log:
  format: text                             # text or json (Logstash-format, for fluent-bit/Logstash); container images default to json via NTWIRE_LOG_FORMAT
  level : info                             # debug, info, warn, or error
  # Precedence: -log-format/-log-level flags > this file > NTWIRE_LOG_FORMAT/NTWIRE_LOG_LEVEL env > built-in default (text, info). See docs/LOGGING.md.

audit:
  log_file: ""                             # optional path for a dedicated JSON-lines audit log (auth_allowed, session_disconnected, session_expired, session_revoked); in addition to, not instead of, the main log
`
}

// ConfigGuide renders the server configuration reference. It deliberately
// embeds SampleConfig verbatim so there is only one canonical YAML template.
func ConfigGuide() (string, error) { return serverGuide().Markdown() }

// ConfigJSONSchema renders the strict Draft 2020-12 schema used by tooling.
func ConfigJSONSchema() ([]byte, error) { return serverGuide().JSONSchema() }

// WriteConfigSkill creates a portable, low-context Agent Skill folder for
// generating and reviewing ntwire-server configuration.
func WriteConfigSkill(dir string) error { return serverGuide().WriteSkill(dir) }

func serverGuide() configguide.Guide {
	return configguide.Guide{
		Title:       "ntwire-server configuration guide",
		Description: "Complete reference for ntwire-server YAML configuration.",
		Sample:      SampleConfig(), Root: Config{},
		Skill: serverConfigSkill(),
		QA: []configguide.QA{
			{Question: "How should clients reach the server?", Answer: "Use direct listen.https, or relay.enabled with a registered relay tenant; relay.direct_clients explicitly enables both."},
			{Question: "How do users authenticate?", Answer: "Configure authorized_keys_dir, OIDC issuers, or native_wireguard.enabled. OIDC client_secret is deliberately rejected."},
			{Question: "Which TLS/listeners are needed?", Answer: "Set cert_file and key_file together, or allow generated TLS. listen.https and listen.wireguard have defaults."},
			{Question: "Which tunnel type is needed?", Answer: "Use a fixed host:port target, target: socks for the embedded filtered proxy, or target: external_socks with external_socks.url for an opaque upstream."},
			{Question: "How are destinations controlled?", Answer: "Use tunnel allow lists, destination_policies, and SOCKS filters; an unfiltered embedded SOCKS tunnel denies all unless allow_all is explicit."},
			{Question: "Need ordinary WireGuard clients?", Answer: "Enable native_wireguard and configure peers; it is independent from authenticated HTTP sessions."},
			{Question: "Need observability or Portal?", Answer: "Configure log/audit for records and portal for operator presentation metadata; do not put tokens or secrets in generated examples."},
			{Question: "Need Apple Network Relay/MASQUE?", Answer: "Enable masque only with its fixed tunnel mapping and certificate inputs; it is opt-in and separate from other transports."},
		},
		Rules: []string{
			"At least one of auth.authorized_keys_dir, auth.oidc.issuers, or native_wireguard.enabled must be configured.",
			"TLS cert_file and key_file must be set together; client_secret is a legacy key that always fails semantic validation.",
			"relay.url/fingerprint cannot be combined with relay.endpoints; relay.advertise_direct requires relay mode.",
			"target: socks and target: external_socks each require their corresponding configuration; external SOCKS URLs are credential-free socks5://host:port.",
		},
		SchemaOverrides: map[string]map[string]any{
			"listen.https": {"default": ":8443"}, "listen.wireguard": {"default": ":51820"},
			"auth.session_ttl": {"default": "15m"}, "authorizer.timeout": {"default": "5s"},
			"network.tunnel_cidr": {"default": "100.64.0.0/16"},
			"transport.force":     {"enum": []string{"auto", "wss", "udp-relay", "direct-udp"}, "default": "auto"},
			"log.format":          {"enum": []string{"text", "json"}, "default": "text"},
			"log.level":           {"enum": []string{"debug", "info", "warn", "error"}, "default": "info"},
			"tunnels":             {"minItems": 0},
		},
	}
}

func serverConfigSkill() configguide.Skill {
	return configguide.Skill{
		Name:        "ntwire-server-config",
		Description: "Generate or review safe ntwire-server YAML from a user's deployment requirements, including Portal, tunnels, authentication, relay, native WireGuard, and MASQUE.",
		Binary:      "ntwire-server",
		Workflow: []string{
			"Read references/core.md, then match the requested capability to one additional reference below. Do not preload unrelated references.",
			"Ask only for missing values required by the selected feature. If an existing YAML file is supplied, preserve unrelated fields and report assumptions separately.",
			"Return the proposed YAML or a minimal patch, the unresolved choices, and any file or firewall work that remains. Never put private keys, bearer tokens, OIDC client secrets, or a real public-key value in generated YAML.",
			"Validate the resulting file with ntwire-server -check-config -config <path>. For a Portal template, also run ntwire-server portal validate -config <path> before deployment.",
		},
		References: []configguide.SkillReference{
			{Path: "references/core.md", When: "direct or relay server, TLS, authentication, network, logging, or audit", Content: `# Core server configuration

Ask whether clients reach this server directly or through an ntwire-relay, the public hostname and TLS source, the authentication method, the tunnel address range, and the services to publish. Do not ask for a value the user already supplied.

At least one of auth.authorized_keys_dir, auth.oidc.issuers, or native_wireguard.enabled must be configured. OIDC uses a public client ID and PKCE; client_secret is rejected. Set tls.cert_file and tls.key_file together, or leave both empty only when generated TLS is acceptable.

~~~yaml
listen:
  https: ":8443"
  wireguard: ":51820"
tls:
  cert_file: "/etc/ntwire/tls.crt"
  key_file: "/etc/ntwire/tls.key"
auth:
  authorized_keys_dir: "/etc/ntwire/keys"
network:
  tunnel_cidr: "100.64.0.0/16"
transport:
  multipath: true
  force: auto
~~~

Use generated TLS only for a deliberate development or trust-on-first-use deployment. Keep log and audit paths writable by the service account. Read references/relay.md only for a server that dials an ntwire-relay.`},
			{Path: "references/tunnels.md", When: "published services, TCP or UDP tunnels, SOCKS, egress policy, or per-user access", Content: `# Tunnels and access

For every requested service, ask for a stable name, target host:port, virtual_port, optional preferred client local_port, and exactly who may access it. A tunnel allow list is the access-control boundary; Portal metadata never grants access.

Use a normal target for one fixed service. Use target: socks only for ntwire's embedded, policy-controlled SOCKS proxy; an unfiltered embedded SOCKS tunnel denies all destinations unless socks.allow_all is explicitly true. Use target: external_socks only for a credential-free socks5://host:port upstream; it is opaque and has no local SOCKS filtering, UDP, BIND, or PAC service.

~~~yaml
tunnels:
  - name: grafana
    target: "grafana.internal:3000"
    virtual_port: 3000
    local_port: 3000
    allow: ["group:engineering"]
~~~

For UDP, protocol, destination policy, browser, or instruction fields not covered here, use the complete reference or schema on demand.`},
			{Path: "references/portal.md", When: "an ntwire Portal, user service catalog, browser launch, or in-tunnel web portal", Content: `# Portal

Treat a request for a Portal as a request for a user-facing, authorization-aware catalog of existing tunnels. Ask whether the user needs the native ntwire client Portal, an in-tunnel WireGuard web portal, or both; ask for the title, optional template and variables, and the metadata for every service to present.

For the native client Portal, set portal.enabled: true. For the web Portal, also set portal.web.enabled: true and portal.web.listen to a server WireGuard-overlay host:port such as 100.64.0.1:8080. It is not a public HTTP listener. portal.web.enabled without portal.web.listen is invalid.

~~~yaml
portal:
  enabled: true
  title: "Engineering Portal"
  template: "portal.md"
  variables:
    environment: "Production"
  web:
    enabled: true
    listen: "100.64.0.1:8080"

tunnels:
  - name: grafana
    target: "grafana.internal:3000"
    virtual_port: 3000
    local_port: 3000
    allow: ["group:engineering"]
    portal:
      name: "Grafana Dashboards"
      description: "Metrics and observability dashboards"
      category: "Observability"
      icon: "chart"
      url: "https://grafana.internal"
      applications: ["grafana"]
~~~

Each displayed service still needs a real tunnel and its allow list. portal.url must be absolute http(s). Use socks_tunnel only when the browser should use a named authorized embedded SOCKS tunnel. Keep template content declarative; ask the binary for a safe authoring prompt with ntwire-server portal prompt -config <path>, then validate it with ntwire-server portal validate -config <path>.`},
			{Path: "references/relay.md", When: "server behind NAT, relay tenant, relay pool, or direct-UDP privacy choice", Content: `# Server connection to an ntwire-relay

Use relay mode when the server dials out from behind NAT and clients arrive through a relay registration. Ask for the relay URL or shared relay endpoints, tenant name, relay identity-file path, certificate pin policy, and whether direct client access or address disclosure is explicitly desired.

~~~yaml
relay:
  enabled: true
  url: "wss://relay.example.com:8444"
  name: "home"
  identity_file: "/etc/ntwire/relay_id_ed25519"
  fingerprint: ""
  advertise_direct: false
  direct_clients: false
~~~

The tenant name and identity key must match a registration on the relay. In relay mode, network.advertised_endpoint must be empty. Keep advertise_direct false unless the operator explicitly accepts exposing the server's direct address; it also needs the relay reflector. Use relay.direct_clients only when an additional direct HTTPS listener is intended.`},
			{Path: "references/native-wireguard.md", When: "ordinary WireGuard clients or an in-tunnel Portal for those clients", Content: `# Native WireGuard

Native WireGuard peers are static server-side peers, separate from authenticated HTTP sessions. Ask for every peer's public key, unique overlay address, allowed tunnel names, and any destination policy. Keep the server WireGuard private key in network.wireguard_private_key_file, not in the YAML itself.

~~~yaml
network:
  wireguard_private_key_file: "/etc/ntwire/server_wg.key"
native_wireguard:
  enabled: true
  peers:
    - name: "alice-phone"
      public_key: "<operator-provided-public-key>"
      tunnel_ip: "100.64.0.10"
      tunnels: ["grafana"]
~~~

When a web Portal is enabled, its listener must use the same overlay and the peer still receives only the tunnels named above. Generate a client profile only after the server configuration validates.`},
			{Path: "references/masque.md", When: "Apple Network Relay, MASQUE, or connect-udp gateway", Content: `# MASQUE gateway

MASQUE is opt-in and separate from ntwire's ordinary WireGuard and WebSocket data planes. Ask for the fixed public HTTP/2 or HTTP/3 endpoint, client CA, issuer certificate and key file paths, certificate lifetime, match domains, and an explicit FQDN-to-existing-tunnel map. Do not create wildcard or arbitrary destination mappings.

~~~yaml
masque:
  enabled: true
  listen: ":443"
  http2_url: "https://relay.example.com"
  match_domains: ["internal.example.com"]
  client_ca_file: "/etc/ntwire/masque-client-ca.pem"
  issuer_cert_file: "/etc/ntwire/masque-issuer.pem"
  issuer_key_file: "/etc/ntwire/masque-issuer.key"
  tunnels:
    "reports.internal.example.com": "reports"
~~~

Use the complete reference for certificate lifetime and HTTP/3 fields. Keep all private material in files with restricted permissions.`},
		},
	}
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

func loadPortalTemplateFile(p *portal.PortalConfig, baseDir string) {
	if p.Template == "" || strings.Contains(p.Template, "\n") {
		return
	}
	path := p.Template
	fi, err := os.Stat(path)
	if err != nil && baseDir != "" {
		alt := filepath.Join(baseDir, path)
		if fi2, err2 := os.Stat(alt); err2 == nil {
			path = alt
			fi = fi2
			err = nil
		}
	}
	if err != nil || fi.IsDir() || fi.Size() > maxInstructionsFileSize {
		return
	}
	if b, err := os.ReadFile(path); err == nil {
		p.Template = string(b)
	}
}

func LoadConfig(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	return ParseConfig(b, filepath.Dir(path))
}

// ParseConfig unmarshals and validates server configuration YAML from b.
func ParseConfig(b []byte, stateDir string) (Config, error) {
	var c Config
	var e error
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if e = decoder.Decode(&c); e != nil {
		return c, e
	}
	if c.TLS.StateDir == "" {
		c.TLS.StateDir = stateDir
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
	if c.Auth.AuthorizedKeysDir == "" && len(c.Auth.OIDC.Issuers) == 0 && !c.NativeWireGuard.Enabled {
		return c, fmt.Errorf("at least one of auth.authorized_keys_dir, auth.oidc.issuers, or native_wireguard.enabled is required")
	}
	seenIssuers := map[string]bool{}
	for i := range c.Auth.OIDC.Issuers {
		iss := &c.Auth.OIDC.Issuers[i]
		if iss.Name == "" || iss.Issuer == "" || iss.ClientID == "" {
			return c, fmt.Errorf("auth.oidc.issuers require name, issuer, and client_id")
		}
		if iss.DeprecatedClientSecret != "" {
			return c, fmt.Errorf("auth.oidc.issuers[%q].client_secret is no longer supported: rotate the exposed secret, remove it from server configuration, and configure it only on each client if your IdP requires one", iss.Name)
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
	if c.Network.DNS.Domain != "" {
		dom := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Network.DNS.Domain)), ".")
		if dom == "" || strings.ContainsAny(dom, "/: @") {
			return c, fmt.Errorf("network.dns.domain %q is not a valid DNS domain", c.Network.DNS.Domain)
		}
	}
	force, err := wstransport.ValidateTransportName(c.Transport.Force)
	if err != nil {
		return c, fmt.Errorf("transport.force: %w", err)
	}
	if force != "" && !c.MultipathEnabled() {
		return c, fmt.Errorf("transport.force requires transport.multipath")
	}
	c.Transport.Force = force
	prefix, _ := netip.ParsePrefix(c.Network.TunnelCIDR)
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
	} else if c.Relay.DirectClients {
		return c, fmt.Errorf("relay.direct_clients requires relay.enabled: direct clients are already served by listen.https without relay mode")
	}
	if c.Relay.ReconnectMin == 0 {
		c.Relay.ReconnectMin = time.Second
	}
	if c.Relay.ReconnectMax == 0 {
		c.Relay.ReconnectMax = time.Minute
	}
	if c.MASQUE.Enabled {
		if c.MASQUE.Listen == "" || c.MASQUE.HTTP2URL == "" {
			return c, fmt.Errorf("masque.enabled requires masque.listen and masque.http2_url")
		}
		for _, raw := range []string{c.MASQUE.HTTP2URL, c.MASQUE.HTTP3URL} {
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return c, fmt.Errorf("masque relay URLs must be absolute https URLs without credentials, query, or fragment")
			}
		}
		if c.MASQUE.HTTP3URL != "" {
			return c, fmt.Errorf("masque.http3_url is not supported yet: the initial gateway serves HTTP/2 CONNECT only")
		}
		if len(c.MASQUE.MatchDomains) == 0 {
			return c, fmt.Errorf("masque.enabled requires masque.match_domains")
		}
		for _, domain := range c.MASQUE.MatchDomains {
			domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
			if domain == "" || strings.ContainsAny(domain, "/:@") || net.ParseIP(domain) != nil {
				return c, fmt.Errorf("invalid masque.match_domains entry %q", domain)
			}
		}
		if c.MASQUE.ClientCAFile == "" || c.MASQUE.IssuerCertFile == "" || c.MASQUE.IssuerKeyFile == "" {
			return c, fmt.Errorf("masque.enabled requires client_ca_file, issuer_cert_file, and issuer_key_file")
		}
		if c.MASQUE.CertificateTTL == 0 {
			c.MASQUE.CertificateTTL = 15 * time.Minute
		}
		if c.MASQUE.CertificateTTL < time.Minute || c.MASQUE.CertificateTTL > 24*time.Hour {
			return c, fmt.Errorf("masque.certificate_ttl must be between 1m and 24h")
		}
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
		if t.LocalHost != "" {
			ip, e := netip.ParseAddr(t.LocalHost)
			if e != nil || !ip.IsLoopback() {
				return c, fmt.Errorf("tunnel %q: local_host must be a loopback IP address (127.0.0.0/8 or ::1)", t.Name)
			}
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
			if t.Socks.UDPIdleTimeout < 0 {
				return c, fmt.Errorf("tunnel %q: socks.udp_idle_timeout must not be negative", t.Name)
			}
			if t.Socks.Upstream != "" {
				u, e := url.Parse(t.Socks.Upstream)
				if e != nil || (u.Scheme != "socks5" && u.Scheme != "socks5h") || u.Host == "" {
					return c, fmt.Errorf("tunnel %q: socks.upstream must be a socks5:// or socks5h:// URL", t.Name)
				}
			}
			if t.Socks.Transparent {
				if t.Socks.Upstream == "" {
					return c, fmt.Errorf("tunnel %q: socks.transparent requires socks.upstream", t.Name)
				}
				if t.Socks.OnlyLocal || len(t.Socks.Filters) > 0 || len(t.Socks.DomainFilters) > 0 || len(t.Socks.ASNFilters) > 0 || t.Socks.ASNUpdates != nil || t.Socks.ASNURL != "" || t.Socks.ReverseFilters || t.Socks.AllowAll || t.Socks.AllowBind || t.Socks.DNSTimeout != 0 || t.Socks.UDPIdleTimeout != 0 {
					return c, fmt.Errorf("tunnel %q: socks.transparent cannot be combined with ntwire SOCKS filtering, DNS, BIND, or UDP options", t.Name)
				}
			}
		} else if t.Socks != nil {
			return c, fmt.Errorf("tunnel %q: socks: block requires target: socks", t.Name)
		} else {
			if t.Protocol == "" {
				t.Protocol = "tcp"
			}
			if t.Protocol != "tcp" && t.Protocol != "udp" {
				return c, fmt.Errorf("tunnel %q: protocol must be tcp or udp", t.Name)
			}
			host, port, e := net.SplitHostPort(t.Target)
			if e != nil || host == "" || port == "" {
				return c, fmt.Errorf("tunnel %q: target must be host:port: %w", t.Name, e)
			}
			if _, e := net.LookupPort(t.Protocol, port); e != nil {
				return c, fmt.Errorf("tunnel %q: target port: %w", t.Name, e)
			}
			if t.Protocol == "udp" && t.UDPIdleTimeout < 0 {
				return c, fmt.Errorf("tunnel %q: udp_idle_timeout must not be negative", t.Name)
			}
		}
		if t.Portal != nil {
			if t.Portal.URL != "" && !instructions.SafeURL(t.Portal.URL) {
				return c, fmt.Errorf("tunnel %q: portal.url must be an absolute http(s) URL", t.Name)
			}
		}
	}
	loadPortalTemplateFile(&c.Portal, stateDir)
	if c.Portal.Enabled {
		if c.Portal.Template != "" {
			errs := portal.ValidateTemplate(c.Portal.Template, nil)
			for _, err := range errs {
				if err.Fatal {
					return c, fmt.Errorf("portal.template: %w", err)
				}
			}
		}
		if c.Portal.Web.Enabled {
			if c.Portal.Web.Listen == "" {
				return c, fmt.Errorf("portal.web.enabled requires portal.web.listen")
			}
			if _, _, err := net.SplitHostPort(c.Portal.Web.Listen); err != nil {
				return c, fmt.Errorf("portal.web.listen: %w", err)
			}
		}
	}
	for name, policy := range c.DestinationPolicies {
		if strings.TrimSpace(name) == "" {
			return c, fmt.Errorf("destination_policies: empty policy name")
		}
		if _, err := compilePolicy(policy, nil); err != nil {
			return c, fmt.Errorf("destination_policies.%s: %w", name, err)
		}
	}
	seenPeerNames, seenPeerKeys, seenPeerIPs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	if !c.NativeWireGuard.Enabled && len(c.NativeWireGuard.Peers) > 0 {
		return c, fmt.Errorf("native_wireguard.peers requires native_wireguard.enabled: true")
	}
	serverIP := prefix.Addr().Next()
	for i, peer := range c.NativeWireGuard.Peers {
		where := fmt.Sprintf("native_wireguard.peers[%d]", i)
		if peer.Name == "" || peer.PublicKey == "" || peer.TunnelIP == "" {
			return c, fmt.Errorf("%s requires name, public_key, and tunnel_ip", where)
		}
		if seenPeerNames[peer.Name] {
			return c, fmt.Errorf("duplicate native WireGuard peer name %q", peer.Name)
		}
		seenPeerNames[peer.Name] = true
		if seenPeerKeys[peer.PublicKey] {
			return c, fmt.Errorf("duplicate native WireGuard public key")
		}
		seenPeerKeys[peer.PublicKey] = true
		if err := wgnet.ValidatePublicKey(peer.PublicKey); err != nil {
			return c, fmt.Errorf("%s.public_key: %w", where, err)
		}
		ip, err := netip.ParseAddr(peer.TunnelIP)
		if err != nil || !prefix.Contains(ip) {
			return c, fmt.Errorf("%s.tunnel_ip must belong to network.tunnel_cidr", where)
		}
		if ip == serverIP {
			return c, fmt.Errorf("%s.tunnel_ip collides with server tunnel address", where)
		}
		if seenPeerIPs[ip.String()] {
			return c, fmt.Errorf("duplicate native WireGuard tunnel IP %q", ip)
		}
		seenPeerIPs[ip.String()] = true
		if peer.DestinationPolicy != "" {
			if _, ok := c.DestinationPolicies[peer.DestinationPolicy]; !ok {
				return c, fmt.Errorf("%s.destination_policy references unknown policy %q", where, peer.DestinationPolicy)
			}
		}
		for _, tunnel := range peer.Tunnels {
			if !seen[tunnel] {
				return c, fmt.Errorf("%s.tunnels references unknown tunnel %q", where, tunnel)
			}
		}
	}
	for _, t := range c.Tunnels {
		if t.DestinationPolicy != "" {
			if _, ok := c.DestinationPolicies[t.DestinationPolicy]; !ok {
				return c, fmt.Errorf("tunnel %q references unknown destination policy %q", t.Name, t.DestinationPolicy)
			}
		}
	}
	if c.MASQUE.Enabled {
		if len(c.MASQUE.Tunnels) == 0 {
			return c, fmt.Errorf("masque.enabled requires masque.tunnels")
		}
		known := map[string]TunnelConfig{}
		for _, tunnel := range c.Tunnels {
			known[tunnel.Name] = tunnel
		}
		for domain, tunnelName := range c.MASQUE.Tunnels {
			normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
			if normalized != domain || normalized == "" || !containsDomain(c.MASQUE.MatchDomains, normalized) {
				return c, fmt.Errorf("masque.tunnels domain %q is not in masque.match_domains", domain)
			}
			tunnel, ok := known[tunnelName]
			if !ok || tunnel.IsSocks() {
				return c, fmt.Errorf("masque.tunnels domain %q requires a configured non-SOCKS tunnel", domain)
			}
		}
	}
	return c, nil
}

func containsDomain(domains []string, want string) bool {
	for _, domain := range domains {
		if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".") == want {
			return true
		}
	}
	return false
}
