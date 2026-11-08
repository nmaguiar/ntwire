// Package config manages ntwire-gui's own profile store, ~/.ntwire/gui.yaml.
// It is a superset of client.Settings (the CLI's single-server config) since
// the GUI holds several server profiles at once and exposes a few options
// client.Settings has no field for (websocket, known_servers_file,
// token_cache_file). This package never writes ~/.ntwire/config.yaml -- that
// file is owned by cmd/ntwire, which auto-persists it on every successful
// `ntwire connect`, and a second writer would fight it.
package config

import (
	"encoding/json"

	"github.com/nmaguiar/ntwire/pkg/client"
)

// Profile is one saved server connection. It holds everything
// ToClientOptions needs to build a client.Options, plus GUI-only metadata
// (ID, Name, ConnectOnStart).
type Profile struct {
	ID             string         `yaml:"id"`
	Name           string         `yaml:"name"`
	Server         string         `yaml:"server"`
	IdentityFile   string         `yaml:"identity_file"`
	ConnectOnStart bool           `yaml:"connect_on_start"`
	Ports          map[string]int `yaml:"ports"`
	// Hosts is a per-tunnel loopback address override; see
	// client.Options.Hosts.
	Hosts            map[string]string `yaml:"hosts"`
	CAFile           string            `yaml:"ca_file"`
	Insecure         bool              `yaml:"insecure"`
	HTTPSProxy       string            `yaml:"https_proxy,omitempty"`
	NoSystemProxy    bool              `yaml:"no_system_proxy,omitempty"`
	KnownServersFile string            `yaml:"known_servers_file"`
	TokenCacheFile   string            `yaml:"token_cache_file"`
	// Websocket forces the WebSocket WireGuard transport. Leave false for
	// almost every profile: relay servers are auto-detected and use it
	// without this being set (see client.selectTransport).
	Websocket bool   `yaml:"websocket"`
	SSO       bool   `yaml:"sso"`
	Provider  string `yaml:"provider"`
	// OIDCClientSecret is profile-local client authentication material for an
	// issuer that requires it. It is persisted only in gui.yaml (mode 0600)
	// and deliberately excluded from JSON so the settings API can never return
	// it to the UI after it has been saved.
	OIDCClientSecret string `yaml:"oidc_client_secret,omitempty" json:"-"`
	CollectExec      string `yaml:"collect_exec"`
	// BindAddress is the advanced, opt-in override for the loopback-only
	// default tunnel listeners bind to; see client.Options.BindAddress.
	BindAddress string `yaml:"bind_address"`
	// IPVersion is "", "4", or "6"; see client.Options.IPVersion.
	IPVersion string `yaml:"ip_version"`
	// Transport is "auto", "direct-udp", "udp-relay", or "wss"; see client.Options.Transport.
	Transport string `yaml:"transport"`
	// UDPAlt is the opt-in --udp-alt setting; see client.Options.UDPAlt.
	UDPAlt bool `yaml:"udp_alt,omitempty"`
	// MTUAware is the opt-in --mtu-aware setting; see client.Options.MTUAware.
	MTUAware bool `yaml:"mtu_aware,omitempty"`
	// TunnelMTU is the opt-in --tunnel-mtu setting; see client.Options.TunnelMTU.
	TunnelMTU string `yaml:"tunnel_mtu,omitempty"`
}

// Settings holds ntwire-gui's own app-wide preferences, as opposed to any
// one server profile's connection settings.
type Settings struct {
	UpdateChecksDisabled bool `yaml:"update_checks_disabled"`
	AutomaticUpdates     bool `yaml:"automatic_updates"`
	StartAtLogin         bool `yaml:"start_at_login"`
	Notifications        bool `yaml:"notifications"`
	ImportedCLIConfig    bool `yaml:"imported_cli_config"`
}

// Config is the full contents of ~/.ntwire/gui.yaml.
type Config struct {
	Version  int       `yaml:"version"`
	Settings Settings  `yaml:"settings"`
	Profiles []Profile `yaml:"profiles"`
}

// CurrentVersion is the Config.Version this package reads and writes.
const CurrentVersion = 1

// MarshalJSON keeps proxy credentials out of profiles, snapshots and SSE events.
func (p Profile) MarshalJSON() ([]byte, error) {
	type plain Profile
	safe := plain(p)
	safe.HTTPSProxy = client.RedactProxyURL(p.HTTPSProxy)
	return json.Marshal(safe)
}
