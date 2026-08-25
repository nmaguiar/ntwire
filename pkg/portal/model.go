// Package portal implements the ntwire Portal capability: safe declarative
// template evaluation, authorization-isolated context rendering, markdown
// sanitization, WireGuard web portal, and client portal actions.
package portal

// SchemaVersion identifies the portal data model and descriptor format.
const SchemaVersion = "ntwire.portal/v1"

// PortalConfig configures the ntwire Portal at the server level.
type PortalConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Title     string            `yaml:"title" json:"title"`
	Template  string            `yaml:"template" json:"template"`
	Variables map[string]string `yaml:"variables" json:"variables"`
	Web       PortalWebConfig   `yaml:"web" json:"web"`
}

// PortalWebConfig configures the optional server-side HTTP portal reachable over WireGuard.
type PortalWebConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Listen  string `yaml:"listen" json:"listen"`
}

// TargetPortalConfig defines presentation and application metadata for a tunnel/target.
type TargetPortalConfig struct {
	Name         string   `yaml:"name" json:"name"`
	Description  string   `yaml:"description" json:"description"`
	Category     string   `yaml:"category" json:"category"`
	Icon         string   `yaml:"icon" json:"icon"`
	URL          string   `yaml:"url" json:"url"`
	SocksTunnel  string   `yaml:"socks_tunnel" json:"socks_tunnel"`
	Applications []string `yaml:"applications" json:"applications"`
}

// PortalContext is the strongly typed rendering model passed to portal templates.
type PortalContext struct {
	Schema       string             `json:"schema"`
	Portal       PortalInfo         `json:"portal"`
	User         PortalUser         `json:"user"`
	Client       PortalClient       `json:"client"`
	Capabilities PortalCapabilities `json:"capabilities"`
	Targets      []PortalTarget     `json:"targets"`
	Categories   []PortalCategory   `json:"categories"`
	Variables    map[string]string  `json:"variables"`
}

// PortalInfo describes the portal itself.
type PortalInfo struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Version     int    `json:"version"`
}

// PortalUser describes the authenticated principal accessing the portal.
type PortalUser struct {
	Identity    string   `json:"identity"`
	DisplayName string   `json:"display_name"`
	Method      string   `json:"method"` // "ssh", "oidc", or "native-wireguard"
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups,omitempty"`
}

// PortalClient describes the client environment when known.
type PortalClient struct {
	OS            string `json:"os,omitempty"`
	Arch          string `json:"arch,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

// PortalCapabilities flags runtime features available in the current portal viewing mode.
type PortalCapabilities struct {
	NativeClient     bool `json:"native_client"`
	WebPortal        bool `json:"web_portal"`
	OpenSocksBrowser bool `json:"open_socks_browser"`
	Copy             bool `json:"copy"`
	LocalForward     bool `json:"local_forward"`
	SSHLauncher      bool `json:"ssh_launcher"`
}

// PortalTarget describes one authorized target available to the user.
type PortalTarget struct {
	ID                     string               `json:"id"`
	Name                   string               `json:"name"`
	Description            string               `json:"description"`
	Category               string               `json:"category"`
	Icon                   string               `json:"icon"`
	URL                    string               `json:"url,omitempty"`
	Target                 string               `json:"target"`
	TargetHint             string               `json:"target_hint,omitempty"`
	Host                   string               `json:"host,omitempty"`
	Port                   int                  `json:"port,omitempty"`
	Protocol               string               `json:"protocol,omitempty"`
	VirtualPort            int                  `json:"virtual_port"`
	LocalPort              int                  `json:"local_port,omitempty"`
	LocalHost              string               `json:"local_host,omitempty"`
	LocalAddress           string               `json:"local_address,omitempty"`
	DocsURL                string               `json:"docs_url,omitempty"`
	Instructions           string               `json:"instructions,omitempty"`
	ConnectionInstructions string               `json:"connection_instructions,omitempty"`
	IsSocks                bool                 `json:"is_socks"`
	SocksTunnel            string               `json:"socks_tunnel,omitempty"`
	Applications           []string             `json:"applications,omitempty"`
	Connection             PortalConnectionInfo `json:"connection"`
}

// PortalConnectionInfo contains semantic connection parameters safely escaped for user instructions.
type PortalConnectionInfo struct {
	Socks   *SocksConnectionInfo   `json:"socks,omitempty"`
	SSH     *SSHConnectionInfo     `json:"ssh,omitempty"`
	DBeaver *DBeaverConnectionInfo `json:"dbeaver,omitempty"`
	HTTP    *HTTPConnectionInfo    `json:"http,omitempty"`
}

// SocksConnectionInfo describes a SOCKS proxy endpoint.
type SocksConnectionInfo struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// SSHConnectionInfo describes safe SSH connection instructions.
type SSHConnectionInfo struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Command string `json:"command"`
}

// DBeaverConnectionInfo describes DBeaver database client connection parameters.
type DBeaverConnectionInfo struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	SocksHost string `json:"socks_host,omitempty"`
	SocksPort int    `json:"socks_port,omitempty"`
}

// HTTPConnectionInfo describes an HTTP web target.
type HTTPConnectionInfo struct {
	URL string `json:"url"`
}

// PortalCategory groups targets into presentation sections. Empty categories are omitted during rendering.
type PortalCategory struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Targets     []PortalTarget `json:"targets"`
}

// RenderedPortal contains the output of portal template and markdown processing.
type RenderedPortal struct {
	Title    string         `json:"title"`
	Markdown string         `json:"markdown"`
	HTML     string         `json:"html"`
	Context  *PortalContext `json:"context,omitempty"`
}
