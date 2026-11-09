// Package clientopts is the single declaration of every option the ntwire
// client accepts. cmd/ntwire builds its flag.FlagSets from this registry and
// ntwire-gui generates its settings form from the same registry, so the two
// can never drift apart.
package clientopts

import "github.com/nmaguiar/ntwire/pkg/client"

// Kind is the flag.FlagSet primitive an Option is defined with.
type Kind int

const (
	KindString     Kind = iota // fs.String
	KindBool                   // fs.Bool
	KindStringList             // fs.Var -- repeatable literal string
	KindKeyValue               // fs.Var(&MultiValue{}) -- repeatable name=value
)

// Widget is a hint for how a GUI should render this option. It has no
// meaning to cmd/ntwire.
type Widget string

const (
	WidgetStringList Widget = "stringlist"
	WidgetText       Widget = "text"
	WidgetPath       Widget = "path"
	WidgetToggle     Widget = "toggle"
	WidgetPortMap    Widget = "portmap"
)

// Defaults is everything a flag's default value can depend on, mirroring
// today's config-underneath-flags layering (e.g. fs.String("i",
// settings.IdentityFile, ...)). ConfigPath is separate from Settings because
// --config's own default is the path scavenged from raw argv before any
// FlagSet exists (see cmd/ntwire's settingsFor), not a field of Settings.
type Defaults struct {
	Settings              client.Settings
	ConfigPath            string
	GeneratedIdentityFile string
}

// Binding overrides Option.Usage for one specific command. Three flags in
// the current CLI word themselves differently per subcommand
// (--no-browser, --token-cache), so a registry that flattened them to one
// usage string would be a regression.
type Binding struct {
	Command string
	Usage   string // overrides Option.Usage for this command when non-empty
}

// Option is one command-line flag, declared once and shared by every
// subcommand that exposes it.
type Option struct {
	Name  string // exactly as flag.FlagSet sees it: "i", "no-color", "port"
	Kind  Kind
	Usage string // default usage string, used unless a Binding overrides it
	Bind  []Binding

	// Default returns the flag's default value as a string ("" or "false"
	// for the zero value). nil means always the Kind's zero value.
	Default func(d Defaults) string

	// Discarded marks flags whose parsed value is never read by cmd/ntwire:
	// --config and --no-color exist only so flag.Parse accepts them and -h
	// documents them. Their real values are scavenged from raw argv by
	// noColorFrom/settingsFor before any FlagSet is built.
	Discarded bool

	// --- GUI-only metadata; ignored by cmd/ntwire ---
	Label     string
	Help      string
	Group     string
	Widget    Widget
	Advanced  bool
	GUIHidden bool
}

// usageFor returns o.Usage, or a Binding's override for command when present.
func (o Option) usageFor(command string) string {
	for _, b := range o.Bind {
		if b.Command == command && b.Usage != "" {
			return b.Usage
		}
	}
	return o.Usage
}

// definedOn reports whether o is exposed on command.
func (o Option) definedOn(command string) bool {
	for _, b := range o.Bind {
		if b.Command == command {
			return true
		}
	}
	return false
}

func strDefault(f func(client.Settings) string) func(Defaults) string {
	return func(d Defaults) string { return f(d.Settings) }
}

func boolDefault(f func(client.Settings) bool) func(Defaults) string {
	return func(d Defaults) string {
		if f(d.Settings) {
			return "true"
		}
		return "false"
	}
}

// registry is the complete, exact set of options across every ntwire
// subcommand. Order is not significant: flag.FlagSet.VisitAll (used by
// ui.FlagsOf) sorts lexicographically regardless of registration order.
var registry = []Option{
	{Name: "browser-arg", Kind: KindStringList, Usage: "literal extra browser switch (repeatable; replaces configured extras)", Bind: []Binding{{Command: "connect"}, {Command: "browser"}}, Label: "Extra browser arguments", Group: "🌐 Connection", Widget: WidgetStringList, Advanced: true, Help: "One literal --flag or --flag=value per row. Close the isolated browser before relaunching to apply changes reliably."},
	{Name: "no-browser-args", Kind: KindBool, Usage: "clear configured extra browser arguments", Bind: []Binding{{Command: "connect"}, {Command: "browser"}}, GUIHidden: true},
	{
		Name: "v", Kind: KindBool, Usage: "show connection diagnostics",
		Bind:  []Binding{{Command: "connect"}, {Command: "list"}, {Command: "transport", Usage: "show per-path MTU and the transport switch history"}},
		Group: "🛠️ Advanced", GUIHidden: true,
	},
	{
		Name: "config", Kind: KindString, Usage: "persistent client configuration",
		Bind:      []Binding{{Command: "connect"}, {Command: "list"}, {Command: "logout"}},
		Default:   func(d Defaults) string { return d.ConfigPath },
		Discarded: true, GUIHidden: true,
	},
	{
		Name: "i", Kind: KindString, Usage: "SSH private key",
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: strDefault(func(s client.Settings) string { return s.IdentityFile }),
		Label:   "SSH private key", Group: "🪪 Identity", Widget: WidgetPath,
	},
	{
		Name: "browser-executable", Kind: KindString, Usage: "Chromium-compatible browser executable (empty: automatic detection)",
		Bind:    []Binding{{Command: "connect"}, {Command: "browser"}},
		Default: strDefault(func(s client.Settings) string { return s.BrowserExecutable }),
		Label:   "Chromium-compatible browser executable", Group: "🌐 Connection", Widget: WidgetPath, Advanced: true,
		Help: "Leave empty to detect automatically. Select Chrome, Edge, Chromium, or Brave. Applies to SOCKS browser launches.",
	},

	{
		Name: "ca", Kind: KindString, Usage: "PEM CA certificate",
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: strDefault(func(s client.Settings) string { return s.CAFile }),
		Label:   "CA certificate", Group: "🔒 TLS", Widget: WidgetPath, Advanced: true,
	},
	{
		Name: "insecure", Kind: KindBool, Usage: "skip TLS certificate verification",
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: boolDefault(func(s client.Settings) bool { return s.Insecure }),
		Label:   "Skip TLS certificate verification", Group: "🔒 TLS", Widget: WidgetToggle, Advanced: true,
	},
	{
		Name: "https-proxy", Kind: KindString, Usage: "explicit HTTP(S) or SOCKS5 proxy URL for HTTPS and WSS traffic",
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: strDefault(func(s client.Settings) string { return s.HTTPSProxy }),
		Label:   "HTTPS proxy", Group: "🌐 Connection", Widget: WidgetText, Advanced: true,
		Help: "Overrides HTTPS_PROXY and HTTP_PROXY for this ntwire connection. Use http://, https://, socks5://, or socks5h://, optionally with credentials.",
	},
	{
		Name: "no-system-proxy", Kind: KindBool, Usage: "ignore HTTP(S)_PROXY and NO_PROXY environment variables",
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: boolDefault(func(s client.Settings) bool { return s.NoSystemProxy }),
		Label:   "Ignore system proxy", Group: "🌐 Connection", Widget: WidgetToggle, Advanced: true,
		Help: "Connect directly instead of using HTTP_PROXY, HTTPS_PROXY, or NO_PROXY. An explicit HTTPS proxy still takes precedence.",
	},
	{
		Name: "ip-version", Kind: KindString, Usage: `restrict the server connection to "4" or "6" (default: either)`,
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: strDefault(func(s client.Settings) string { return s.IPVersion }),
		Label:   "IP version preference", Group: "🌐 Connection", Widget: WidgetText, Advanced: true,
		Help: `Leave empty to allow either family (default). Set to "4" or "6" to connect over only that family -- the other is never attempted, even if it would have worked. Applies to every connection ntwire makes: the control-plane/WebSocket connection to the server (or to the proxy, if one is configured) and the direct-UDP WireGuard data plane, including relay-assisted NAT punching and upgrade attempts.`,
	},
	{
		Name: "transport", Kind: KindString, Usage: `preferred or forced transport mode ("auto", "direct-udp", "udp-relay", "wss")`,
		Bind:    []Binding{{Command: "connect"}},
		Default: strDefault(func(s client.Settings) string { return s.Transport }),
		Label:   "Transport mode", Group: "🌐 Connection", Widget: WidgetText, Advanced: true,
		Help: `Select a transport mode ("auto", "direct-udp", "udp-relay", "wss"). Default is "auto" (sticky health-driven failover across available transports). When forced to a specific transport, ntwire will use it while healthy and automatically fall back to the best available transport if unavailable.`,
	},
	{
		Name: "known-servers", Kind: KindString, Usage: "known servers file",
		Bind:  []Binding{{Command: "connect"}, {Command: "list"}},
		Label: "Known servers file", Group: "🔒 TLS", Widget: WidgetPath, Advanced: true,
	},
	{
		Name: "no-browser", Kind: KindBool,
		Usage: "do not open a browser (local status UI, and SSO login falls back to the device flow)",
		Bind: []Binding{
			{Command: "connect"},
			{Command: "list", Usage: "do not open a browser; SSO login falls back to the device flow"},
		},
		Default: boolDefault(func(s client.Settings) bool { return s.NoBrowser }),
		// The GUI always sets NoWebUI:true, NoBrowser:false itself (see
		// config.Profile.ToClientOptions's doc comment) -- it is never a
		// per-profile choice there, so this is not a form field to expose.
		Label: "Do not open a browser", Group: "🌐 Connection", Widget: WidgetToggle, GUIHidden: true,
	},
	{
		Name: "sso", Kind: KindBool, Usage: "use SSO (OIDC) authentication instead of an SSH key",
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: boolDefault(func(s client.Settings) bool { return s.SSO }),
		Label:   "Use SSO (OIDC)", Group: "🔑 SSO", Widget: WidgetToggle,
	},
	{
		Name: "provider", Kind: KindString, Usage: "oidc issuer name (when the server advertises more than one)",
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: strDefault(func(s client.Settings) string { return s.Provider }),
		Label:   "OIDC provider", Group: "🔑 SSO", Widget: WidgetText,
	},
	{
		Name: "token-cache", Kind: KindString,
		Bind: []Binding{
			{Command: "connect", Usage: "SSO token cache file"},
			{Command: "list", Usage: "SSO token cache file"},
			{Command: "logout", Usage: "token cache file"},
		},
		Usage: "SSO token cache file",
		Label: "Token cache file", Group: "🔑 SSO", Widget: WidgetPath, Advanced: true,
	},
	{
		Name: "udp-alt", Kind: KindBool, Usage: "retry direct UDP on the server's alternate port (listen.wireguard_alt) when the primary port is unreachable",
		Bind:    []Binding{{Command: "connect"}},
		Default: boolDefault(func(s client.Settings) bool { return s.UDPAlt }),
		Label:   "Try alternate UDP port", Group: "🛠️ Advanced", Widget: WidgetToggle, Advanced: true,
		Help: "Off by default. When the server advertises an alternate WireGuard UDP port (for example 443) and direct UDP on its primary port cannot be proven, retry the direct-UDP path on the alternate port. Has no effect unless the server enables listen.wireguard_alt.",
	},
	{
		Name: "mtu-aware", Kind: KindBool, Usage: "retry lost MTU probes and avoid UDP paths that cannot carry full-size tunnel packets",
		Bind:    []Binding{{Command: "connect"}},
		Default: boolDefault(func(s client.Settings) bool { return s.MTUAware }),
		Label:   "MTU-aware path selection", Group: "🛠️ Advanced", Widget: WidgetToggle, Advanced: true,
		Help: "Off by default. Probes each UDP path at the size a full tunnel packet needs, retrying lost probes, and reports it as ok or limited in ntwire transport -v. A limited path is ranked after other healthy paths on failover. Works with any server that negotiates path-MTU probing; the server's own transport.mtu_aware setting is independent.",
	},
	{
		Name: "tunnel-mtu", Kind: KindString, Usage: "WireGuard tunnel MTU, 1280-1420 (default 1420)",
		Bind:    []Binding{{Command: "connect"}},
		Default: strDefault(func(s client.Settings) string { return s.TunnelMTU }),
		Label:   "Tunnel MTU", Group: "🛠️ Advanced", Widget: WidgetText, Advanced: true,
		Help: "Leave empty for 1420. Lower it (for example 1380) on links with extra encapsulation such as PPPoE or another VPN, so full-size tunnel packets fit. With MTU-aware path selection, the required probe size follows this value.",
	},
	{
		Name: "promote", Kind: KindBool, Usage: "move a healthy session from WebSocket to a proven faster UDP path, coordinated with the server",
		Bind:    []Binding{{Command: "connect"}},
		Default: boolDefault(func(s client.Settings) bool { return s.Promote }),
		Label:   "Promote to faster transport (experimental)", Group: "🛠️ Advanced", Widget: WidgetToggle, Advanced: true,
		Help: "Off by default. Normally a session that starts on the WebSocket carrier stays there while it is healthy, even if a UDP path becomes available. With this on, and with transport.promotion enabled on the server, ntwire moves both directions to a UDP path once it has been healthy for about 15 seconds and clearly better, at most once a minute, backing off if a promoted path fails soon after. Has no effect unless the server enables it.",
	},
	{
		Name: "websocket", Kind: KindBool, Usage: "use the WebSocket WireGuard transport",
		Bind:  []Binding{{Command: "connect"}},
		Label: "Force WebSocket transport", Group: "🛠️ Advanced", Widget: WidgetToggle, Advanced: true,
	},
	{
		Name: "collect-exec", Kind: KindString, Usage: "command that emits JSON client-info fields",
		Bind:    []Binding{{Command: "connect"}, {Command: "list"}},
		Default: strDefault(func(s client.Settings) string { return s.CollectExec }),
		Label:   "Client-info collector command", Group: "🛠️ Advanced", Widget: WidgetText, Advanced: true,
	},
	{
		Name: "bind", Kind: KindString,
		Usage:   "local address to bind tunnel listeners to, instead of 127.0.0.1 (numeric IP only; exposes tunneled targets beyond this host)",
		Bind:    []Binding{{Command: "connect"}},
		Default: strDefault(func(s client.Settings) string { return s.BindAddress }),
		Label:   "Bind address", Group: "🛠️ Advanced", Widget: WidgetText, Advanced: true,
		Help: "Leave empty for 127.0.0.1 (default, most secure). A LAN IP or 0.0.0.0 makes tunneled targets reachable from other hosts on that network -- there is no additional access control at the listener.",
	},
	{
		Name: "port", Kind: KindKeyValue, Usage: "name=[host:]local-port (repeatable)",
		Bind:  []Binding{{Command: "connect"}},
		Label: "Local ports", Group: "🔌 Tunnels", Widget: WidgetPortMap,
		Help: "name=local-port, or name=host:local-port (IPv6 as name=[::1]:local-port) to also pin the tunnel's loopback address, e.g. 127.70.0.1 -- lets distinct tunnels share a memorable port without colliding. Falls back to 127.0.0.1 if the address can't be bound; on macOS a non-default 127.x.x.x address needs `sudo ifconfig lo0 alias <address> up` first (Linux binds it out of the box).",
	},
	{
		Name: "status-file", Kind: KindString, Usage: "local status file",
		Bind:      []Binding{{Command: "list"}, {Command: "status"}, {Command: "disconnect"}, {Command: "port"}, {Command: "browser"}, {Command: "transport"}},
		GUIHidden: true,
	},
	{
		Name: "json", Kind: KindBool, Usage: "output as JSON",
		Bind:      []Binding{{Command: "list"}, {Command: "status"}},
		GUIHidden: true,
	},
	{
		Name: "clean", Kind: KindBool, Usage: "remove the target's persistent browser profile instead of opening it",
		Bind:      []Binding{{Command: "browser"}},
		GUIHidden: true,
	},
	{
		Name: "list", Kind: KindBool, Usage: "list persistent browser profile directories and exit",
		Bind:      []Binding{{Command: "browser"}},
		GUIHidden: true,
	},
	{
		Name: "clean-all", Kind: KindBool, Usage: "remove all unused persistent browser profile directories and exit",
		Bind:      []Binding{{Command: "browser"}},
		GUIHidden: true,
	},
	{
		Name: "o", Kind: KindString, Usage: "private key output",
		Bind:    []Binding{{Command: "keygen"}},
		Default: func(d Defaults) string { return d.GeneratedIdentityFile },
		Label:   "Output path", Group: "🪪 Identity", Widget: WidgetPath,
	},
	{
		Name: "no-color", Kind: KindBool, Usage: "disable ANSI colors (or set NO_COLOR)",
		Bind: []Binding{
			{Command: "connect"}, {Command: "list"}, {Command: "status"}, {Command: "disconnect"},
			{Command: "port"}, {Command: "browser"}, {Command: "logout"}, {Command: "keygen"}, {Command: "transport"},
		},
		Discarded: true, GUIHidden: true,
	},
}

// All returns every declared Option, across every subcommand.
func All() []Option {
	out := make([]Option, len(registry))
	copy(out, registry)
	return out
}

// For returns the Options exposed on command, in registry order.
func For(command string) []Option {
	var out []Option
	for _, o := range registry {
		if o.definedOn(command) {
			out = append(out, o)
		}
	}
	return out
}

// Usage returns o's usage string for command: a Binding override when one
// exists for that command, otherwise o.Usage.
func Usage(o Option, command string) string {
	return o.usageFor(command)
}

// Lookup finds the Option named name on command.
func Lookup(command, name string) (Option, bool) {
	for _, o := range registry {
		if o.Name == name && o.definedOn(command) {
			return o, true
		}
	}
	return Option{}, false
}

// Field is one generated settings-form field, derived from an Option and
// the name of the config struct field its value is read from and written
// back to (a GUI profile field, or a persisted client.Settings field).
type Field struct {
	Name        string // the Option's Name
	ConfigField string // the config struct field name this maps to
	Kind        string // "string", "bool", or "keyvalue"
	Label       string
	Help        string
	Group       string
	Widget      string
	Advanced    bool
}

func kindName(k Kind) string {
	switch k {
	case KindBool:
		return "bool"
	case KindStringList:
		return "stringlist"
	case KindKeyValue:
		return "keyvalue"
	default:
		return "string"
	}
}

// Fields builds a settings-form field list for command from the registry,
// so a generated form can never drift from the flags cmd/ntwire actually
// parses. fieldMap names, for each Option.Name a settings UI wants to
// expose, the config struct field it reads/writes -- an option missing
// from fieldMap (deliberately, e.g. one with nothing persisted to write to)
// is skipped rather than producing a field that writes nowhere.
func Fields(command string, fieldMap map[string]string) []Field {
	var out []Field
	for _, o := range For(command) {
		field, ok := fieldMap[o.Name]
		if !ok {
			continue
		}
		out = append(out, Field{
			Name: o.Name, ConfigField: field, Kind: kindName(o.Kind),
			Label: o.Label, Help: o.Help, Group: o.Group, Widget: string(o.Widget), Advanced: o.Advanced,
		})
	}
	return out
}
