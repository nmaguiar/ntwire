package completion

import (
	"github.com/nmaguiar/ntwire/pkg/clientopts"
)

// ClientCommand builds the completion Command specification for ntwire.
func ClientCommand() Command {
	subcmdDefs := []struct {
		name    string
		summary string
	}{
		{"keygen", "create an SSH identity"},
		{"connect", "connect tunnels"},
		{"list", "show allowed tunnels"},
		{"status", "show the running connection"},
		{"disconnect", "stop the running connection"},
		{"port", "replace a tunnel's local port"},
		{"logout", "clear cached SSO tokens"},
	}

	var subcmds []Command
	for _, sc := range subcmdDefs {
		var flags []Flag
		for _, o := range clientopts.For(sc.name) {
			flags = append(flags, Flag{
				Name:       o.Name,
				Usage:      clientopts.Usage(o, sc.name),
				TakesValue: o.Kind != clientopts.KindBool,
				IsFilePath: o.Widget == clientopts.WidgetPath,
			})
		}
		subcmds = append(subcmds, Command{
			Name:    sc.name,
			Summary: sc.summary,
			Flags:   flags,
		})
	}

	subcmds = append(subcmds,
		Command{
			Name:       "completion",
			Summary:    "generate shell completion script",
			ArgChoices: SupportedShells,
		},
		Command{
			Name:    "version",
			Summary: "print the build version",
		},
	)

	return Command{
		Name:    "ntwire",
		Summary: "connect to tunnels published by an ntwire-server",
		Flags: []Flag{
			{Name: "no-color", Usage: "disable ANSI colors (or set NO_COLOR)", TakesValue: false},
		},
		Subcommands: subcmds,
	}
}

// ServerCommand builds the completion Command specification for ntwire-server.
func ServerCommand() Command {
	return Command{
		Name:    "ntwire-server",
		Summary: "ntwire tunnel server",
		Flags: []Flag{
			{Name: "config", Usage: "server configuration file", TakesValue: true, IsFilePath: true},
			{Name: "print-sample-config", Usage: "print a fully commented sample YAML configuration and exit", TakesValue: false},
			{Name: "version", Usage: "print the build version and exit", TakesValue: false},
			{Name: "generate-relay-key", Usage: "generate an Ed25519 identity for relay.identity_file at this path, print setup instructions, and exit", TakesValue: true, IsFilePath: true},
			{Name: "generate-wireguard-key", Usage: "generate a WireGuard key pair at this path (and path.pub) for a native_wireguard peer, print setup instructions, and exit", TakesValue: true, IsFilePath: true},
			{Name: "print-wireguard-config", Usage: "print sample official WireGuard client configuration (.conf and QR code text) and exit", TakesValue: false},
			{Name: "print-wireguard-client-config", Usage: "alias for -print-wireguard-config", TakesValue: false},
			{Name: "print-wireguard-conf", Usage: "print sample official WireGuard client configuration in .conf format and exit", TakesValue: false},
			{Name: "print-wireguard-qr", Usage: "print sample official WireGuard client configuration as a QR code in text format and exit", TakesValue: false},
			{Name: "wireguard-format", Usage: "output format for -print-wireguard-config: conf, qr, or all", TakesValue: true, Choices: []string{"conf", "qr", "all"}},
			{Name: "wireguard-peer", Usage: "peer name from native_wireguard.peers to use", TakesValue: true},
			{Name: "wireguard-client-key", Usage: "client WireGuard private key to embed in the generated configuration", TakesValue: true},
			{Name: "log-format", Usage: "log output format: text or json", TakesValue: true, Choices: []string{"text", "json"}},
			{Name: "log-level", Usage: "log level: debug, info, warn, error", TakesValue: true, Choices: []string{"debug", "info", "warn", "error"}},
			{Name: "no-color", Usage: "disable ANSI colors in text-format logs (or set NO_COLOR)", TakesValue: false},
			{Name: "completion", Usage: "generate shell completion script (bash, zsh, fish, powershell) and exit", TakesValue: true, Choices: SupportedShells},
		},
	}
}

// RelayCommand builds the completion Command specification for ntwire-relay.
func RelayCommand() Command {
	return Command{
		Name:    "ntwire-relay",
		Summary: "NAT-traversal relay for ntwire-server",
		Flags: []Flag{
			{Name: "config", Usage: "relay configuration file", TakesValue: true, IsFilePath: true},
			{Name: "print-sample-config", Usage: "print a fully commented sample YAML configuration and exit", TakesValue: false},
			{Name: "version", Usage: "print the build version and exit", TakesValue: false},
			{Name: "log-format", Usage: "log output format: text or json", TakesValue: true, Choices: []string{"text", "json"}},
			{Name: "log-level", Usage: "log level: debug, info, warn, error", TakesValue: true, Choices: []string{"debug", "info", "warn", "error"}},
			{Name: "no-color", Usage: "disable ANSI colors in text-format logs (or set NO_COLOR)", TakesValue: false},
			{Name: "completion", Usage: "generate shell completion script (bash, zsh, fish, powershell) and exit", TakesValue: true, Choices: SupportedShells},
		},
	}
}

// GUICommand builds the completion Command specification for ntwire-gui.
func GUICommand() Command {
	return Command{
		Name:    "ntwire-gui",
		Summary: "ntwire tray/menu-bar GUI client",
		Flags: []Flag{
			{Name: "headless", Usage: "run the connection manager and settings API without a tray icon", TakesValue: false},
			{Name: "window", Usage: "internal: host a native settings window at this URL", TakesValue: true},
			{Name: "version", Usage: "print the version and exit", TakesValue: false},
			{Name: "gui-config", Usage: "path to gui.yaml (default ~/.ntwire/gui.yaml)", TakesValue: true, IsFilePath: true},
			{Name: "cli-config", Usage: "path to the CLI's config.yaml, imported once on first run (default ~/.ntwire/config.yaml)", TakesValue: true, IsFilePath: true},
			{Name: "autostart", Usage: "the process was launched by the OS's own login-item mechanism", TakesValue: false},
			{Name: "completion", Usage: "generate shell completion script (bash, zsh, fish, powershell) and exit", TakesValue: true, Choices: SupportedShells},
		},
	}
}
