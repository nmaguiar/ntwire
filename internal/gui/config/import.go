package config

import (
	"net/url"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/client"
)

// ImportFromCLI seeds gui.yaml from the CLI's ~/.ntwire/config.yaml the
// first time ntwire-gui runs, so a user who already has a working `ntwire
// connect` setup gets a matching profile without re-entering anything.
//
// It is a one-time, one-directional migration: it only runs when cfg has no
// profiles and Settings.ImportedCLIConfig is not already set (so an
// explicit "delete my only profile" is never silently undone), and it never
// writes ~/.ntwire/config.yaml -- that file is owned by cmd/ntwire, which
// auto-persists it on every successful `ntwire connect`, and a second
// writer would fight it.
//
// When cliConfigPath is empty, client.LoadSettings resolves it to
// client.DefaultConfigFile() (~/.ntwire/config.yaml); a caller passes an
// explicit path only in tests, to avoid depending on the real home
// directory.
//
// It reports whether a profile was imported.
func ImportFromCLI(cfg *Config, cliConfigPath string) (bool, error) {
	if len(cfg.Profiles) > 0 || cfg.Settings.ImportedCLIConfig {
		return false, nil
	}
	settings, err := client.LoadSettings(cliConfigPath)
	if err != nil {
		return false, err
	}
	cfg.Settings.ImportedCLIConfig = true
	if settings.Server == "" {
		return false, nil
	}
	ports := make(map[string]int, len(settings.Ports))
	for k, v := range settings.Ports {
		ports[k] = v
	}
	cfg.Profiles = append(cfg.Profiles, Profile{
		ID:             NewID(),
		Name:           profileNameFor(settings.Server),
		Server:         settings.Server,
		IdentityFile:   settings.IdentityFile,
		ConnectOnStart: false,
		Ports:          ports,
		CAFile:         settings.CAFile,
		Insecure:       settings.Insecure,
		HTTPSProxy:     settings.HTTPSProxy,
		NoSystemProxy:  settings.NoSystemProxy,
		SSO:            settings.SSO,
		Provider:       settings.Provider,
		CollectExec:    settings.CollectExec,
	})
	return true, nil
}

// profileNameFor derives a human-readable profile name from a server URL,
// e.g. "https://ntwire.example:8443" -> "ntwire.example:8443".
func profileNameFor(server string) string {
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(server, "https://"), "http://")
}
