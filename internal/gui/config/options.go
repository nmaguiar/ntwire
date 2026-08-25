package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/client"
)

// ExpandHome expands a leading "~" or "~/" to the current user's home
// directory. A path without a leading ~ is returned unchanged.
func ExpandHome(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return h
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(h, path[2:])
	}
	return path
}

// IdentityFilePath returns this profile's SSH private key path with a
// leading ~ expanded.
func (p Profile) IdentityFilePath() string {
	return ExpandHome(p.IdentityFile)
}

// ToClientOptions builds the client.Options this profile should connect
// with.
//
// statusFile must be non-empty -- use StatusFilePath(p.ID). It exists as a
// required parameter, not a field read internally, specifically so this
// invariant cannot be forgotten: client.Connection.Close falls back to
// ~/.ntwire/status.json and deletes it when Options.StatusFile is empty,
// which would delete a concurrently running `ntwire connect`'s status file
// out from under it and kill that process's ability to see its own status.
//
// NoWebUI is always true (the GUI renders its own dashboard; the CLI's
// local-status-UI browser popup is never wanted here) and NoBrowser is
// always false (an SSO login must still be able to open a browser) --
// deliberately different from the CLI, which conflates both meanings behind
// one --no-browser flag. Getting this backwards would silently force every
// GUI-managed SSO login into the device-code flow.
//
// settingsURL, when non-empty, is the running ntwire-gui settings window's
// own URL (api.Server.URL()); it is only ever surfaced back to the operator
// as a link on this profile's per-connection status page, never dialed.
func (p Profile) ToClientOptions(statusFile, passphrase, settingsURL string) (client.Options, error) {
	if statusFile == "" {
		return client.Options{}, fmt.Errorf("gui: profile %q has no status file", p.Name)
	}
	ports := make(map[string]int, len(p.Ports))
	for k, v := range p.Ports {
		ports[k] = v
	}
	hosts := make(map[string]string, len(p.Hosts))
	for k, v := range p.Hosts {
		hosts[k] = v
	}
	return client.Options{
		Ports:            ports,
		Hosts:            hosts,
		CAFile:           ExpandHome(p.CAFile),
		Insecure:         p.Insecure,
		HTTPSProxy:       p.HTTPSProxy,
		NoSystemProxy:    p.NoSystemProxy,
		KnownServersFile: ExpandHome(p.KnownServersFile),
		NoWebUI:          true,
		StatusFile:       statusFile,
		UseWebSocket:     p.Websocket,
		KeyPassphrase:    passphrase,
		SSO:              p.SSO,
		Provider:         p.Provider,
		NoBrowser:        false,
		TokenCacheFile:   ExpandHome(p.TokenCacheFile),
		OIDCClientSecret: p.OIDCClientSecret,
		BindAddress:      p.BindAddress,
		IPVersion:        p.IPVersion,
		Transport:        p.Transport,
		SettingsURL:      settingsURL,
	}, nil
}
