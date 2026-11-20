package main

import (
	"fmt"
	"maps"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/clientopts"
)

func browserStorage(fs *clientopts.FlagSet, settings client.Settings) (browseropen.LaunchOptions, error) {
	profiles := make(map[string]browseropen.ProfileSettings)
	maps.Copy(profiles, settings.BrowserProfiles)
	for _, flag := range []string{"browser-profile-dir", "browser-profile-name"} {
		for _, entry := range fs.KeyValues(flag) {
			name, value, ok := strings.Cut(entry, "=")
			if !ok || strings.TrimSpace(name) == "" {
				return browseropen.LaunchOptions{}, fmt.Errorf("--%s requires TUNNEL=VALUE", flag)
			}
			p := profiles[name]
			if flag == "browser-profile-dir" {
				p.Folder = value
			} else {
				p.Name = value
			}
			profiles[name] = p
		}
	}
	folder := settings.BrowserProfilesDir
	if fs.WasSet("browser-profiles-dir") {
		folder = fs.Str("browser-profiles-dir")
	}
	return browseropen.LaunchOptions{ProfilesDir: folder, TunnelProfiles: profiles}, browseropen.ValidateStorage(folder, profiles)
}
