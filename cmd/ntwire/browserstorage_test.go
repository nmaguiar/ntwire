package main

import (
	"testing"

	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/clientopts"
)

func TestBrowserStorageFlagsOverrideSavedSettings(t *testing.T) {
	global := t.TempDir()
	override := t.TempDir()
	settings := client.Settings{
		BrowserProfilesDir: t.TempDir(),
		BrowserProfiles: map[string]browseropen.ProfileSettings{
			"reports": {Name: "Saved", Folder: override},
		},
	}
	fs := clientopts.NewFlagSet("browser", clientopts.Defaults{Settings: settings})
	if err := fs.Parse([]string{"--browser-profiles-dir", global, "--browser-profile-name", "reports=Work reports"}); err != nil {
		t.Fatal(err)
	}
	storage, err := browserStorage(fs, settings)
	if err != nil {
		t.Fatal(err)
	}
	if got := storage.ForTunnel("reports").Profile; got.Folder != override || got.Name != "Work reports" {
		t.Fatalf("wrong override: %+v", got)
	}
	if got := storage.ForTunnel("other").Profile.Folder; got != global {
		t.Fatalf("other tunnel inherited %q, want %q", got, global)
	}

	fs = clientopts.NewFlagSet("browser", clientopts.Defaults{Settings: settings})
	if err := fs.Parse([]string{"--browser-profile-dir", "reports="}); err != nil {
		t.Fatal(err)
	}
	storage, err = browserStorage(fs, settings)
	if err != nil || storage.ForTunnel("reports").Profile.Folder != settings.BrowserProfilesDir {
		t.Fatalf("clearing override did not restore inheritance: %+v, %v", storage, err)
	}
}
