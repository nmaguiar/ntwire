package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gui.yaml")
	cfg := Config{Profiles: []Profile{{ID: "a", Name: "A"}, {ID: "b", HTTPSProxy: "http://independent:8080"}}}
	for _, mode := range []struct {
		proxy  string
		direct bool
	}{
		{"http://user:p%40ss@proxy:8080", false}, {"https://proxy:8443", false},
		{"socks5://proxy:1080", false}, {"socks5h://proxy:1080", false},
		{"", true}, {"", false}, {"http://proxy:8080", false}, {"", true},
	} {
		cfg.Profiles[0].HTTPSProxy = mode.proxy
		cfg.Profiles[0].NoSystemProxy = mode.direct
		if err := Save(path, cfg); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		a, b := loaded.Profiles[0], loaded.Profiles[1]
		if a.HTTPSProxy != mode.proxy || a.NoSystemProxy != mode.direct || b.HTTPSProxy != cfg.Profiles[1].HTTPSProxy {
			t.Fatal("profile settings did not survive restart independently")
		}
		opts, err := a.ToClientOptions("/tmp/status-test", "", "")
		if err != nil || opts.HTTPSProxy != mode.proxy || opts.NoSystemProxy != mode.direct {
			t.Fatal("client options changed proxy mode")
		}
		if mode.proxy == "" && !mode.direct {
			data, _ := os.ReadFile(path)
			first := strings.Split(string(data), "id: b")[0]
			if strings.Contains(first, "https_proxy:") || strings.Contains(first, "no_system_proxy:") {
				t.Fatal("environment mode saved explicit values")
			}
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("insecure profile store permissions")
		}
	}
}

func TestExistingProxyProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gui.yaml")
	const old = "version: 1\nprofiles:\n- id: a\n  https_proxy: http://user:password@proxy:8080\n  no_system_proxy: true\n- id: b\n"
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profiles[0].HTTPSProxy != "http://user:password@proxy:8080" || !cfg.Profiles[0].NoSystemProxy || cfg.Profiles[1].HTTPSProxy != "" || cfg.Profiles[1].NoSystemProxy {
		t.Fatal("legacy profile semantics changed")
	}
}
