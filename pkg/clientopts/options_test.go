package clientopts

import (
	"sort"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/client"
)

// wantSurface is the exact (command, flag name) surface cmd/ntwire exposed
// before this registry existed, captured by reading cmd/ntwire/main.go's
// hand-written flag.FlagSet definitions. A reviewer can compare this table
// directly against that history without needing a golden file.
var wantSurface = map[string][]string{
	"connect": {
		"v", "config", "i", "ca", "insecure", "known-servers", "no-browser",
		"sso", "provider", "token-cache", "websocket", "collect-exec",
		"no-color", "port", "bind", "https-proxy", "no-system-proxy", "ip-version", "transport",
	},
	"list": {
		"v", "config", "i", "ca", "insecure", "known-servers", "no-browser",
		"sso", "provider", "token-cache", "collect-exec", "status-file",
		"json", "no-color", "https-proxy", "no-system-proxy", "ip-version",
	},
	"status":     {"status-file", "json", "no-color"},
	"disconnect": {"status-file", "no-color"},
	"port":       {"status-file", "no-color"},
	"browser":    {"status-file", "clean", "list", "clean-all", "no-color"},
	"transport":  {"status-file", "no-color"},
	"logout":     {"config", "token-cache", "no-color"},
	"keygen":     {"o", "no-color"},
}

func TestRegistryCoversExactFlagSurface(t *testing.T) {
	for command, want := range wantSurface {
		got := For(command)
		gotNames := make([]string, len(got))
		for i, o := range got {
			gotNames[i] = o.Name
		}
		sort.Strings(gotNames)
		wantNames := append([]string(nil), want...)
		sort.Strings(wantNames)
		if len(gotNames) != len(wantNames) {
			t.Fatalf("%s: got %d flags %v, want %d %v", command, len(gotNames), gotNames, len(wantNames), wantNames)
		}
		for i := range gotNames {
			if gotNames[i] != wantNames[i] {
				t.Fatalf("%s: flag surface mismatch: got %v, want %v", command, gotNames, wantNames)
			}
		}
	}
}

func TestUsageOverridesPerCommand(t *testing.T) {
	o, ok := Lookup("list", "no-browser")
	if !ok {
		t.Fatal("no-browser not found on list")
	}
	if got := Usage(o, "list"); got != "do not open a browser; SSO login falls back to the device flow" {
		t.Errorf("list no-browser usage = %q", got)
	}
	if got := Usage(o, "connect"); got != "do not open a browser (local status UI, and SSO login falls back to the device flow)" {
		t.Errorf("connect no-browser usage = %q", got)
	}

	o, ok = Lookup("logout", "token-cache")
	if !ok {
		t.Fatal("token-cache not found on logout")
	}
	if got := Usage(o, "logout"); got != "token cache file" {
		t.Errorf("logout token-cache usage = %q", got)
	}
	o, ok = Lookup("connect", "token-cache")
	if !ok {
		t.Fatal("token-cache not found on connect")
	}
	if got := Usage(o, "connect"); got != "SSO token cache file" {
		t.Errorf("connect token-cache usage = %q", got)
	}
}

func TestDefaultsLayerFromSettings(t *testing.T) {
	d := Defaults{
		Settings: client.Settings{
			IdentityFile:  "/home/x/key",
			CAFile:        "/home/x/ca.pem",
			Insecure:      true,
			HTTPSProxy:    "http://proxy.example:8080",
			NoSystemProxy: true,
			NoBrowser:     true,
			SSO:           true,
			Provider:      "okta",
			CollectExec:   "/usr/local/bin/collect",
			BindAddress:   "0.0.0.0",
		},
		ConfigPath:            "/home/x/.ntwire/config.yaml",
		GeneratedIdentityFile: "/home/x/.ntwire/id_ed25519",
	}
	cases := []struct{ command, name, want string }{
		{"connect", "i", "/home/x/key"},
		{"connect", "ca", "/home/x/ca.pem"},
		{"connect", "insecure", "true"},
		{"connect", "https-proxy", "http://proxy.example:8080"},
		{"connect", "no-system-proxy", "true"},
		{"connect", "no-browser", "true"},
		{"connect", "sso", "true"},
		{"connect", "provider", "okta"},
		{"connect", "collect-exec", "/usr/local/bin/collect"},
		{"connect", "bind", "0.0.0.0"},
		{"connect", "config", "/home/x/.ntwire/config.yaml"},
		{"keygen", "o", "/home/x/.ntwire/id_ed25519"},
		{"connect", "known-servers", ""},
	}
	for _, c := range cases {
		o, ok := Lookup(c.command, c.name)
		if !ok {
			t.Fatalf("%s/%s not found", c.command, c.name)
		}
		got := ""
		if o.Default != nil {
			got = o.Default(d)
		}
		if got != c.want {
			t.Errorf("%s/%s default = %q, want %q", c.command, c.name, got, c.want)
		}
	}
}

func TestWebsocketHasNoConfigDefault(t *testing.T) {
	// --websocket is always false unless the user passes it; unlike the
	// other connect/list flags it is not layered under client.Settings.
	o, ok := Lookup("connect", "websocket")
	if !ok {
		t.Fatal("websocket not found on connect")
	}
	if o.Default != nil {
		t.Errorf("websocket should have no Default func, got one")
	}
}

func TestZeroSettingsDefaultsToEmpty(t *testing.T) {
	d := Defaults{}
	for _, o := range All() {
		if o.Default == nil {
			continue
		}
		got := o.Default(d)
		if got != "" && got != "false" {
			t.Errorf("%s: zero-Settings default = %q, want \"\" or \"false\"", o.Name, got)
		}
	}
}

func TestDiscardedFlagsAreConfigAndNoColor(t *testing.T) {
	for _, o := range All() {
		if o.Discarded && o.Name != "config" && o.Name != "no-color" {
			t.Errorf("unexpected Discarded option %q", o.Name)
		}
	}
}
