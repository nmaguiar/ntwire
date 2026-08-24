package client

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultIdentityFileUsesOpenSSHOrder(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_ed25519", "id_rsa"} {
		if err := os.WriteFile(filepath.Join(sshDir, name), []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := defaultIdentityFile(home), filepath.Join(sshDir, "id_rsa"); got != want {
		t.Fatalf("defaultIdentityFile() = %q, want %q", got, want)
	}
}

func TestDefaultIdentityFileSkipsMissingAndNonRegularFiles(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(sshDir, "id_rsa"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := defaultIdentityFile(home); got != "" {
		t.Fatalf("defaultIdentityFile() = %q, want empty", got)
	}
}

func TestDefaultIdentityFilePrefersNTWire(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ntwire", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := defaultIdentityFile(home); got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestNormalizeServerURL(t *testing.T) {
	for in, want := range map[string]string{" example.test/ ": "https://example.test", "http://example.test:8080/": "http://example.test:8080"} {
		got, err := NormalizeServerURL(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeServerURL(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := NormalizeServerURL("ssh://example.test"); err == nil {
		t.Fatal("non-HTTP scheme accepted")
	}
}

func TestLoadSettingsReadsHTTPSProxyControls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("https_proxy: http://proxy.example:8080\nno_system_proxy: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.HTTPSProxy != "http://proxy.example:8080" || !got.NoSystemProxy {
		t.Errorf("LoadSettings() = %+v, want HTTPS proxy controls", got)
	}
}

// TestSaveSettingsWritesEveryFieldIncludingClearedOnes is the reason
// SaveSettings exists instead of reusing UpdateSettings: a settings page
// submits its whole current state, and a value the user cleared (Provider
// here) or turned off (Insecure) must land in the file, not be treated as
// "not touched".
func TestSaveSettingsWritesEveryFieldIncludingClearedOnes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("# a comment worth keeping\nprovider: old-provider\ninsecure: true\nports:\n  reports: 5432\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := SaveSettings(path, Settings{Server: "https://ntwire.example:8443", IdentityFile: "/home/u/.ntwire/id_ed25519", Insecure: false, SSO: true})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("SaveSettings reported no change")
	}
	got, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server != "https://ntwire.example:8443" || got.IdentityFile != "/home/u/.ntwire/id_ed25519" || got.Insecure || !got.SSO {
		t.Fatalf("LoadSettings() after SaveSettings = %+v", got)
	}
	if got.Provider != "" {
		t.Fatalf("Provider = %q, want cleared", got.Provider)
	}
	if got.Ports["reports"] != 5432 {
		t.Fatalf("Ports = %+v, want the pre-existing ports map preserved", got.Ports)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "a comment worth keeping") {
		t.Fatalf("comment lost:\n%s", raw)
	}
}

func TestSaveSettingsNoOpWhenNothingChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	s := Settings{Server: "https://ntwire.example:8443", SSO: true}
	if _, err := SaveSettings(path, s); err != nil {
		t.Fatal(err)
	}
	changed, err := SaveSettings(path, s)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("SaveSettings reported a change on an identical save")
	}
}

// TestSettingsUIFieldsCoverEveryPersistedScalarField is SaveSettings' half
// of the no-drift promise clientopts.Fields relies on elsewhere: a Settings
// field added without a settingsUIFields entry would silently never reach
// the settings page or the saved file.
func TestSettingsUIFieldsCoverEveryPersistedScalarField(t *testing.T) {
	mapped := map[string]bool{}
	for _, f := range settingsUIFields {
		mapped[f.Field] = true
	}
	typ := reflect.TypeOf(Settings{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if name == "Ports" || name == "Hosts" {
			continue // map fields: intentionally out of scope, see settingsUIFields' doc comment
		}
		if !mapped[name] {
			t.Errorf("Settings.%s has no settingsUIFields entry", name)
		}
	}
}
