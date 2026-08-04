package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCLIConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImportFromCLICreatesOneProfile(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIConfig(t, dir, "server: https://home.example:8443\nidentity_file: /home/x/key\nhttps_proxy: http://proxy.example:8080\nno_system_proxy: true\nports:\n  web: 8080\n")

	var cfg Config
	imported, err := ImportFromCLI(&cfg, path)
	if err != nil {
		t.Fatalf("ImportFromCLI() error = %v", err)
	}
	if !imported {
		t.Fatal("ImportFromCLI() imported = false, want true")
	}
	if len(cfg.Profiles) != 1 {
		t.Fatalf("Profiles = %v, want exactly one", cfg.Profiles)
	}
	p := cfg.Profiles[0]
	if p.Server != "https://home.example:8443" || p.IdentityFile != "/home/x/key" || p.Ports["web"] != 8080 {
		t.Errorf("imported profile = %+v", p)
	}
	if p.Name != "home.example:8443" {
		t.Errorf("imported profile Name = %q, want the server's host:port", p.Name)
	}
	if p.ID == "" {
		t.Error("imported profile has no ID")
	}
	if p.HTTPSProxy != "http://proxy.example:8080" || !p.NoSystemProxy {
		t.Errorf("imported proxy settings = %+v", p)
	}
	if !cfg.Settings.ImportedCLIConfig {
		t.Error("Settings.ImportedCLIConfig = false, want true after import")
	}
}

func TestImportFromCLIWithNoServerConfiguredMarksImportedButAddsNothing(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIConfig(t, dir, "identity_file: /home/x/key\n") // no "server:" key

	var cfg Config
	imported, err := ImportFromCLI(&cfg, path)
	if err != nil {
		t.Fatalf("ImportFromCLI() error = %v", err)
	}
	if imported {
		t.Fatal("ImportFromCLI() imported = true, want false when config.yaml has no server")
	}
	if len(cfg.Profiles) != 0 {
		t.Errorf("Profiles = %v, want none", cfg.Profiles)
	}
	// Still marked, so a later config.yaml edit doesn't retroactively import.
	if !cfg.Settings.ImportedCLIConfig {
		t.Error("Settings.ImportedCLIConfig = false, want true even when nothing was imported")
	}
}

func TestImportFromCLIIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIConfig(t, dir, "server: https://home.example:8443\n")

	cfg := Config{Settings: Settings{ImportedCLIConfig: true}}
	imported, err := ImportFromCLI(&cfg, path)
	if err != nil {
		t.Fatalf("ImportFromCLI() error = %v", err)
	}
	if imported {
		t.Fatal("ImportFromCLI() imported = true, want false when ImportedCLIConfig is already set")
	}
	if len(cfg.Profiles) != 0 {
		t.Errorf("Profiles = %v, want none -- import must not run twice", cfg.Profiles)
	}
}

func TestImportFromCLIDoesNotRunWhenProfilesAlreadyExist(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIConfig(t, dir, "server: https://home.example:8443\n")

	cfg := Config{Profiles: []Profile{{ID: "existing", Name: "manually added"}}}
	imported, err := ImportFromCLI(&cfg, path)
	if err != nil {
		t.Fatalf("ImportFromCLI() error = %v", err)
	}
	if imported {
		t.Fatal("ImportFromCLI() imported = true, want false when a profile already exists")
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].ID != "existing" {
		t.Errorf("Profiles = %v, want the existing profile untouched", cfg.Profiles)
	}
}

// TestImportFromCLIDoesNotTouchConfigFile is the guardrail for the
// documented invariant that this package never writes ~/.ntwire/config.yaml.
// client.UpdateSettings is simply never imported here, but this also checks
// observable behavior: the CLI config file's mtime and content are
// unchanged after an import.
func TestImportFromCLIDoesNotTouchConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := writeCLIConfig(t, dir, "server: https://home.example:8443\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	var cfg Config
	if _, err := ImportFromCLI(&cfg, path); err != nil {
		t.Fatalf("ImportFromCLI() error = %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("config.yaml content changed:\nbefore: %s\nafter:  %s", before, after)
	}
	if !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Errorf("config.yaml mtime changed: %v -> %v", beforeInfo.ModTime(), afterInfo.ModTime())
	}
}
