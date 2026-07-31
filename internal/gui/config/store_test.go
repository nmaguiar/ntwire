package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileReturnsEmptyConfig(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(filepath.Join(dir, "gui.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Version != CurrentVersion {
		t.Errorf("Load() Version = %d, want %d", cfg.Version, CurrentVersion)
	}
	if len(cfg.Profiles) != 0 {
		t.Errorf("Load() Profiles = %v, want empty", cfg.Profiles)
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gui.yaml")
	cfg := Config{
		Settings: Settings{StartAtLogin: true, Notifications: true},
		Profiles: []Profile{
			{ID: "abc123", Name: "home-lab", Server: "https://home.example:8443", Ports: map[string]int{"web": 8080}},
		},
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].Name != "home-lab" || got.Profiles[0].Ports["web"] != 8080 {
		t.Fatalf("Load() = %+v, want the saved profile back", got)
	}
	if !got.Settings.StartAtLogin {
		t.Errorf("Load() Settings.StartAtLogin = false, want true")
	}
}

func TestSaveWritesAtMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gui.yaml")
	if err := Save(path, Config{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("gui.yaml mode = %o, want 0600", perm)
	}
}

func TestSaveCreatesParentDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "gui.yaml")
	if err := Save(path, Config{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("gui.yaml not written: %v", err)
	}
}

// TestSaveLeavesNoTempFileOnSuccess guards against a leaked .gui-* temp file
// in the target directory, which would otherwise accumulate on every save.
func TestSaveLeavesNoTempFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gui.yaml")
	if err := Save(path, Config{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "gui.yaml" {
		t.Errorf("directory contents = %v, want only gui.yaml", entries)
	}
}

func TestStatusFilePathDistinctPerProfile(t *testing.T) {
	a := StatusFilePath("profile-a")
	b := StatusFilePath("profile-b")
	if a == "" || b == "" {
		t.Fatal("StatusFilePath returned empty path")
	}
	if a == b {
		t.Fatalf("StatusFilePath(a) == StatusFilePath(b) == %q, want distinct paths", a)
	}
	if filepath.Base(a) == filepath.Base(filepath.Dir(a)) {
		t.Errorf("StatusFilePath(%q) looks malformed: %q", "profile-a", a)
	}
}
