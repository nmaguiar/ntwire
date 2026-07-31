package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultPath returns ~/.ntwire/gui.yaml.
func DefaultPath() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".ntwire", "gui.yaml")
}

// StatusDir returns ~/.ntwire/gui, where per-profile status files live.
func StatusDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".ntwire", "gui")
}

// StatusFilePath returns the status file a profile's connection should use.
// It is never empty when home is resolvable, which is what lets
// ToClientOptions enforce that every GUI-managed connection has one -- see
// options.go. Every profile gets a distinct file so that Connection.Close
// (which deletes its StatusFile) never touches another profile's, or the
// CLI's own ~/.ntwire/status.json.
func StatusFilePath(profileID string) string {
	dir := StatusDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "status-"+profileID+".json")
}

// Load reads path (DefaultPath when empty). A missing file is not an error:
// it returns an empty, current-version Config, matching client.LoadSettings'
// convention that "not configured yet" is not a failure.
func Load(path string) (Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	cfg := Config{Version: CurrentVersion}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err = yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Version == 0 {
		cfg.Version = CurrentVersion
	}
	return cfg, nil
}

// Save writes cfg to path (DefaultPath when empty) atomically at mode 0600,
// using the same temp-file-then-rename pattern as client.UpdateSettings.
// Unlike UpdateSettings, Save owns the whole file: it marshals cfg
// wholesale rather than patching individual keys, since gui.yaml has no
// user-authored comments to preserve.
func Save(path string, cfg Config) error {
	if path == "" {
		path = DefaultPath()
	}
	if path == "" {
		return errors.New("gui/config: cannot determine gui.yaml path")
	}
	if cfg.Version == 0 {
		cfg.Version = CurrentVersion
	}
	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gui-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(out)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
