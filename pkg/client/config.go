package client

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultIdentityFile returns the first conventional OpenSSH identity file
// present in ~/.ssh. The same home-relative location is used on every
// supported platform, including Windows.
//
// An explicit -i flag or identity_file setting always takes precedence.
func DefaultIdentityFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return defaultIdentityFile(home)
}

func defaultIdentityFile(home string) string {
	for _, name := range []string{
		"id_rsa",
		"id_ecdsa",
		"id_ecdsa_sk",
		"id_ed25519",
		"id_ed25519_sk",
		"id_xmss",
		"id_dsa",
	} {
		path := filepath.Join(home, ".ssh", name)
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

// Settings is the optional persistent configuration stored at
// ~/.nwire/config.yaml. Command-line flags take precedence over these values.
type Settings struct {
	Server       string         `yaml:"server"`
	IdentityFile string         `yaml:"identity_file"`
	Ports        map[string]int `yaml:"ports"`
	CAFile       string         `yaml:"ca_file"`
	Insecure     bool           `yaml:"insecure"`
	NoBrowser    bool           `yaml:"no_browser"`
	CollectExec  string         `yaml:"collect_exec"`
}

func DefaultConfigFile() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".nwire", "config.yaml")
}

// LoadSettings treats a missing configuration file as an empty configuration.
func LoadSettings(path string) (Settings, error) {
	if path == "" {
		path = DefaultConfigFile()
	}
	var s Settings
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	err = yaml.Unmarshal(b, &s)
	return s, err
}
