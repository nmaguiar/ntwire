package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nmaguiar/ntwire/pkg/sshkey"
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
	ntwire := filepath.Join(home, ".ntwire", "id_ed25519")
	if info, err := os.Stat(ntwire); err == nil && info.Mode().IsRegular() {
		return ntwire
	}
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

// GenerateIdentity writes an Ed25519 private key and OpenSSH public key.
// It never overwrites an existing key pair.
func GenerateIdentity(path string) (string, error) {
	return sshkey.GenerateIdentityFile(path)
}

// Settings is the optional persistent configuration stored at
// ~/.ntwire/config.yaml. Command-line flags take precedence over these values.
type Settings struct {
	Server       string         `yaml:"server"`
	IdentityFile string         `yaml:"identity_file"`
	Ports        map[string]int `yaml:"ports"`
	// Hosts is a per-tunnel loopback address override; see
	// client.Options.Hosts.
	Hosts         map[string]string `yaml:"hosts"`
	CAFile        string            `yaml:"ca_file"`
	Insecure      bool              `yaml:"insecure"`
	HTTPSProxy    string            `yaml:"https_proxy"`
	NoSystemProxy bool              `yaml:"no_system_proxy"`
	NoBrowser     bool              `yaml:"no_browser"`
	CollectExec   string            `yaml:"collect_exec"`
	SSO           bool              `yaml:"sso"`
	Provider      string            `yaml:"provider"`
	// BindAddress is the advanced, opt-in override for the loopback-only
	// default tunnel listeners bind to; see client.Options.BindAddress.
	BindAddress string `yaml:"bind_address"`
	// IPVersion is the persisted default for client.Options.IPVersion
	// ("", "4", or "6").
	IPVersion string `yaml:"ip_version"`
}

func DefaultConfigFile() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".ntwire", "config.yaml")
}

func DefaultGeneratedIdentityFile() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".ntwire", "id_ed25519")
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

// UpdateSettings merges connection fields without replacing comments or other
// user-owned YAML settings. It returns true only when a file was changed.
func UpdateSettings(path string, update Settings) (bool, error) {
	if path == "" {
		path = DefaultConfigFile()
	}
	if path == "" {
		return false, fmt.Errorf("cannot determine configuration path")
	}
	var doc yaml.Node
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	} else if err != nil {
		return false, err
	} else if err = yaml.Unmarshal(b, &doc); err != nil {
		return false, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return false, fmt.Errorf("configuration root must be a mapping")
	}
	m := doc.Content[0]
	values := map[string]string{"server": update.Server, "identity_file": update.IdentityFile, "provider": update.Provider}
	changed := false
	for key, value := range values {
		if value != "" {
			changed = setYAMLString(m, key, value) || changed
		}
	}
	changed = setYAMLBool(m, "sso", update.SSO) || changed
	if !changed {
		return false, nil
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return false, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return false, err
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
		return false, err
	}
	return true, os.Rename(tmpName, path)
}

func setYAMLString(m *yaml.Node, key, value string) bool { return setYAML(m, key, value, "!!str") }
func setYAMLBool(m *yaml.Node, key string, value bool) bool {
	v := "false"
	if value {
		v = "true"
	}
	return setYAML(m, key, v, "!!bool")
}
func setYAML(m *yaml.Node, key, value, tag string) bool {
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			if m.Content[i+1].Value == value {
				return false
			}
			m.Content[i+1].Value, m.Content[i+1].Tag = value, tag
			return true
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value})
	return true
}
