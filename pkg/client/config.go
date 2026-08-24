package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

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
	return editSettings(path, func(m *yaml.Node) bool {
		values := map[string]string{"server": update.Server, "identity_file": update.IdentityFile, "provider": update.Provider}
		changed := false
		for key, value := range values {
			if value != "" {
				changed = setYAMLString(m, key, value) || changed
			}
		}
		return setYAMLBool(m, "sso", update.SSO) || changed
	})
}

// settingsUIFields is the settings UI's ordered field list: it is the
// complete set of scalar (non-map) Settings fields the "ntwire connect"
// settings page can read and save, each paired with its YAML key. Ports
// and Hosts are deliberately absent -- those stay the job of `ntwire port`
// and the local status UI's per-tunnel "Replace" control, not this page.
var settingsUIFields = []struct {
	Field, YAMLKey string
	Bool           bool
}{
	{Field: "Server", YAMLKey: "server"},
	{Field: "IdentityFile", YAMLKey: "identity_file"},
	{Field: "CAFile", YAMLKey: "ca_file"},
	{Field: "Insecure", YAMLKey: "insecure", Bool: true},
	{Field: "HTTPSProxy", YAMLKey: "https_proxy"},
	{Field: "NoSystemProxy", YAMLKey: "no_system_proxy", Bool: true},
	{Field: "NoBrowser", YAMLKey: "no_browser", Bool: true},
	{Field: "CollectExec", YAMLKey: "collect_exec"},
	{Field: "SSO", YAMLKey: "sso", Bool: true},
	{Field: "Provider", YAMLKey: "provider"},
	{Field: "BindAddress", YAMLKey: "bind_address"},
	{Field: "IPVersion", YAMLKey: "ip_version"},
}

// SaveSettings writes every settingsUIFields value from s into the
// configuration file, unconditionally -- unlike UpdateSettings, an empty
// string or false is written as such rather than treated as "leave
// untouched". This is what the local settings UI's "Save" button needs:
// the form always submits its complete current state (including fields the
// user cleared), so a partial-update merge would be unable to tell
// "cleared" apart from "never touched" and would leave stale values behind.
// Ports, Hosts, and any YAML this package does not model are preserved as
// on-disk, the same as UpdateSettings.
func SaveSettings(path string, s Settings) (bool, error) {
	return editSettings(path, func(m *yaml.Node) bool {
		changed := false
		for _, f := range settingsUIFields {
			v := reflect.ValueOf(s).FieldByName(f.Field)
			if f.Bool {
				changed = setYAMLBool(m, f.YAMLKey, v.Bool()) || changed
			} else {
				changed = setYAMLString(m, f.YAMLKey, v.String()) || changed
			}
		}
		return changed
	})
}

// editSettings loads path as a YAML document (an empty mapping when the
// file does not yet exist), applies edit to its root mapping node, and
// rewrites the file only when edit reports a change -- shared by
// UpdateSettings and SaveSettings so both go through the same
// comment-preserving read/write and atomic-rename path.
func editSettings(path string, edit func(m *yaml.Node) bool) (bool, error) {
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
	if !edit(doc.Content[0]) {
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
