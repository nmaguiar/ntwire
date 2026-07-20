package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSampleConfigIsCompleteAndLoadable(t *testing.T) {
	sample := SampleConfig()
	for _, option := range []string{
		"cert_file:", "key_file:", "state_dir:", "ephemeral:",
		"https:", "wireguard:", "authorized_keys_dir:", "session_ttl:",
		"max_sessions_per_key:", "issuers:", "name:", "issuer:", "client_id:",
		"scopes:", "groups_claim:", "require_verified_email:", "webhook_url:", "exec:",
		"timeout:", "tunnel_cidr:", "advertised_endpoint:", "virtual_port:",
		"local_port:", "allow:", "target:", "description:",
	} {
		if !strings.Contains(sample, option) {
			t.Errorf("sample configuration is missing %q", option)
		}
	}

	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	if err := os.WriteFile(path, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig(SampleConfig()) failed: %v", err)
	}
}

func TestLoadConfigReadsTunnelLocalPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    local_port: 58080
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 1 || got.Tunnels[0].LocalPort != 58080 {
		t.Fatalf("tunnels = %+v", got.Tunnels)
	}
}

func TestLoadConfigRejectsInvalidTunnelLocalPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    local_port: 65536
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted local_port above 65535")
	}
}
