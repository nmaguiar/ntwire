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
		"https:", "wireguard:", "metrics:", "authorized_keys_dir:", "session_ttl:",
		"max_sessions_per_key:", "issuers:", "name:", "issuer:", "client_id:",
		"scopes:", "groups_claim:", "require_verified_email:", "webhook_url:", "exec:",
		"timeout:", "tunnel_cidr:", "advertised_endpoint:", "virtual_port:",
		"local_port:", "allow:", "target:", "description:", "log_file:",
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

func TestLoadConfigReadsAuditLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
audit:
  log_file: /var/log/ntwire/audit.log
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Audit.LogFile != "/var/log/ntwire/audit.log" {
		t.Fatalf("audit.log_file = %q", got.Audit.LogFile)
	}
}

func TestLoadConfigReadsSocksTunnel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: egress
    target: socks
    virtual_port: 11080
    socks:
      only_local: true
      filters: ["10.0.0.0/8"]
      domain_filters: [".svc.cluster.local"]
      asn_filters: [15169]
      reverse_filters: true
      dns_timeout: 5s
      allow_all: true
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 1 || !got.Tunnels[0].IsSocks() {
		t.Fatalf("tunnels = %+v", got.Tunnels)
	}
	sc := got.Tunnels[0].Socks
	if sc == nil {
		t.Fatal("socks config is nil")
	}
	if !sc.OnlyLocal || len(sc.Filters) != 1 || len(sc.DomainFilters) != 1 || len(sc.ASNFilters) != 1 ||
		!sc.ReverseFilters || sc.DNSTimeout != 5*1e9 || !sc.AllowAll {
		t.Fatalf("socks config = %+v", sc)
	}
}

func TestLoadConfigRejectsSocksTargetWithoutSocksBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: egress
    target: socks
    virtual_port: 11080
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted target: socks without a socks: block")
	}
}

func TestLoadConfigRejectsSocksBlockWithoutSocksTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    socks:
      allow_all: true
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted a socks: block on a non-socks target")
	}
}

func TestLoadConfigRejectsInvalidSocksFilterCIDR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: egress
    target: socks
    virtual_port: 11080
    socks:
      filters: ["not-a-cidr"]
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted an invalid socks.filters CIDR")
	}
}

func TestSocksConfigWantsASNUpdates(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name string
		cfg  SocksConfig
		want bool
	}{
		{"unset, no asn filters", SocksConfig{}, false},
		{"unset, with asn filters", SocksConfig{ASNFilters: []uint32{15169}}, true},
		{"explicitly disabled despite asn filters", SocksConfig{ASNFilters: []uint32{15169}, ASNUpdates: &no}, false},
		{"explicitly enabled without asn filters", SocksConfig{ASNUpdates: &yes}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.WantsASNUpdates(); got != tt.want {
				t.Errorf("WantsASNUpdates() = %v, want %v", got, tt.want)
			}
		})
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
