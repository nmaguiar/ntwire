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
		"instructions:", "docs_url:", "advertise_direct:",
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

func TestLoadConfigAcceptsActiveActiveRelayEndpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
relay:
  enabled: true
  name: home
  identity_file: relay_id
  endpoints:
    - url: wss://relay-a.example.test:8444
      fingerprint: SHA256:a
    - url: wss://relay-b.example.test:8444
      fingerprint: SHA256:b
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Relay.Endpoints) != 2 || got.Relay.URL != "" {
		t.Fatalf("relay endpoints = %+v, url = %q", got.Relay.Endpoints, got.Relay.URL)
	}
}

// TestLoadConfigReadsInstructionsFromFile covers the file-path convenience:
// a single-line instructions value naming an existing file is replaced with
// that file's content, so operators can keep longer instructions in a
// separately maintained file instead of an inline YAML block scalar.
func TestLoadConfigReadsInstructionsFromFile(t *testing.T) {
	dir := t.TempDir()
	instrPath := filepath.Join(dir, "reports.md")
	want := "# Reports\n\nRun:\n\n```sh\ncurl http://{{.LocalHost}}:{{.LocalPort}}/reports\n```\n"
	if err := os.WriteFile(instrPath, []byte(want), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    instructions: ` + instrPath + `
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 1 || got.Tunnels[0].Instructions != want {
		t.Fatalf("Instructions = %q, want %q", got.Tunnels[0].Instructions, want)
	}
}

// TestLoadConfigKeepsInstructionsLiteralWhenNoSuchFile guards the fallback:
// a single-line value that happens not to name a real file is ordinary
// short-form instructions text, not a broken file reference.
func TestLoadConfigKeepsInstructionsLiteralWhenNoSuchFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    instructions: "See the team wiki for setup."
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "See the team wiki for setup."
	if len(got.Tunnels) != 1 || got.Tunnels[0].Instructions != want {
		t.Fatalf("Instructions = %q, want %q", got.Tunnels[0].Instructions, want)
	}
}

// TestLoadConfigSkipsOversizedInstructionsFile guards against a mistyped
// single-line instructions value accidentally naming a large file: without a
// size cap, that file's whole content would be shipped to every client over
// /v1/auth and /v1/renew instead of being caught at config-load time.
func TestLoadConfigSkipsOversizedInstructionsFile(t *testing.T) {
	dir := t.TempDir()
	instrPath := filepath.Join(dir, "big.md")
	if err := os.WriteFile(instrPath, make([]byte, maxInstructionsFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    instructions: ` + instrPath + `
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 1 || got.Tunnels[0].Instructions != instrPath {
		t.Fatalf("Instructions = %q, want the literal path %q (file too large to load)", got.Tunnels[0].Instructions, instrPath)
	}
}

// TestLoadConfigRejectsAdvertiseDirectWithoutRelay guards against a config
// that would silently be a no-op: relay.advertise_direct only means
// anything for a server that is actually relaying (cmd/ntwire-server only
// wires RelayAgent.OnReflectAddr inside the relay.enabled branch), so a
// standalone server setting it should be told rather than have it quietly
// ignored.
func TestLoadConfigRejectsAdvertiseDirectWithoutRelay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
relay:
  advertise_direct: true
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "advertise_direct") {
		t.Fatalf("LoadConfig() error = %v, want an advertise_direct validation error", err)
	}
}

func TestLoadConfigAcceptsAdvertiseDirectWithRelay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
relay:
  enabled: true
  url: wss://relay.example.com:8444
  name: home
  identity_file: relay_id_ed25519
  advertise_direct: true
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() = %v", err)
	}
	if !got.Relay.AdvertiseDirect {
		t.Fatal("Relay.AdvertiseDirect = false, want true")
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

func TestLoadConfigReadsTunnelInstructions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ntwire.yaml")
	config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    docs_url: https://wiki.example/reports
    instructions: |
      curl http://{{.LocalHost}}:{{.LocalPort}}/
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tunnels[0].DocsURL != "https://wiki.example/reports" {
		t.Fatalf("docs URL = %q", got.Tunnels[0].DocsURL)
	}
	if got.Tunnels[0].Instructions != "curl http://{{.LocalHost}}:{{.LocalPort}}/\n" {
		t.Fatalf("instructions = %q", got.Tunnels[0].Instructions)
	}
}

// A docs_url reaches an href in every connected client's browser, so a value
// that is not an absolute http(s) URL has to fail at load rather than ship.
func TestLoadConfigRejectsUnsafeDocsURL(t *testing.T) {
	for _, bad := range []string{"javascript:alert(1)", "/relative", "wiki.example"} {
		path := filepath.Join(t.TempDir(), "ntwire.yaml")
		config := `
auth:
  authorized_keys_dir: keys
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    docs_url: "` + bad + `"
`
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("docs_url %q was accepted", bad)
		}
	}
}
