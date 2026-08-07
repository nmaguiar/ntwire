package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func TestNoColorFrom(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"connect", "server.example"}, false},
		{[]string{"--no-color", "connect"}, true},
		{[]string{"connect", "--no-color"}, true},
		{[]string{"connect", "-no-color", "server.example"}, true},
	}
	for _, c := range cases {
		if got := noColorFrom(c.args); got != c.want {
			t.Errorf("noColorFrom(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

func TestSettingsForParsesConfigFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server: https://example.com:8443\n"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"--config", path, "connect"},
		{"--config=" + path, "connect"},
	} {
		settings, configPath := settingsFor(args)
		if configPath != path {
			t.Errorf("settingsFor(%v) configPath = %q, want %q", args, configPath, path)
		}
		if settings.Server != "https://example.com:8443" {
			t.Errorf("settingsFor(%v) server = %q", args, settings.Server)
		}
	}
}

func TestSettingsForDefaultsToDefaultConfigFile(t *testing.T) {
	_, configPath := settingsFor(nil)
	if configPath != client.DefaultConfigFile() {
		t.Errorf("settingsFor(nil) configPath = %q, want %q", configPath, client.DefaultConfigFile())
	}
}

func TestCollectedInfoWithoutCommandReturnsBuiltinInfo(t *testing.T) {
	info, err := collectedInfo("")
	if err != nil {
		t.Fatalf("collectedInfo(\"\") error = %v", err)
	}
	if info.OS == "" {
		t.Errorf("collectedInfo(\"\") returned empty OS field, want BuiltinInfo()'s runtime.GOOS")
	}
}

func TestCollectedInfoMergesCommandOutput(t *testing.T) {
	info, err := collectedInfo(`echo '{"team":"platform"}'`)
	if err != nil {
		t.Fatalf("collectedInfo() error = %v", err)
	}
	if info.Extra["team"] != "platform" {
		t.Errorf("collectedInfo() Extra = %+v, want team=platform", info.Extra)
	}
}

func TestCollectedInfoWrapsCommandError(t *testing.T) {
	_, err := collectedInfo("exit 1")
	if err == nil || !strings.Contains(err.Error(), "collect-exec") {
		t.Fatalf("collectedInfo() error = %v, want a wrapped collect-exec error", err)
	}
}

func TestKeygenWritesIdentity(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "id_ed25519")
	var stdout, stderr bytes.Buffer
	u := ui.New(&stdout, &stderr, true)

	keygen([]string{"-o", out}, u)

	if _, err := os.Stat(out); err != nil {
		t.Errorf("private key not written: %v", err)
	}
	pub, err := os.ReadFile(out + ".pub")
	if err != nil {
		t.Fatalf("public key not written: %v", err)
	}
	if !strings.HasPrefix(string(pub), "ssh-ed25519 ") {
		t.Errorf("public key = %q, want an ssh-ed25519 OpenSSH line", pub)
	}
	if !strings.Contains(stdout.String(), "Fingerprint:") {
		t.Errorf("keygen output = %q, want a Fingerprint line", stdout.String())
	}
}

// TestTrustPromptWithoutTerminalDenies exercises trustPrompt's no-TTY path,
// which is what every non-interactive invocation (CI, a piped ntwire
// connect) actually hits: without a terminal to confirm on, it must fail
// closed rather than block reading stdin or silently trust the certificate.
func TestTrustPromptWithoutTerminalDenies(t *testing.T) {
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		t.Skip("stdin is a terminal in this environment; the no-TTY path isn't exercised here")
	}
	e := &client.UnknownCertificateError{Host: "server.example", Fingerprint: "SHA256:abc"}
	if trustPrompt(e, filepath.Join(t.TempDir(), "known_servers")) {
		t.Fatal("trustPrompt() = true without a terminal, want false (fail closed)")
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1153433, "1.1 MiB"},
		{1 << 40, "1.0 TiB"},
	}
	for _, c := range cases {
		if got := formatBytes(c.n); got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestConnsAndTrafficSummary(t *testing.T) {
	s := client.TunnelStats{Active: 3, Connections: 12, BytesFromTunnel: 1153433, BytesToTunnel: 4404019}
	if got, want := connsSummary(s), "3/12"; got != want {
		t.Errorf("connsSummary() = %q, want %q", got, want)
	}
	if got, want := trafficSummary(s), "1.1 MiB in / 4.2 MiB out"; got != want {
		t.Errorf("trafficSummary() = %q, want %q", got, want)
	}
}

// TestListEntryJSONOmitsLiveFieldsWhenNotConnected checks that a tunnel
// with no matching live status marshals without a "stats" field, rather
// than a misleading zero-valued one -- callers should be able to tell
// "not connected" apart from "connected with zero traffic" by field
// presence alone.
func TestListEntryJSONOmitsLiveFieldsWhenNotConnected(t *testing.T) {
	e := listEntry{Name: "reports", VirtualPort: 51001, Description: "Reporting DB"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	got := string(b)
	if strings.Contains(got, `"stats"`) {
		t.Errorf("Marshal() = %s, want no \"stats\" field for a disconnected tunnel", got)
	}
	if !strings.Contains(got, `"connected":false`) {
		t.Errorf("Marshal() = %s, want \"connected\":false", got)
	}
}

// TestStatusJSONOmitsWebStatusWhenUnavailable checks that statusJSON's
// embedded *client.WebStatus, when left nil (the live status UI could not
// be reached), disappears entirely from the marshaled output instead of
// contributing zero-valued "connected"/"ttl_seconds"/etc. fields that would
// look like real data.
func TestStatusJSONOmitsWebStatusWhenUnavailable(t *testing.T) {
	out := statusJSON{Status: client.Status{PID: 123, Server: "https://example.com:8443"}}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	got := string(b)
	for _, field := range []string{"connected", "connection_type", "ttl_seconds", "latency_millis", "reconnections", "tunnels"} {
		if strings.Contains(got, `"`+field+`"`) {
			t.Errorf("Marshal() = %s, want no %q field when WebStatus is nil", got, field)
		}
	}
	if !strings.Contains(got, `"pid":123`) {
		t.Errorf("Marshal() = %s, want \"pid\":123", got)
	}
}

// TestListColumnsFitLiveStats renders list()'s table with realistic and
// near-worst-case live stats and checks that DESCRIPTION starts at the
// same column offset on every row -- the failure mode a too-narrow STATS
// column previously produced (a long CONNS/TRAFFIC value overflowed its
// padded width and pushed DESCRIPTION out of alignment on that row only).
func TestListColumnsFitLiveStats(t *testing.T) {
	rows := [][]string{
		{"reports", "51001", "8080", "connected", connsSummary(client.TunnelStats{Active: 3, Connections: 12}),
			trafficSummary(client.TunnelStats{BytesFromTunnel: 1153433, BytesToTunnel: 4404019}), "Reporting DB"},
		{"admin", "51002", "8081", "-", "-", "-", "Admin panel"},
		{"huge-tunnel", "9", "-", "connected", connsSummary(client.TunnelStats{Active: 999, Connections: 99999}),
			trafficSummary(client.TunnelStats{BytesFromTunnel: (1 << 40) * 999, BytesToTunnel: (1 << 40) * 999}), "Worst case"},
	}
	tbl := ui.Table{Columns: listColumns(), Rows: rows}

	var out bytes.Buffer
	u := ui.New(&out, &out, true) // --no-color
	got := tbl.Render(u)

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != len(rows) {
		t.Fatalf("Render() produced %d lines, want %d:\n%s", len(lines), len(rows), got)
	}
	var descOffset = -1
	for i, line := range lines {
		want := rows[i][len(rows[i])-1] // DESCRIPTION is the last field
		idx := strings.Index(line, want)
		if idx < 0 {
			t.Fatalf("line %d %q does not contain description %q", i, line, want)
		}
		if descOffset == -1 {
			descOffset = idx
		} else if idx != descOffset {
			t.Errorf("line %d: DESCRIPTION starts at column %d, want %d (misaligned):\n%s", i, idx, descOffset, got)
		}
	}
}

func TestResolveIdentityKey(t *testing.T) {
	defaultKey := func() string { return "/home/x/.ntwire/id_ed25519" }
	cases := []struct {
		name string
		key  string
		sso  bool
		want string
	}{
		{"empty key, no sso, falls back to default", "", false, "/home/x/.ntwire/id_ed25519"},
		{"empty key, sso, stays empty", "", true, ""},
		{"explicit key wins over default", "/other/key", false, "/other/key"},
		{"explicit key kept even with sso", "/other/key", true, "/other/key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveIdentityKey(c.key, c.sso, defaultKey); got != c.want {
				t.Errorf("resolveIdentityKey(%q, %v) = %q, want %q", c.key, c.sso, got, c.want)
			}
		})
	}
}

func TestMergePorts(t *testing.T) {
	cases := []struct {
		name          string
		settingsPort  map[string]int
		settingsHosts map[string]string
		mappings      []string
		want          map[string]int
		wantHosts     map[string]string
		wantErr       bool
	}{
		{
			name:     "two repeated --port mappings both present",
			mappings: []string{"a=1", "b=2"},
			want:     map[string]int{"a": 1, "b": 2},
		},
		{
			name:         "explicit --port overrides same-named settings entry, others kept",
			settingsPort: map[string]int{"db": 9, "web": 8},
			mappings:     []string{"db=1"},
			want:         map[string]int{"db": 1, "web": 8},
		},
		{
			name: "no settings, no mappings, empty map not nil",
			want: map[string]int{},
		},
		{
			name:     "missing '=' is an error",
			mappings: []string{"bad"},
			wantErr:  true,
		},
		{
			name:     "port 0 is out of range",
			mappings: []string{"a=0"},
			wantErr:  true,
		},
		{
			name:     "port 70000 is out of range",
			mappings: []string{"a=70000"},
			wantErr:  true,
		},
		{
			name:     "non-numeric port is an error",
			mappings: []string{"a=notaport"},
			wantErr:  true,
		},
		{
			name:      "host:port sets both port and host",
			mappings:  []string{"db=127.70.0.1:5432"},
			want:      map[string]int{"db": 5432},
			wantHosts: map[string]string{"db": "127.70.0.1"},
		},
		{
			name:      "IPv6 host:port",
			mappings:  []string{"db=[::1]:5432"},
			want:      map[string]int{"db": 5432},
			wantHosts: map[string]string{"db": "::1"},
		},
		{
			name:          "port-only mapping leaves an existing settings host untouched",
			settingsHosts: map[string]string{"db": "127.70.0.1"},
			mappings:      []string{"db=5432"},
			want:          map[string]int{"db": 5432},
			wantHosts:     map[string]string{"db": "127.70.0.1"},
		},
		{
			name:          "host:port overrides a same-named settings host",
			settingsHosts: map[string]string{"db": "127.70.0.1"},
			mappings:      []string{"db=127.71.0.1:5432"},
			want:          map[string]int{"db": 5432},
			wantHosts:     map[string]string{"db": "127.71.0.1"},
		},
		{
			name:     "bare host with no port is ambiguous",
			mappings: []string{"db=127.70.0.1"},
			wantErr:  true,
		},
		{
			name:     "host:0 is out of range like bare 0",
			mappings: []string{"db=127.70.0.1:0"},
			wantErr:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, gotHosts, err := mergePorts(c.settingsPort, c.settingsHosts, c.mappings)
			if c.wantErr {
				if err == nil {
					t.Fatalf("mergePorts(%v, %v, %v) = %v, %v, nil; want error", c.settingsPort, c.settingsHosts, c.mappings, got, gotHosts)
				}
				return
			}
			if err != nil {
				t.Fatalf("mergePorts(%v, %v, %v) unexpected error: %v", c.settingsPort, c.settingsHosts, c.mappings, err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("mergePorts(%v, %v, %v) = %v, want %v", c.settingsPort, c.settingsHosts, c.mappings, got, c.want)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("mergePorts(%v, %v, %v)[%q] = %d, want %d", c.settingsPort, c.settingsHosts, c.mappings, k, got[k], v)
				}
			}
			if len(gotHosts) != len(c.wantHosts) {
				t.Fatalf("mergePorts(%v, %v, %v) hosts = %v, want %v", c.settingsPort, c.settingsHosts, c.mappings, gotHosts, c.wantHosts)
			}
			for k, v := range c.wantHosts {
				if gotHosts[k] != v {
					t.Errorf("mergePorts(%v, %v, %v) hosts[%q] = %q, want %q", c.settingsPort, c.settingsHosts, c.mappings, k, gotHosts[k], v)
				}
			}
		})
	}
}
