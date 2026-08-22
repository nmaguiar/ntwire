package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func TestPrintWireGuardConfig_Conf(t *testing.T) {
	var stdout, stderr bytes.Buffer
	u := ui.New(&stdout, &stderr, true)

	c := server.Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	c.Listen.WireGuard = ":51820"

	code := printWireGuardConfig(c, "conf", server.WireGuardClientOptions{}, u)
	if code != 0 {
		t.Fatalf("printWireGuardConfig returned code %d, stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "[Interface]") || !strings.Contains(out, "[Peer]") {
		t.Errorf("expected WireGuard conf output, got:\n%s", out)
	}
	if !strings.Contains(out, "Address = 100.64.0.2/32") {
		t.Errorf("expected client address 100.64.0.2/32, got:\n%s", out)
	}
	if !strings.Contains(out, "AllowedIPs = 100.64.0.0/16") {
		t.Errorf("expected allowed IPs 100.64.0.0/16, got:\n%s", out)
	}
}

func TestPrintWireGuardConfig_QR(t *testing.T) {
	var stdout, stderr bytes.Buffer
	u := ui.New(&stdout, &stderr, true)

	c := server.Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	c.Listen.WireGuard = ":51820"

	code := printWireGuardConfig(c, "qr", server.WireGuardClientOptions{}, u)
	if code != 0 {
		t.Fatalf("printWireGuardConfig returned code %d, stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if len(strings.TrimSpace(out)) == 0 {
		t.Errorf("expected non-empty QR code output")
	}
}

func TestPrintWireGuardConfig_All(t *testing.T) {
	var stdout, stderr bytes.Buffer
	u := ui.New(&stdout, &stderr, true)

	c := server.Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	c.Listen.WireGuard = ":51820"

	code := printWireGuardConfig(c, "all", server.WireGuardClientOptions{}, u)
	if code != 0 {
		t.Fatalf("printWireGuardConfig returned code %d, stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "[Interface]") || !strings.Contains(out, "[Peer]") {
		t.Errorf("expected .conf in 'all' output, got:\n%s", out)
	}
	if !strings.Contains(out, "QR code") {
		t.Errorf("expected QR code section in 'all' output, got:\n%s", out)
	}
}

func TestPrintWireGuardConfig_InvalidFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	u := ui.New(&stdout, &stderr, true)

	c := server.Config{}
	code := printWireGuardConfig(c, "invalid", server.WireGuardClientOptions{}, u)
	if code != 2 {
		t.Errorf("expected code 2 for invalid format, got %d", code)
	}
}

func TestServerCompletion(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(sh, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			u := ui.New(&stdout, &stderr, true)
			runCompletion([]string{sh}, u)
			if stderr.Len() > 0 {
				t.Fatalf("runCompletion(%q) unexpected stderr: %s", sh, stderr.String())
			}
			if !strings.Contains(stdout.String(), "ntwire-server") {
				t.Errorf("runCompletion(%q) stdout does not contain ntwire-server", sh)
			}
		})
	}
}

func TestPrintServerList_TableAndJSON(t *testing.T) {
	c := server.Config{
		Tunnels: []server.TunnelConfig{
			{
				Name:        "reports",
				Target:      "127.0.0.1:8080",
				VirtualPort: 18080,
				LocalPort:   8080,
				Allow:       []string{"*"},
				Description: "Reports UI",
			},
			{
				Name:        "egress",
				Target:      "socks",
				VirtualPort: 10080,
				LocalPort:   10080,
				Allow:       []string{"group:eng"},
				Description: "Internal SOCKS",
				Socks:       &server.SocksConfig{},
			},
			{
				Name:        "mytarget",
				Target:      "socks",
				VirtualPort: 10081,
				LocalPort:   10081,
				Allow:       []string{"group:eng"},
				Description: "Custom SOCKS",
				Socks:       &server.SocksConfig{},
			},
		},
	}

	// 1. Table format
	var stdoutTable, stderrTable bytes.Buffer
	uTable := ui.New(&stdoutTable, &stderrTable, true)
	printServerList(c, false, uTable)

	outTable := stdoutTable.String()
	if !strings.Contains(outTable, "reports") || !strings.Contains(outTable, "egress") || !strings.Contains(outTable, "mytarget") {
		t.Errorf("table output missing tunnels: %s", outTable)
	}
	if !strings.Contains(outTable, "Proxy PAC URLs (Desktop):") || !strings.Contains(outTable, "Proxy PAC URLs (iOS):") {
		t.Errorf("table output missing Proxy PAC URLs: %s", outTable)
	}
	if !strings.Contains(outTable, "/proxy.pac") || !strings.Contains(outTable, "/proxy-mytarget.pac") || !strings.Contains(outTable, "/proxy-ios.pac") {
		t.Errorf("table output missing PAC paths: %s", outTable)
	}

	// 2. JSON format
	var stdoutJSON, stderrJSON bytes.Buffer
	uJSON := ui.New(&stdoutJSON, &stderrJSON, true)
	printServerList(c, true, uJSON)

	outJSON := stdoutJSON.String()
	if !strings.Contains(outJSON, `"pac_url": "/proxy-egress.pac"`) {
		t.Errorf("JSON output missing egress pac_url: %s", outJSON)
	}
	if !strings.Contains(outJSON, `"pac_url_ios": "/proxy-ios-egress.pac"`) {
		t.Errorf("JSON output missing egress pac_url_ios: %s", outJSON)
	}
	if !strings.Contains(outJSON, `"pac_url": "/proxy-mytarget.pac"`) {
		t.Errorf("JSON output missing mytarget pac_url: %s", outJSON)
	}
	if !strings.Contains(outJSON, `"/proxy.pac"`) || !strings.Contains(outJSON, `"/proxy-ios.pac"`) {
		t.Errorf("JSON output missing pac_urls list: %s", outJSON)
	}
}
