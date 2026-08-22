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
