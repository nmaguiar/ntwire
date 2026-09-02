package portal

import (
	"net/http"
	"strings"
	"testing"
)

func TestDetectBrowserContext(t *testing.T) {
	cases := []struct {
		name, ua, os, browser string
		mobile                bool
	}{
		{"iphone safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Mobile Safari/604.1", "ios", "safari", true},
		{"ipad safari", "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Version/17.0 Mobile Safari/604.1", "ipados", "safari", true},
		{"mac safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Version/17.0 Safari/605.1.15", "macos", "safari", false},
		{"mac chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/120.0 Safari/537.36", "macos", "chrome", false},
		{"windows edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/120.0", "windows", "edge", false},
		{"windows chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36", "windows", "chrome", false},
		{"linux firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Firefox/120.0", "linux", "firefox", false},
		{"android chrome", "Mozilla/5.0 (Linux; Android 14) Chrome/120.0 Mobile Safari/537.36", "android", "chrome", true},
		{"unknown", "unrecognised", "unknown", "unknown", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectBrowserContext(http.Header{"User-Agent": []string{tc.ua}})
			if got.OS != tc.os || got.Browser != tc.browser || got.Mobile != tc.mobile {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestClientTemplateAliasesAndOverrideDoNotChangeCapabilities(t *testing.T) {
	c := NormalizeClient(ClientContext{OS: "darwin", Type: "wireguard", Capabilities: ClientCapabilities{NativeWireGuard: true}}, "wireguard")
	c = c.WithViewOS("windows")
	if !c.Override || c.ViewOS != "windows" || c.Capabilities.LocalPorts {
		t.Fatalf("unsafe override: %+v", c)
	}
	out, err := RenderTemplate(`{{if eq .Client.ViewOS "windows"}}windows{{end}} {{if .Client.Capabilities.LocalPorts}}local{{else}}tunnel{{end}}`, &PortalContext{Client: c})
	if err != nil || strings.TrimSpace(out) != "windows tunnel" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}
