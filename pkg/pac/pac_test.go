package pac

import (
	"strings"
	"testing"
)

func TestPACGenerate_DefaultPort(t *testing.T) {
	content := Generate("", 0, nil, nil)
	if !strings.Contains(content, "127.0.0.1:10080") {
		t.Errorf("expected default port 10080 in PAC content, got: %s", content)
	}
	if !strings.Contains(content, "function FindProxyForURL(url, host)") {
		t.Errorf("missing FindProxyForURL in PAC content")
	}
	if !strings.Contains(content, "return \"DIRECT\";") {
		t.Errorf("missing DIRECT return in PAC content")
	}
}

func TestPACGenerate_IOSHost(t *testing.T) {
	content := Generate("100.64.0.1", 10080, nil, nil)
	if !strings.Contains(content, "SOCKS5 100.64.0.1:10080") {
		t.Errorf("expected 100.64.0.1:10080 in iOS PAC content, got: %s", content)
	}
	if strings.Contains(content, "127.0.0.1") {
		t.Errorf("did not expect 127.0.0.1 in iOS PAC content, got: %s", content)
	}
}

func TestPACGenerate_CustomPortAndFilters(t *testing.T) {
	domainFilters := []string{".custom.internal", "mycluster.local"}
	ipFilters := []string{"10.50.0.0/16"}
	content := Generate("", 18080, domainFilters, ipFilters)

	if !strings.Contains(content, "127.0.0.1:18080") {
		t.Errorf("expected port 18080 in PAC content, got: %s", content)
	}
	if !strings.Contains(content, "shExpMatch(host, \"*.custom.internal\")") {
		t.Errorf("missing domain filter in PAC content")
	}
	if !strings.Contains(content, "isInNet(resolved_ip, \"10.50.0.0\", \"255.255.0.0\")") {
		t.Errorf("missing IP filter in PAC content")
	}
}

func TestPACGenerate_IOSCompatibility(t *testing.T) {
	content := Generate("100.64.0.1", 10080, nil, nil)

	// Check iOS pattern matching keywords
	iosKeywords := []string{
		"shExpMatch(host, \"*.svc\")",
		"shExpMatch(host, \"*.cluster.local\")",
		"shExpMatch(host, \"*.local\")",
		"shExpMatch(host, \"*.internal\")",
		"isPlainHostName(host)",
		"!isResolvable(host)",
		"dnsResolve(host)",
		"isInNet(resolved_ip, \"10.0.0.0\", \"255.0.0.0\")",
		"isInNet(resolved_ip, \"172.16.0.0\", \"255.240.0.0\")",
		"isInNet(resolved_ip, \"192.168.0.0\", \"255.255.0.0\")",
		"isInNet(resolved_ip, \"127.0.0.0\", \"255.0.0.0\")",
		"isInNet(resolved_ip, \"100.64.0.0\", \"255.192.0.0\")",
		"isInNet(resolved_ip, \"169.254.0.0\", \"255.255.0.0\")",
		"SOCKS5",
		"SOCKS",
		"DIRECT",
	}

	for _, kw := range iosKeywords {
		if !strings.Contains(content, kw) {
			t.Errorf("PAC content missing iOS/k8s keyword: %q", kw)
		}
	}
}

func TestPACPathAndURL(t *testing.T) {
	tests := []struct {
		target   string
		baseURL  string
		wantPath string
		wantURL  string
	}{
		{"", "https://server.example:8443", "/proxy.pac", "https://server.example:8443/proxy.pac"},
		{"egress", "https://server.example:8443", "/proxy-egress.pac", "https://server.example:8443/proxy-egress.pac"},
		{"my-target", "https://server.example:8443/", "/proxy-my-target.pac", "https://server.example:8443/proxy-my-target.pac"},
		{"", "", "/proxy.pac", "/proxy.pac"},
		{"custom", "", "/proxy-custom.pac", "/proxy-custom.pac"},
	}

	for _, tt := range tests {
		gotPath := Path(tt.target)
		if gotPath != tt.wantPath {
			t.Errorf("Path(%q) = %q, want %q", tt.target, gotPath, tt.wantPath)
		}
		gotURL := URL(tt.baseURL, tt.target)
		if gotURL != tt.wantURL {
			t.Errorf("URL(%q, %q) = %q, want %q", tt.baseURL, tt.target, gotURL, tt.wantURL)
		}
	}
}

func TestPACPathForPlatform(t *testing.T) {
	tests := []struct {
		target   string
		isIOS    bool
		wantPath string
	}{
		{"", false, "/proxy.pac"},
		{"egress", false, "/proxy-egress.pac"},
		{"", true, "/proxy-ios.pac"},
		{"egress", true, "/proxy-ios-egress.pac"},
		{"mytarget", true, "/proxy-ios-mytarget.pac"},
	}

	for _, tt := range tests {
		got := PathForPlatform(tt.target, tt.isIOS)
		if got != tt.wantPath {
			t.Errorf("PathForPlatform(%q, %v) = %q, want %q", tt.target, tt.isIOS, got, tt.wantPath)
		}
	}
}
