package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestRelayPAC_NoRegisteredAgents(t *testing.T) {
	as := newAgentServer(NewRegistry(nil, Limits{}), "example.com", Limits{}, nil)
	ts := httptest.NewServer(as.Handler())
	defer ts.Close()

	// When no agents with socks targets are registered, /proxy.pac returns 404
	resp, err := http.Get(ts.URL + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /proxy.pac status = %d, want 404", resp.StatusCode)
	}
}

func TestRelayPAC_WithRegisteredSocksTargets(t *testing.T) {
	as := newAgentServer(NewRegistry(nil, Limits{}), "example.com", Limits{}, nil)
	as.mu.Lock()
	as.socksTargets["home"] = []protocol.SocksTarget{
		{
			Name:        "egress",
			LocalPort:   10080,
			VirtualPort: 10080,
			TunnelIP:    "100.64.0.1",
		},
		{
			Name:          "mytarget",
			LocalPort:     10081,
			VirtualPort:   10081,
			TunnelIP:      "100.64.0.1",
			DomainFilters: []string{"custom.internal"},
		},
	}
	as.mu.Unlock()

	ts := httptest.NewServer(as.Handler())
	defer ts.Close()

	// 1. GET /proxy.pac returns default (first: egress)
	resp, err := http.Get(ts.URL + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy.pac status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ns-proxy-autoconfig" {
		t.Errorf("GET /proxy.pac Content-Type = %q, want application/x-ns-proxy-autoconfig", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "127.0.0.1:10080") {
		t.Errorf("PAC body missing port 10080: %s", string(body))
	}

	// 2. GET /proxy-mytarget.pac returns mytarget
	respTarget, err := http.Get(ts.URL + "/proxy-mytarget.pac")
	if err != nil {
		t.Fatalf("GET /proxy-mytarget.pac failed: %v", err)
	}
	defer respTarget.Body.Close()

	if respTarget.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy-mytarget.pac status = %d, want 200", respTarget.StatusCode)
	}
	bodyTarget, _ := io.ReadAll(respTarget.Body)
	if !strings.Contains(string(bodyTarget), "127.0.0.1:10081") {
		t.Errorf("PAC body missing port 10081: %s", string(bodyTarget))
	}
	if !strings.Contains(string(bodyTarget), "custom.internal") {
		t.Errorf("PAC body missing custom.internal: %s", string(bodyTarget))
	}

	// 3. GET /proxy-ios.pac returns default iOS PAC (100.64.0.1:10080)
	respIOS, err := http.Get(ts.URL + "/proxy-ios.pac")
	if err != nil {
		t.Fatalf("GET /proxy-ios.pac failed: %v", err)
	}
	defer respIOS.Body.Close()
	if respIOS.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy-ios.pac status = %d, want 200", respIOS.StatusCode)
	}
	bodyIOS, _ := io.ReadAll(respIOS.Body)
	if !strings.Contains(string(bodyIOS), "100.64.0.1:10080") {
		t.Errorf("expected 100.64.0.1:10080 in iOS PAC, got: %s", string(bodyIOS))
	}

	// 4. GET /proxy-ios-mytarget.pac
	respIOSTarget, err := http.Get(ts.URL + "/proxy-ios-mytarget.pac")
	if err != nil {
		t.Fatalf("GET /proxy-ios-mytarget.pac failed: %v", err)
	}
	defer respIOSTarget.Body.Close()
	bodyIOSTarget, _ := io.ReadAll(respIOSTarget.Body)
	if !strings.Contains(string(bodyIOSTarget), "100.64.0.1:10081") {
		t.Errorf("expected 100.64.0.1:10081 in /proxy-ios-mytarget.pac, got: %s", string(bodyIOSTarget))
	}

	// 5. GET /proxy-unknown.pac returns 404
	respMissing, err := http.Get(ts.URL + "/proxy-unknown.pac")
	if err != nil {
		t.Fatalf("GET /proxy-unknown.pac failed: %v", err)
	}
	defer respMissing.Body.Close()

	if respMissing.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /proxy-unknown.pac status = %d, want 404", respMissing.StatusCode)
	}
}
