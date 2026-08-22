package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerPAC_SingleSocksTunnel(t *testing.T) {
	c := Config{
		Tunnels: []TunnelConfig{
			{
				Name:        "egress",
				Target:      "socks",
				VirtualPort: 10080,
				LocalPort:   10080,
				Socks: &SocksConfig{
					DomainFilters: []string{".k8s.internal"},
					Filters:       []string{"10.0.0.0/8"},
				},
			},
			{
				Name:        "web",
				Target:      "127.0.0.1:8080",
				VirtualPort: 18080,
			},
		},
	}

	s := New(c, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// 1. GET /proxy.pac without authentication (Desktop)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "127.0.0.1:10080") {
		t.Errorf("PAC body missing port 10080: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "shExpMatch(host, \"*.k8s.internal\")") {
		t.Errorf("PAC body missing domain filter: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "FindProxyForURL") {
		t.Errorf("PAC body missing FindProxyForURL: %s", bodyStr)
	}

	// 2. GET /proxy-egress.pac without authentication
	respNamed, err := http.Get(ts.URL + "/proxy-egress.pac")
	if err != nil {
		t.Fatalf("GET /proxy-egress.pac failed: %v", err)
	}
	defer respNamed.Body.Close()

	if respNamed.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy-egress.pac status = %d, want 200", respNamed.StatusCode)
	}

	// 3. GET /proxy-ios.pac (iOS tunnel IP 100.64.0.1)
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

	// 4. GET /proxy.ios.pac alias
	respIOSAlias, err := http.Get(ts.URL + "/proxy.ios.pac")
	if err != nil {
		t.Fatalf("GET /proxy.ios.pac failed: %v", err)
	}
	defer respIOSAlias.Body.Close()
	if respIOSAlias.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy.ios.pac status = %d, want 200", respIOSAlias.StatusCode)
	}

	// 5. GET /proxy.pac?ios
	respIOSQuery, err := http.Get(ts.URL + "/proxy.pac?ios")
	if err != nil {
		t.Fatalf("GET /proxy.pac?ios failed: %v", err)
	}
	defer respIOSQuery.Body.Close()
	bodyQuery, _ := io.ReadAll(respIOSQuery.Body)
	if !strings.Contains(string(bodyQuery), "100.64.0.1:10080") {
		t.Errorf("expected 100.64.0.1:10080 in /proxy.pac?ios, got: %s", string(bodyQuery))
	}

	// 6. GET /proxy-nonexistent.pac returns 404
	respMissing, err := http.Get(ts.URL + "/proxy-nonexistent.pac")
	if err != nil {
		t.Fatalf("GET /proxy-nonexistent.pac failed: %v", err)
	}
	defer respMissing.Body.Close()

	if respMissing.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /proxy-nonexistent.pac status = %d, want 404", respMissing.StatusCode)
	}
}

func TestServerPAC_MultipleSocksTunnels(t *testing.T) {
	c := Config{
		Tunnels: []TunnelConfig{
			{
				Name:        "egress-main",
				Target:      "socks",
				VirtualPort: 10080,
				LocalPort:   10080,
				Socks:       &SocksConfig{},
			},
			{
				Name:        "mytarget",
				Target:      "socks",
				VirtualPort: 10081,
				LocalPort:   10081,
				Socks: &SocksConfig{
					DomainFilters: []string{"custom.internal"},
				},
			},
		},
	}

	s := New(c, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// GET /proxy.pac returns default (first: egress-main on 10080)
	resp, err := http.Get(ts.URL + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "127.0.0.1:10080") {
		t.Errorf("expected port 10080 in default /proxy.pac, got: %s", string(body))
	}

	// GET /proxy-mytarget.pac returns mytarget on 10081 with domain filter
	respTarget, err := http.Get(ts.URL + "/proxy-mytarget.pac")
	if err != nil {
		t.Fatalf("GET /proxy-mytarget.pac failed: %v", err)
	}
	defer respTarget.Body.Close()
	bodyTarget, _ := io.ReadAll(respTarget.Body)
	if !strings.Contains(string(bodyTarget), "127.0.0.1:10081") {
		t.Errorf("expected port 10081 in /proxy-mytarget.pac, got: %s", string(bodyTarget))
	}
	if !strings.Contains(string(bodyTarget), "custom.internal") {
		t.Errorf("expected custom.internal in /proxy-mytarget.pac, got: %s", string(bodyTarget))
	}

	// GET /proxy-ios-mytarget.pac returns mytarget on 100.64.0.1:10081
	respIOSTarget, err := http.Get(ts.URL + "/proxy-ios-mytarget.pac")
	if err != nil {
		t.Fatalf("GET /proxy-ios-mytarget.pac failed: %v", err)
	}
	defer respIOSTarget.Body.Close()
	bodyIOSTarget, _ := io.ReadAll(respIOSTarget.Body)
	if !strings.Contains(string(bodyIOSTarget), "100.64.0.1:10081") {
		t.Errorf("expected 100.64.0.1:10081 in /proxy-ios-mytarget.pac, got: %s", string(bodyIOSTarget))
	}
}

func TestServerPAC_NoSocksTunnels(t *testing.T) {
	c := Config{
		Tunnels: []TunnelConfig{
			{
				Name:        "web",
				Target:      "127.0.0.1:8080",
				VirtualPort: 18080,
			},
		},
	}

	s := New(c, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// When no socks tunnels exist, /proxy.pac returns 404
	resp, err := http.Get(ts.URL + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /proxy.pac status = %d, want 404", resp.StatusCode)
	}
}
