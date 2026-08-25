package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/portal"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestPortal_AuthorizationIsolation(t *testing.T) {
	s := New(Config{
		Portal: portal.PortalConfig{
			Enabled: true,
			Title:   "Engineering Portal",
			Variables: map[string]string{
				"env": "Staging",
			},
		},
		Tunnels: []TunnelConfig{
			{
				Name:        "grafana",
				Target:      "grafana.internal:3000",
				Description: "Grafana Dashboards",
				VirtualPort: 3000,
				LocalPort:   3000,
				Portal: &portal.TargetPortalConfig{
					Name:        "Grafana",
					Description: "Production metrics",
					Category:    "Observability",
					URL:         "http://grafana.internal:3000",
				},
			},
			{
				Name:        "postgres",
				Target:      "postgres.internal:5432",
				Description: "PostgreSQL Database",
				VirtualPort: 5432,
				LocalPort:   5432,
				Portal: &portal.TargetPortalConfig{
					Name:        "PostgreSQL",
					Description: "Customer records",
					Category:    "Databases",
				},
			},
			{
				Name:        "linux-ssh",
				Target:      "bastion.internal:22",
				Description: "SSH Bastion",
				VirtualPort: 2222,
				LocalPort:   2222,
				Portal: &portal.TargetPortalConfig{
					Name:        "Linux Bastion",
					Description: "Administrative access",
					Category:    "Administration",
				},
			},
		},
	}, nil)

	// Alice has access to Grafana, PostgreSQL, Linux Bastion
	aliceSession := s.sessions.Create(CreateParams{
		Method:   "ssh",
		Identity: "alice@corp.com",
		TunnelIP: "100.64.0.2",
		Tunnels: []protocol.Tunnel{
			{Name: "grafana", VirtualPort: 3000, LocalPort: 3000},
			{Name: "postgres", VirtualPort: 5432, LocalPort: 5432},
			{Name: "linux-ssh", VirtualPort: 2222, LocalPort: 2222},
		},
		TTL: 15 * time.Minute,
	})

	// Bob has access to Grafana and Linux Bastion only
	bobSession := s.sessions.Create(CreateParams{
		Method:   "ssh",
		Identity: "bob@corp.com",
		TunnelIP: "100.64.0.3",
		Tunnels: []protocol.Tunnel{
			{Name: "grafana", VirtualPort: 3000, LocalPort: 3000},
			{Name: "linux-ssh", VirtualPort: 2222, LocalPort: 2222},
		},
		TTL: 15 * time.Minute,
	})

	handler := s.Handler()

	// 1. Alice requests portal
	reqAlice := httptest.NewRequest(http.MethodGet, "/v1/portal", nil)
	reqAlice.Header.Set("Authorization", "Bearer "+aliceSession.Token)
	recAlice := httptest.NewRecorder()
	handler.ServeHTTP(recAlice, reqAlice)

	if recAlice.Code != http.StatusOK {
		t.Fatalf("Alice /v1/portal returned status %d: %s", recAlice.Code, recAlice.Body.String())
	}

	var alicePortal portal.RenderedPortal
	if err := json.Unmarshal(recAlice.Body.Bytes(), &alicePortal); err != nil {
		t.Fatalf("failed to decode Alice portal JSON: %v", err)
	}

	if len(alicePortal.Context.Targets) != 3 {
		t.Errorf("expected Alice to have 3 targets, got %d", len(alicePortal.Context.Targets))
	}
	if !strings.Contains(alicePortal.Markdown, "PostgreSQL") || !strings.Contains(alicePortal.HTML, "PostgreSQL") {
		t.Errorf("expected PostgreSQL in Alice portal output")
	}
	if !strings.Contains(alicePortal.Markdown, "Databases") || !strings.Contains(alicePortal.HTML, "Databases") {
		t.Errorf("expected Databases category in Alice portal output")
	}

	// 2. Bob requests portal
	reqBob := httptest.NewRequest(http.MethodGet, "/v1/portal", nil)
	reqBob.Header.Set("Authorization", "Bearer "+bobSession.Token)
	recBob := httptest.NewRecorder()
	handler.ServeHTTP(recBob, reqBob)

	if recBob.Code != http.StatusOK {
		t.Fatalf("Bob /v1/portal returned status %d: %s", recBob.Code, recBob.Body.String())
	}

	var bobPortal portal.RenderedPortal
	if err := json.Unmarshal(recBob.Body.Bytes(), &bobPortal); err != nil {
		t.Fatalf("failed to decode Bob portal JSON: %v", err)
	}

	if len(bobPortal.Context.Targets) != 2 {
		t.Errorf("expected Bob to have 2 targets, got %d", len(bobPortal.Context.Targets))
	}

	// STRICT ISOLATION CHECK: Bob must have zero knowledge of PostgreSQL or the Databases category
	for _, target := range bobPortal.Context.Targets {
		if target.ID == "postgres" || target.Name == "PostgreSQL" {
			t.Errorf("CRITICAL SECURITY LEAK: Bob received postgres target in context: %+v", target)
		}
	}
	for _, cat := range bobPortal.Context.Categories {
		if cat.Name == "Databases" {
			t.Errorf("CRITICAL SECURITY LEAK: Bob received empty Databases category in context")
		}
	}
	if strings.Contains(bobPortal.Markdown, "PostgreSQL") || strings.Contains(bobPortal.Markdown, "Databases") {
		t.Errorf("CRITICAL SECURITY LEAK: Bob received postgres in Markdown:\n%s", bobPortal.Markdown)
	}
	if strings.Contains(bobPortal.HTML, "PostgreSQL") || strings.Contains(bobPortal.HTML, "Databases") {
		t.Errorf("CRITICAL SECURITY LEAK: Bob received postgres in HTML:\n%s", bobPortal.HTML)
	}
}

func TestPortal_ActionAuthorization(t *testing.T) {
	s := New(Config{
		Portal: portal.PortalConfig{Enabled: true},
		Tunnels: []TunnelConfig{
			{Name: "grafana", Target: "grafana.internal:3000", VirtualPort: 3000, Portal: &portal.TargetPortalConfig{URL: "https://grafana.internal/dashboards"}},
			{Name: "postgres", Target: "postgres.internal:5432", VirtualPort: 5432},
		},
	}, nil)

	aliceSession := s.sessions.Create(CreateParams{
		Method:   "ssh",
		Identity: "alice",
		Tunnels:  []protocol.Tunnel{{Name: "grafana"}, {Name: "postgres"}},
		TTL:      15 * time.Minute,
	})

	bobSession := s.sessions.Create(CreateParams{
		Method:   "ssh",
		Identity: "bob",
		Tunnels:  []protocol.Tunnel{{Name: "grafana"}},
		TTL:      15 * time.Minute,
	})

	handler := s.Handler()

	// Alice executes action on postgres -> Allowed
	aliceActionReq := httptest.NewRequest(http.MethodPost, "/v1/portal/action", bytes.NewBufferString(`{"action":"open","target_id":"postgres"}`))
	aliceActionReq.Header.Set("Authorization", "Bearer "+aliceSession.Token)
	aliceRec := httptest.NewRecorder()
	handler.ServeHTTP(aliceRec, aliceActionReq)

	if aliceRec.Code != http.StatusOK {
		t.Errorf("Alice action on postgres failed with status %d: %s", aliceRec.Code, aliceRec.Body.String())
	}

	grafanaActionReq := httptest.NewRequest(http.MethodPost, "/v1/portal/action", bytes.NewBufferString(`{"action":"open","target_id":"grafana"}`))
	grafanaActionReq.Header.Set("Authorization", "Bearer "+aliceSession.Token)
	grafanaRec := httptest.NewRecorder()
	handler.ServeHTTP(grafanaRec, grafanaActionReq)
	if grafanaRec.Code != http.StatusOK {
		t.Fatalf("Grafana action failed with status %d: %s", grafanaRec.Code, grafanaRec.Body.String())
	}
	var grafanaResolution portal.ActionResolution
	if err := json.NewDecoder(grafanaRec.Body).Decode(&grafanaResolution); err != nil {
		t.Fatal(err)
	}
	if grafanaResolution.URL != "https://grafana.internal/dashboards" {
		t.Errorf("Grafana action URL = %q", grafanaResolution.URL)
	}

	// Bob executes action on postgres -> Rejected (403)
	bobActionReq := httptest.NewRequest(http.MethodPost, "/v1/portal/action", bytes.NewBufferString(`{"action":"open","target_id":"postgres"}`))
	bobActionReq.Header.Set("Authorization", "Bearer "+bobSession.Token)
	bobRec := httptest.NewRecorder()
	handler.ServeHTTP(bobRec, bobActionReq)

	if bobRec.Code != http.StatusForbidden {
		t.Errorf("Bob action on unauthorized postgres returned status %d, want 403 Forbidden", bobRec.Code)
	}

	// Unknown target action -> Rejected (403)
	unknownActionReq := httptest.NewRequest(http.MethodPost, "/v1/portal/action", bytes.NewBufferString(`{"action":"open","target_id":"nonexistent"}`))
	unknownActionReq.Header.Set("Authorization", "Bearer "+aliceSession.Token)
	unknownRec := httptest.NewRecorder()
	handler.ServeHTTP(unknownRec, unknownActionReq)

	if unknownRec.Code != http.StatusForbidden {
		t.Errorf("Action on nonexistent target returned status %d, want 403 Forbidden", unknownRec.Code)
	}

	invalidActionReq := httptest.NewRequest(http.MethodPost, "/v1/portal/action", bytes.NewBufferString(`{"action":"shell","target_id":"grafana"}`))
	invalidActionReq.Header.Set("Authorization", "Bearer "+aliceSession.Token)
	invalidActionRec := httptest.NewRecorder()
	handler.ServeHTTP(invalidActionRec, invalidActionReq)
	if invalidActionRec.Code != http.StatusBadRequest {
		t.Errorf("unsupported action returned status %d, want 400 Bad Request", invalidActionRec.Code)
	}
}

func TestWireGuardWebPortal_IdentityMappingAndSecurity(t *testing.T) {
	s := New(Config{
		Network: struct {
			TunnelCIDR              string    `yaml:"tunnel_cidr"`
			AdvertisedEndpoint      string    `yaml:"advertised_endpoint"`
			WireGuardPrivateKeyFile string    `yaml:"wireguard_private_key_file"`
			DNS                     DNSConfig `yaml:"dns"`
		}{TunnelCIDR: "100.64.0.0/16"},
		Portal: portal.PortalConfig{
			Enabled: true,
			Title:   "WireGuard Portal",
		},
		Tunnels: []TunnelConfig{
			{Name: "grafana", Target: "grafana.internal:3000", VirtualPort: 3000, Description: "Grafana"},
			{Name: "postgres", Target: "postgres.internal:5432", VirtualPort: 5432, Description: "Postgres"},
		},
		NativeWireGuard: NativeWireGuardConfig{
			Enabled: true,
			Peers: []NativeWireGuardPeer{
				{
					Name:      "alice-laptop",
					TunnelIP:  "100.64.0.10",
					PublicKey: "alice-pubkey",
					Tunnels:   []string{"grafana", "postgres"},
				},
				{
					Name:      "bob-phone",
					TunnelIP:  "100.64.0.20",
					PublicKey: "bob-pubkey",
					Tunnels:   []string{"grafana"},
				},
			},
		},
	}, nil)

	webHandler := s.WireGuardPortalHandler()

	// 1. Request from Alice's WireGuard IP (100.64.0.10)
	reqAlice := httptest.NewRequest(http.MethodGet, "/", nil)
	reqAlice.RemoteAddr = "100.64.0.10:52341"
	recAlice := httptest.NewRecorder()
	webHandler.ServeHTTP(recAlice, reqAlice)

	if recAlice.Code != http.StatusOK {
		t.Fatalf("Alice web portal request failed with status %d: %s", recAlice.Code, recAlice.Body.String())
	}

	aliceBody := recAlice.Body.String()
	if !strings.Contains(aliceBody, "Grafana") || !strings.Contains(aliceBody, "Postgres") {
		t.Errorf("expected Alice to see both Grafana and Postgres, got:\n%s", aliceBody)
	}

	// Check security headers on response
	if recAlice.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("missing Content-Security-Policy header")
	}
	if recAlice.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing or incorrect X-Content-Type-Options header")
	}
	if recAlice.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing or incorrect X-Frame-Options header")
	}

	// 2. Request from Bob's WireGuard IP (100.64.0.20)
	reqBob := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBob.RemoteAddr = "100.64.0.20:41235"
	recBob := httptest.NewRecorder()
	webHandler.ServeHTTP(recBob, reqBob)

	if recBob.Code != http.StatusOK {
		t.Fatalf("Bob web portal request failed with status %d: %s", recBob.Code, recBob.Body.String())
	}

	bobBody := recBob.Body.String()
	if !strings.Contains(bobBody, "Grafana") {
		t.Errorf("expected Bob to see Grafana")
	}
	if strings.Contains(bobBody, "Postgres") {
		t.Errorf("CRITICAL SECURITY LEAK: Bob received Postgres over WireGuard HTTP portal:\n%s", bobBody)
	}

	// 3. Request from unknown WireGuard IP (100.64.0.99) -> Denied 403
	reqUnknown := httptest.NewRequest(http.MethodGet, "/", nil)
	reqUnknown.RemoteAddr = "100.64.0.99:38192"
	recUnknown := httptest.NewRecorder()
	webHandler.ServeHTTP(recUnknown, reqUnknown)

	if recUnknown.Code != http.StatusForbidden {
		t.Errorf("Unknown peer IP request returned status %d, want 403 Forbidden", recUnknown.Code)
	}
}

func parseAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

func discardBody(body io.ReadCloser) {
	if body != nil {
		_, _ = io.Copy(io.Discard, body)
		_ = body.Close()
	}
}
