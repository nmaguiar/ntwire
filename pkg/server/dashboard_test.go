package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestDashboardRequiresTokenAndShowsGrantedTunnel(t *testing.T) {
	c := Config{Tunnels: []TunnelConfig{{Name: "reports", Target: "reports.internal:8080", Description: "Reports", VirtualPort: 18080}, {Name: "egress", Target: "socks", VirtualPort: 18081, Socks: &SocksConfig{AllowAll: true, AllowBind: true}}}}
	c.Authorizer.Exec = "/usr/local/bin/ntwire-authorizer"
	c.Relay.Enabled = true
	c.Relay.AdvertiseDirect = true
	c.Admin.WebUIToken = "operator-secret"
	s := New(c, nil)
	session := s.sessions.Create(CreateParams{Method: "oidc", Identity: "alice@example.com", WireGuardPublicKey: "wg-alice", TunnelIP: "100.64.0.2", Tunnels: []protocol.Tunnel{{Name: "reports", VirtualPort: 18080}}, LatencyMillis: 18, Reconnections: 2, TTL: time.Minute})
	stats := s.statsFor("100.64.0.2", "reports")
	stats.toTarget.Add(42)
	stats.fromTarget.Add(17)
	stats.connections.Add(3)
	stats.active.Add(1)
	s.udpr.Store(&udpRelay{sessions: map[string]*udpRelaySessionState{session.WireGuardPublicKey: {token: "must-not-leak", stats: protocol.RelayUDPStats{Token: "must-not-leak", ClientBytesReceived: 42, ServerBytesForwarded: 41, ServerBytesReceived: 17, ClientBytesForwarded: 16}}}})

	for _, path := range []string{"/", "/v1/dashboard"} {
		rec := httptest.NewRecorder()
		s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/dashboard?token=operator-secret", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Tunnels              []dashboardTunnel `json:"tunnels"`
		SecurityCapabilities []string          `json:"security_capabilities"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tunnels) != 1 || out.Tunnels[0].SessionID == "" || out.Tunnels[0].Identity != "alice@example.com" || out.Tunnels[0].Target != "reports.internal:8080" || out.Tunnels[0].LatencyMillis != 18 || out.Tunnels[0].Reconnections != 2 || out.Tunnels[0].Stats.BytesToTarget != 42 || out.Tunnels[0].Stats.BytesFromTarget != 17 || out.Tunnels[0].Stats.Connections != 3 || out.Tunnels[0].Stats.Active != 1 {
		t.Fatalf("dashboard tunnels = %+v", out.Tunnels)
	}
	if got := out.Tunnels[0].RelayUDP; got == nil || got.ClientBytesReceived != 42 || got.ServerBytesForwarded != 41 || got.ServerBytesReceived != 17 || got.ClientBytesForwarded != 16 {
		t.Fatalf("dashboard relay UDP stats = %+v", got)
	}
	if strings.Contains(rec.Body.String(), "must-not-leak") {
		t.Fatalf("dashboard leaked relay allocation token: %s", rec.Body.String())
	}
	wantCapabilities := []string{"authorization_hook", "direct_udp_relay_bypass", "relay_mediated_udp", "socks_bind", "socks_unrestricted"}
	if !reflect.DeepEqual(out.SecurityCapabilities, wantCapabilities) {
		t.Fatalf("security_capabilities = %v, want %v", out.SecurityCapabilities, wantCapabilities)
	}
	control := httptest.NewRecorder()
	s.Handler().ServeHTTP(control, httptest.NewRequest(http.MethodGet, "/v1/dashboard?token=operator-secret", nil))
	if control.Code != http.StatusNotFound {
		t.Fatalf("control API dashboard status = %d, want 404", control.Code)
	}
}

func TestRevokeSessionRequiresToken(t *testing.T) {
	c := Config{}
	c.Admin.WebUIToken = "operator-secret"
	s := New(c, nil)
	session := s.sessions.Create(CreateParams{Method: "ssh", Identity: "fp", TTL: time.Minute})

	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/admin/sessions/"+session.ID+"/revoke", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 without a token", rec.Code)
	}
	if _, ok := s.sessions.Get(session.Token); !ok {
		t.Fatal("session was revoked despite the missing token")
	}
}

func TestRevokeSessionEndsSessionByID(t *testing.T) {
	c := Config{}
	c.Admin.WebUIToken = "operator-secret"
	s := New(c, nil)
	session := s.sessions.Create(CreateParams{Method: "ssh", Identity: "fp", TTL: time.Minute})

	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/admin/sessions/"+session.ID+"/revoke?token=operator-secret", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if _, ok := s.sessions.Get(session.Token); ok {
		t.Fatal("session still present after revoke")
	}
}

func TestRevokeSessionUnknownIDNotFound(t *testing.T) {
	c := Config{}
	c.Admin.WebUIToken = "operator-secret"
	s := New(c, nil)

	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/admin/sessions/does-not-exist/revoke?token=operator-secret", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown session id", rec.Code)
	}
}

func TestRevokeSessionNotOnPublicControlAPI(t *testing.T) {
	c := Config{}
	c.Admin.WebUIToken = "operator-secret"
	s := New(c, nil)
	session := s.sessions.Create(CreateParams{Method: "ssh", Identity: "fp", TTL: time.Minute})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/admin/sessions/"+session.ID+"/revoke?token=operator-secret", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("control API revoke status = %d, want 404 (admin endpoints stay off the public API)", rec.Code)
	}
}
