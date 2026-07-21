package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestDashboardRequiresTokenAndShowsGrantedTunnel(t *testing.T) {
	c := Config{Tunnels: []TunnelConfig{{Name: "reports", Target: "reports.internal:8080", Description: "Reports", VirtualPort: 18080}}}
	c.Admin.WebUIToken = "operator-secret"
	s := New(c, nil)
	s.sessions.Create(CreateParams{Method: "oidc", Identity: "alice@example.com", TunnelIP: "100.64.0.2", Tunnels: []protocol.Tunnel{{Name: "reports", VirtualPort: 18080}}, LatencyMillis: 18, Reconnections: 2, TTL: time.Minute})
	stats := s.statsFor("100.64.0.2", "reports")
	stats.toTarget.Add(42)
	stats.fromTarget.Add(17)
	stats.connections.Add(3)
	stats.active.Add(1)

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
		Tunnels []dashboardTunnel `json:"tunnels"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Tunnels) != 1 || out.Tunnels[0].Identity != "alice@example.com" || out.Tunnels[0].Target != "reports.internal:8080" || out.Tunnels[0].LatencyMillis != 18 || out.Tunnels[0].Reconnections != 2 || out.Tunnels[0].Stats.BytesToTarget != 42 || out.Tunnels[0].Stats.BytesFromTarget != 17 || out.Tunnels[0].Stats.Connections != 3 || out.Tunnels[0].Stats.Active != 1 {
		t.Fatalf("dashboard tunnels = %+v", out.Tunnels)
	}
	control := httptest.NewRecorder()
	s.Handler().ServeHTTP(control, httptest.NewRequest(http.MethodGet, "/v1/dashboard?token=operator-secret", nil))
	if control.Code != http.StatusNotFound {
		t.Fatalf("control API dashboard status = %d, want 404", control.Code)
	}
}
