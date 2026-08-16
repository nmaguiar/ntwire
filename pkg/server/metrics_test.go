package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestMetricsHandlerExposesMetrics(t *testing.T) {
	s := New(Config{Tunnels: []TunnelConfig{{Name: "reports"}, {Name: "admin"}}}, nil)
	s.sessions.Create(CreateParams{
		Method: "oidc", Identity: `alice@example.com`, TunnelIP: "100.64.0.2",
		Tunnels: []protocol.Tunnel{{Name: "reports"}}, LatencyMillis: 24, Reconnections: 3, TTL: time.Minute,
	})
	stats := s.statsFor("100.64.0.2", "reports")
	stats.toTarget.Add(150)
	stats.fromTarget.Add(4200)
	stats.active.Add(1)
	s.observe("authentication_success", "oidc")
	s.observe("session_created", "oidc")
	s.observe("configuration_reloaded", "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	s.MetricsHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE ntwire_sessions gauge",
		"ntwire_sessions 1",
		"ntwire_tunnels_configured 2",
		`ntwire_session_tunnels{method="oidc"} 1`,
		`ntwire_session_latency_milliseconds_sum{method="oidc"} 24`,
		`ntwire_session_latency_milliseconds_count{method="oidc"} 1`,
		`ntwire_session_reconnections{method="oidc"} 3`,
		`ntwire_tunnel_bytes_to_target_total{tunnel="reports",method="oidc"} 150`,
		`ntwire_tunnel_bytes_from_target_total{tunnel="reports",method="oidc"} 4200`,
		`ntwire_tunnel_connections_active{tunnel="reports",method="oidc"} 1`,
		`ntwire_lifecycle_events_total{event="authentication_success",method="oidc"} 1`,
		`ntwire_lifecycle_events_total{event="configuration_reloaded",method="unknown"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "alice@example.com") {
		t.Fatalf("metrics leaked identity:\n%s", body)
	}
	if strings.Contains(body, "session_id") || strings.Contains(body, "reports.internal") {
		t.Fatalf("metrics leaked sensitive or unbounded value:\n%s", body)
	}
}

func TestMetricsHandlerOnlyServesMetrics(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrica", nil)
	New(Config{}, nil).MetricsHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
