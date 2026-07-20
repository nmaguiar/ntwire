package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestMetricsHandlerExposesMetrica(t *testing.T) {
	s := New(Config{Tunnels: []TunnelConfig{{Name: "reports"}, {Name: "admin"}}}, nil)
	s.sessions.Create(CreateParams{
		Method: "oidc", Identity: `alice@example.com`,
		Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Minute,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrica", nil)
	s.MetricsHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE ntwire_sessions gauge",
		"ntwire_sessions 1",
		"ntwire_tunnels_configured 2",
		`ntwire_session_tunnels{method="oidc",identity="alice@example.com"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, body)
		}
	}
}

func TestMetricsHandlerOnlyServesMetrica(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	New(Config{}, nil).MetricsHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
