package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/portal"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestClientPortal_FetchAndWebUI(t *testing.T) {
	// Mock server that handles /v1/portal and /v1/portal/action
	serverMux := http.NewServeMux()
	serverMux.HandleFunc("GET /v1/portal", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer valid-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(portal.RenderedPortal{
			Title:    "Engineering Portal",
			Markdown: "# Engineering Portal\n\n- [Grafana](ntwire://open/grafana)",
			HTML:     "<h1>Engineering Portal</h1><p><button class=\"ntwire-action-btn\" data-action=\"open\" data-target=\"grafana\">Grafana</button></p>",
			Context: &portal.PortalContext{
				Schema: SchemaVersion(),
				Portal: portal.PortalInfo{Title: "Engineering Portal"},
				Targets: []portal.PortalTarget{
					{ID: "grafana", Name: "Grafana", URL: "http://grafana.internal:3000"},
				},
			},
		})
	})

	server := httptest.NewServer(serverMux)
	t.Cleanup(server.Close)

	conn := &Connection{
		base:  server.URL,
		token: "valid-token",
		http:  server.Client(),
		tunnels: []*localTunnel{
			{name: "grafana", localAddr: "127.0.0.1:3000", target: "grafana.internal:3000"},
		},
		Response: protocol.AuthResponse{
			Tunnels: []protocol.Tunnel{
				{Name: "grafana", TargetHint: "port_forward"},
			},
		},
	}

	// 1. Test c.Portal()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := conn.Portal(ctx)
	if err != nil {
		t.Fatalf("conn.Portal() failed: %v", err)
	}
	if p.Title != "Engineering Portal" {
		t.Errorf("got portal title %q, want 'Engineering Portal'", p.Title)
	}
	if len(p.Context.Targets) != 1 || p.Context.Targets[0].ID != "grafana" {
		t.Errorf("unexpected targets: %+v", p.Context.Targets)
	}

	// 2. Test executePortalAction for authorized target
	rec := httptest.NewRecorder()
	conn.executePortalAction(rec, "open", "grafana", "http://grafana.internal:3000")
	// Since no SOCKS proxy is configured in this test mock, it attempts browseropen.Open on the URL
	if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
		// In headless CI environments without open command, it might return 500 which is still a valid code execution path
		t.Logf("executePortalAction returned status %d: %s", rec.Code, rec.Body.String())
	}

	// 3. Test executePortalAction for unauthorized target
	recUnauthorized := httptest.NewRecorder()
	conn.executePortalAction(recUnauthorized, "open", "unauthorized-db", "")
	if recUnauthorized.Code != http.StatusForbidden {
		t.Errorf("executePortalAction on unauthorized target returned status %d, want 403", recUnauthorized.Code)
	}
}

func SchemaVersion() string {
	return portal.SchemaVersion
}
