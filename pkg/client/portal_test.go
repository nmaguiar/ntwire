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

	// 2. The server, not the browser caller, supplies the launch URL.
	serverMux.HandleFunc("POST /v1/portal/action", func(w http.ResponseWriter, r *http.Request) {
		var req portal.ActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Action != portal.ActionOpen || req.TargetID != "grafana" {
			t.Errorf("portal action request = %+v", req)
		}
		_ = json.NewEncoder(w).Encode(portal.ActionResolution{
			Target:     portal.PortalTarget{ID: "grafana"},
			URL:        "http://grafana.internal:3000",
			Authorized: true,
		})
	})
	oldOpenSocks := openSocksBrowser
	defer func() { openSocksBrowser = oldOpenSocks }()
	var gotKey, gotAddr, gotURL string
	openSocksBrowser = func(key, addr string, targetURL ...string) error {
		gotKey, gotAddr = key, addr
		if len(targetURL) == 1 {
			gotURL = targetURL[0]
		}
		return nil
	}
	rec := httptest.NewRecorder()
	conn.tunnels = append(conn.tunnels, &localTunnel{name: "egress", localAddr: "127.0.0.1:1080"})
	conn.Response.Tunnels = append(conn.Response.Tunnels, protocol.Tunnel{Name: "egress", TargetHint: "socks"})
	conn.executePortalAction(ctx, rec, "open", "grafana")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("executePortalAction status = %d: %s", rec.Code, rec.Body.String())
	}
	if gotKey != "client-grafana" || gotAddr != "127.0.0.1:1080" || gotURL != "http://grafana.internal:3000" {
		t.Errorf("browser launch = key=%q addr=%q url=%q", gotKey, gotAddr, gotURL)
	}

	// 3. Test executePortalAction for unauthorized target
	recUnauthorized := httptest.NewRecorder()
	conn.executePortalAction(ctx, recUnauthorized, "open", "unauthorized-db")
	if recUnauthorized.Code != http.StatusForbidden {
		t.Errorf("executePortalAction on unauthorized target returned status %d, want 403", recUnauthorized.Code)
	}
}

func SchemaVersion() string {
	return portal.SchemaVersion
}
