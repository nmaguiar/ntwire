package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

const clientsTestToken = "operator-secret-operator-secret-0"

func writeClientsConfig(t *testing.T, metrics, token string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ntwire.yaml")
	config := fmt.Sprintf("listen:\n  metrics: %q\nauth:\n  authorized_keys_dir: %q\nadmin:\n  web_ui_token: %q\n", metrics, dir, token)
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunClients_QueriesLocalInventory(t *testing.T) {
	const response = `{"sessions":[{"session_id":"session-1","identity":"alice\u001b[2J","method":"oidc","tunnel_ip":"100.64.0.2","expires":"2026-11-19T12:00:00Z","granted_tunnel_count":0}],"wireguard_peers":[{"name":"travel","tunnel_ip":"100.64.0.3","last_handshake":null,"status":"never"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RequestURI() != server.AdminClientsPath {
			t.Errorf("unexpected method or request URI: %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("Authorization") != "Bearer "+clientsTestToken {
			t.Error("missing or incorrect bearer credential")
		}
		fmt.Fprint(w, response)
	}))
	defer srv.Close()
	path := writeClientsConfig(t, srv.Listener.Addr().String(), clientsTestToken)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	var out, stderr bytes.Buffer
	u := ui.New(&out, &stderr, true)
	if code := runClients([]string{"-config", path}, u); code != 0 || stderr.Len() != 0 {
		t.Fatalf("clients returned %d: %s", code, &stderr)
	}
	for _, want := range []string{"Authenticated sessions", "Native WireGuard peers", "SESSION ID", "session-1", `alice\x1b[2J`, "travel", "never"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("table lacks %q: %s", want, &out)
		}
	}
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), clientsTestToken) {
		t.Fatal("table contains a terminal escape or credential")
	}
	out.Reset()
	if code := runClients([]string{"-config", path, "-json"}, u); code != 0 {
		t.Fatalf("clients -json returned %d: %s", code, &stderr)
	}
	var snapshot server.ClientsSnapshot
	if err := json.Unmarshal(out.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Sessions) != 1 || snapshot.Sessions[0].Identity != "alice\x1b[2J" || len(snapshot.WireGuardPeers) != 1 || snapshot.WireGuardPeers[0].LastHandshake != nil {
		t.Fatalf("unexpected JSON: %s", &out)
	}
}

func TestRunClients_EmptyAndFailureResponses(t *testing.T) {
	for _, tt := range []struct {
		name, body, diagnostic string
		status, exit           int
	}{
		{"empty", `{"sessions":[],"wireguard_peers":[]}`, "", http.StatusOK, 0},
		{"invalid JSON", clientsTestToken, "invalid", http.StatusOK, 1},
		{"missing arrays", `{}`, "incomplete", http.StatusOK, 1},
		{"trailing data", `{"sessions":[],"wireguard_peers":[]} {}`, "invalid", http.StatusOK, 1},
		{"rejected", clientsTestToken, "unavailable", http.StatusNotFound, 1},
		{"redirect", "", "HTTP 307", http.StatusTemporaryRedirect, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != server.AdminClientsPath {
					t.Error("unexpected redirect follow")
				}
				if tt.status == http.StatusTemporaryRedirect {
					w.Header().Set("Location", "/other")
				}
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer srv.Close()
			path := writeClientsConfig(t, srv.Listener.Addr().String(), clientsTestToken)
			var out, stderr bytes.Buffer
			if exit := runClients([]string{"-config", path, "-json"}, ui.New(&out, &stderr, true)); exit != tt.exit {
				t.Fatalf("exit = %d, want %d; %s", exit, tt.exit, &stderr)
			}
			if tt.exit == 0 {
				if strings.TrimSpace(out.String()) != tt.body || stderr.Len() != 0 {
					t.Fatalf("empty output = %q, stderr = %q", &out, &stderr)
				}
			} else if out.Len() != 0 || !strings.Contains(stderr.String(), tt.diagnostic) {
				t.Fatalf("stdout = %q, stderr = %q", &out, &stderr)
			}
			if strings.Contains(stderr.String(), clientsTestToken) {
				t.Fatal("diagnostic contains credential")
			}
		})
	}
}

func TestLocalMetricsAddress_Loopback(t *testing.T) {
	for _, tt := range []struct{ bind, want string }{
		{":9090", "127.0.0.1:9090"},
		{"localhost:9090", "127.0.0.1:9090"},
		{"0.0.0.0:9090", "127.0.0.1:9090"},
		{"[::]:9090", "[::1]:9090"},
		{"[::1]:9090", "[::1]:9090"},
		{"127.0.0.2:9090", "127.0.0.2:9090"},
		{"", ""},
		{"127.0.0.1:0", ""},
		{"127.0.0.1:65536", ""},
		{"198.51.100.10:9090", ""},
		{"metrics.example.com:9090", ""},
	} {
		t.Run(tt.bind, func(t *testing.T) {
			got, err := localMetricsAddress(tt.bind)
			if got != tt.want || (err != nil) != (tt.want == "") {
				t.Fatalf("address = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}
