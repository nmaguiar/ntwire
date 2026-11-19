package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

func readClientsSnapshot(t *testing.T, s *Server) ClientsSnapshot {
	t.Helper()
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, adminGET(t, AdminClientsPath))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("inventory response: status %d, headers %v, body %s", rec.Code, rec.Header(), rec.Body)
	}
	var snapshot ClientsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Sessions == nil || snapshot.WireGuardPeers == nil {
		t.Fatalf("want arrays, got %s", rec.Body)
	}
	return snapshot
}

func TestAdminClients_ActiveSessions(t *testing.T) {
	s := adminServer(t)
	expired := s.sessions.Create(CreateParams{Identity: "expired", TTL: -time.Minute})
	first := s.sessions.Create(CreateParams{
		Identity: "alice", Method: "oidc", TTL: time.Minute,
		Tunnels: []protocol.Tunnel{{Name: "reports"}}, WireGuardPublicKey: "key-must-stay-private",
	})
	second := s.sessions.Create(CreateParams{Identity: "alice", Method: "ssh", TTL: time.Minute})
	snapshot := readClientsSnapshot(t, s)
	if len(snapshot.Sessions) != 2 || len(snapshot.WireGuardPeers) != 0 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if a, b := snapshot.Sessions[0], snapshot.Sessions[1]; a.SessionID != first.ID || a.GrantedTunnelCount != 1 || b.SessionID != second.ID || b.GrantedTunnelCount != 0 {
		t.Fatalf("sessions = %+v", snapshot.Sessions)
	}
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, adminGET(t, AdminClientsPath))
	for _, secret := range []string{first.Token, second.Token, "key-must-stay-private", adminTestToken} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatal("inventory contains credential or key material")
		}
	}
	if len(s.sessions.All()) != 3 {
		t.Fatal("inventory altered the session store")
	}
	rec = httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, adminPOST(t, "/v1/admin/sessions/"+first.ID+"/revoke"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d", rec.Code)
	}
	if got := readClientsSnapshot(t, s).Sessions; len(got) != 1 || got[0].SessionID != second.ID {
		t.Fatalf("sessions after revoke = %+v", got)
	}
	if dead := s.sessions.Reap(); len(dead) != 1 || dead[0].ID != expired.ID {
		t.Fatalf("reaper returned %d sessions, want original expired session", len(dead))
	}
}

func TestAdminClients_RequiresBearerOnMetricsListener(t *testing.T) {
	s := adminServer(t)
	tests := []struct {
		name    string
		handler http.Handler
		request *http.Request
	}{
		{"anonymous", s.MetricsHandler(), httptest.NewRequest(http.MethodGet, AdminClientsPath, nil)},
		{"cookie", s.MetricsHandler(), httptest.NewRequest(http.MethodGet, AdminClientsPath, nil)},
		{"query", s.MetricsHandler(), httptest.NewRequest(http.MethodGet, AdminClientsPath+"?token="+adminTestToken, nil)},
		{"bare header", s.MetricsHandler(), httptest.NewRequest(http.MethodGet, AdminClientsPath, nil)},
		{"wrong bearer", s.MetricsHandler(), httptest.NewRequest(http.MethodGet, AdminClientsPath, nil)},
		{"public listener", s.Handler(), adminGET(t, AdminClientsPath)},
		{"disabled", New(Config{}, nil).MetricsHandler(), adminGET(t, AdminClientsPath)},
	}
	tests[1].request.AddCookie(&http.Cookie{Name: adminCookie, Value: adminTestToken})
	tests[3].request.Header.Set("Authorization", adminTestToken)
	tests[4].request.Header.Set("Authorization", "Bearer wrong")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.handler.ServeHTTP(rec, tt.request)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
		})
	}
}

func TestAdminClients_NativeHandshake(t *testing.T) {
	serverIP := netip.MustParseAddr("100.65.0.1")
	clientIP := netip.MustParseAddr("100.65.0.2")
	client, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{clientIP}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	idle, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		NativeWireGuard: NativeWireGuardConfig{Enabled: true, Peers: []NativeWireGuardPeer{
			{Name: "idle", PublicKey: idle.Public, TunnelIP: "100.65.0.3"},
			{Name: "active", PublicKey: client.PublicKey(), TunnelIP: clientIP.String()},
		}},
	}
	cfg.Admin.WebUIToken = adminTestToken
	cfg.Network.TunnelCIDR = "100.65.0.0/24"
	cfg.Network.DNS.Enabled = new(bool)
	port := freeUDPPort(t)
	cfg.Listen.WireGuard = fmt.Sprintf("127.0.0.1:%d", port)
	s := New(cfg, nil)
	if err := s.StartDataPlane(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	peers := readClientsSnapshot(t, s).WireGuardPeers
	if len(peers) != 2 || peers[0].Name != "active" || peers[1].Name != "idle" || peers[0].Status != "never" || peers[1].Status != "never" {
		t.Fatalf("peers before traffic = %+v", peers)
	}
	if err := client.AddPeer(wgnet.Endpoint{PublicKey: s.data.stack.PublicKey(), Address: fmt.Sprintf("0.0.0.0/0@127.0.0.1:%d", port)}); err != nil {
		t.Fatal(err)
	}
	listener, err := s.data.stack.Listen("tcp", serverIP.String()+":9000")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", serverIP.String()+":9000")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	peers = readClientsSnapshot(t, s).WireGuardPeers
	if peers[0].Status != "recent" || peers[0].LastHandshake == nil || peers[1].Status != "never" || peers[1].LastHandshake != nil {
		t.Fatalf("peers after traffic = %+v", peers)
	}
	if err := s.data.stack.RemovePeer(idle.Public); err != nil {
		t.Fatal(err)
	}
	if peer := readClientsSnapshot(t, s).WireGuardPeers[1]; peer.Status != "unavailable" || peer.LastHandshake != nil {
		t.Fatalf("uninstalled peer = %+v", peer)
	}
	cfg.NativeWireGuard.Enabled = false
	s.Reload(cfg)
	if peers := readClientsSnapshot(t, s).WireGuardPeers; len(peers) != 0 {
		t.Fatalf("disabled native peers = %+v", peers)
	}
}

func TestWireGuardActivity_RecentWindow(t *testing.T) {
	now := time.Now().UTC()
	for _, tt := range []struct {
		age    time.Duration
		status string
	}{
		{3 * time.Minute, "recent"},
		{3*time.Minute + time.Nanosecond, "stale"},
	} {
		last := now.Add(-tt.age)
		status, timestamp := wireGuardActivity(now, last, true)
		if status != tt.status || timestamp == nil || !timestamp.Equal(last) {
			t.Fatalf("age %s returned %q at %v, want %q at %v", tt.age, status, timestamp, tt.status, last)
		}
	}
}
