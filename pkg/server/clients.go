package server

import (
	"cmp"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

// AdminClientsPath identifies the read-only client inventory on the metrics listener.
const AdminClientsPath = "/v1/admin/clients"

// ClientsSnapshot is the credential-free operator view of one running server.
type ClientsSnapshot struct {
	Sessions       []ClientSession       `json:"sessions"`
	WireGuardPeers []ClientWireGuardPeer `json:"wireguard_peers"`
}

// ClientSession describes an unexpired authorization on the running server.
type ClientSession struct {
	SessionID          string    `json:"session_id"`
	Identity           string    `json:"identity"`
	Method             string    `json:"method"`
	TunnelIP           string    `json:"tunnel_ip"`
	Expires            time.Time `json:"expires"`
	GrantedTunnelCount int       `json:"granted_tunnel_count"`
}

// ClientWireGuardPeer describes a configured peer and its handshake activity.
type ClientWireGuardPeer struct {
	Name          string     `json:"name"`
	TunnelIP      string     `json:"tunnel_ip"`
	LastHandshake *time.Time `json:"last_handshake"`
	Status        string     `json:"status"`
}

func (s *Server) adminClients(w http.ResponseWriter, r *http.Request) {
	snapshot, allowed := s.clientsSnapshot(r)
	if !allowed {
		http.NotFound(w, r)
		return
	}
	slices.SortFunc(snapshot.Sessions, func(a, b ClientSession) int {
		return cmp.Or(cmp.Compare(a.Identity, b.Identity), cmp.Compare(a.Method, b.Method), cmp.Compare(a.SessionID, b.SessionID))
	})
	slices.SortFunc(snapshot.WireGuardPeers, func(a, b ClientWireGuardPeer) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.TunnelIP, b.TunnelIP))
	})
	w.Header().Set("Cache-Control", "no-store")
	write(w, http.StatusOK, snapshot)
}

func (s *Server) clientsSnapshot(r *http.Request) (ClientsSnapshot, bool) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	// Reload takes operationMu before changing the admin token or native peers.
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !s.dashboardHeaderAllowed(r) {
		return ClientsSnapshot{}, false
	}
	snapshot := ClientsSnapshot{
		Sessions:       []ClientSession{},
		WireGuardPeers: []ClientWireGuardPeer{},
	}
	var handshakes map[string]time.Time
	native := s.Config.NativeWireGuard
	if native.Enabled && len(native.Peers) > 0 && s.data != nil {
		// An unreadable device snapshot leaves every configured peer unavailable.
		handshakes, _ = s.data.stack.LastHandshakes()
	}
	now := time.Now()
	for _, session := range s.sessions.All() {
		if session.Expires.After(now) {
			snapshot.Sessions = append(snapshot.Sessions, ClientSession{
				SessionID: session.ID, Identity: session.Identity, Method: session.Method,
				TunnelIP: session.TunnelIP, Expires: session.Expires.UTC(), GrantedTunnelCount: len(session.Tunnels),
			})
		}
	}
	if native.Enabled {
		for _, peer := range native.Peers {
			key, _ := wgnet.CanonicalPublicKey(peer.PublicKey)
			last, found := handshakes[key]
			status, timestamp := wireGuardActivity(now, last, found)
			snapshot.WireGuardPeers = append(snapshot.WireGuardPeers, ClientWireGuardPeer{
				Name: peer.Name, TunnelIP: peer.TunnelIP, LastHandshake: timestamp, Status: status,
			})
		}
	}
	return snapshot, true
}

func wireGuardActivity(now, last time.Time, found bool) (string, *time.Time) {
	if !found {
		return "unavailable", nil
	}
	if !last.After(time.Unix(0, 0)) {
		return "never", nil
	}
	stamp := last.UTC()
	if now.Sub(last) <= 3*time.Minute {
		return "recent", &stamp
	}
	return "stale", &stamp
}
