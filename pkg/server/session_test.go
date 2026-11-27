package server

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestSessionsExpireAndCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewSessions()
		s.Create(CreateParams{Method: "ssh", Identity: "fp", Fingerprint: "fp", WireGuardPublicKey: "wg", TunnelIP: "100.64.0.2", Tunnels: []protocol.Tunnel{{Name: "a"}}, TTL: time.Millisecond})
		if got := s.CountIdentity("ssh", "fp", "", ""); got != 1 {
			t.Fatalf("live session count = %d, want 1", got)
		}
		time.Sleep(2 * time.Millisecond)
		if got := len(s.Reap()); got != 1 {
			t.Fatalf("reaped session count = %d, want 1", got)
		}
	})
}

func TestSessionsDeleteByID(t *testing.T) {
	s := NewSessions()
	want := s.Create(CreateParams{Method: "ssh", Identity: "fp", TTL: time.Minute})

	got, ok := s.DeleteByID(want.ID)
	if !ok || got.Token != want.Token {
		t.Fatalf("DeleteByID(%q) = (%+v, %t), want the created session", want.ID, got, ok)
	}
	if _, ok := s.Get(want.Token); ok {
		t.Fatal("session still present after DeleteByID")
	}
	if _, ok := s.DeleteByID(want.ID); ok {
		t.Fatal("DeleteByID succeeded a second time for an already-deleted session")
	}
}

func TestSessionsDeleteByIDUnknown(t *testing.T) {
	s := NewSessions()
	if _, ok := s.DeleteByID("does-not-exist"); ok {
		t.Fatal("DeleteByID(unknown) = true, want false")
	}
}

func TestSessionsDeleteByIDIgnoresExpired(t *testing.T) {
	s := NewSessions()
	expired := s.Create(CreateParams{Method: "ssh", Identity: "fp", TTL: time.Millisecond})
	time.Sleep(2 * time.Millisecond)
	if _, ok := s.DeleteByID(expired.ID); ok {
		t.Fatal("DeleteByID matched an expired session")
	}
}

func TestSessionsFindWireGuardPublicKey(t *testing.T) {
	s := NewSessions()
	want := s.Create(CreateParams{Method: "ssh", Identity: "fp", WireGuardPublicKey: "peer-key", TunnelIP: "100.64.0.2", TTL: time.Minute})
	got, ok := s.FindWireGuardPublicKey("peer-key")
	if !ok || got.Token != want.Token || got.TunnelIP != want.TunnelIP {
		t.Fatalf("FindWireGuardPublicKey = (%+v, %t), want %q", got, ok, want.Token)
	}
	if _, ok := s.FindWireGuardPublicKey("other-key"); ok {
		t.Fatal("unexpected session for unknown WireGuard key")
	}
}

func TestSessionPrincipalFollowsIPOwnership(t *testing.T) {
	s := New(Config{}, nil)
	const ip = "100.64.0.2"
	old := s.sessions.Create(CreateParams{TunnelIP: ip, TTL: -time.Second})
	if _, ok := s.principalForIP(ip); ok {
		t.Fatal("expired session still authorizes traffic")
	}
	current := s.sessions.Create(CreateParams{TunnelIP: ip, TTL: time.Minute, Tunnels: []protocol.Tunnel{{Name: "new"}}})
	if got := s.sessions.Reap(); len(got) != 1 || got[0].Token != old.Token {
		t.Fatalf("unexpected reaping result: %v", len(got))
	}
	s.sessions.Delete(old.Token)
	if p, ok := s.principalForIP(ip); !ok || !p.Tunnels["new"] {
		t.Fatal("current grant lost during old-session cleanup")
	}
	if _, ok := s.sessions.DeleteByID(current.ID); !ok {
		t.Fatal("admin revoke failed")
	}
	if _, ok := s.principalForIP(ip); ok {
		t.Fatal("revoked grant still authorizes traffic")
	}
	s.Reload(Config{NativeWireGuard: NativeWireGuardConfig{Peers: []NativeWireGuardPeer{{Name: "native", TunnelIP: ip, Tunnels: []string{"native-grant"}}}}})
	if p, ok := s.principalForIP(ip); !ok || !p.Tunnels["native-grant"] || p.Method != "native-wireguard" {
		t.Fatal("native peer unavailable after reload")
	}
}

func TestSessionRenewalPreservesCurrentPeerLifetime(t *testing.T) {
	s := NewSessions()
	params := CreateParams{TunnelIP: "100.64.0.2", Identity: "test", Method: "ssh", TTL: time.Minute}
	original := s.Create(params)
	owner, _ := s.principalForIP(params.TunnelIP)
	renewed, ok := s.renew(original.Token, []protocol.Tunnel{{Name: "current"}}, time.Minute, protocol.ClientInfo{}, nil)
	if !ok || renewed.ID == original.ID || renewed.Token == original.Token {
		t.Fatal("renewal did not rotate the control-plane credentials")
	}
	if _, ok := s.Get(original.Token); ok {
		t.Fatal("old bearer token survived renewal")
	}
	if p, ok := s.principalForIP(params.TunnelIP); !ok || !p.Tunnels["current"] || p.peerLifetime == "" || p.peerLifetime != owner.peerLifetime {
		t.Fatal("renewal lost the peer lifetime or the new grants")
	}
	s.Create(params)
	if _, ok := s.renew(renewed.Token, nil, time.Minute, protocol.ClientInfo{}, nil); ok {
		t.Fatal("a superseded token regained IP ownership by renewing")
	}
	if p, ok := s.principalForIP(params.TunnelIP); !ok || p.peerLifetime == owner.peerLifetime {
		t.Fatal("replacement inherited the previous peer lifetime")
	}
}

func TestNativePeerLifetimeChangesWhenReinstalled(t *testing.T) {
	const ip = "100.64.0.2"
	cfg := Config{NativeWireGuard: NativeWireGuardConfig{Enabled: true, Peers: []NativeWireGuardPeer{{Name: "native", TunnelIP: ip}}}}
	s := New(cfg, nil)
	original, _ := s.principalForIP(ip)
	s.Reload(cfg)
	if p, ok := s.principalForIP(ip); !ok || p.peerLifetime != original.peerLifetime {
		t.Fatal("unchanged native configuration changed the peer lifetime")
	}
	withoutPeer := cfg
	withoutPeer.NativeWireGuard.Peers = nil
	s.Reload(withoutPeer)
	s.Reload(cfg)
	if p, ok := s.principalForIP(ip); !ok || p.peerLifetime == original.peerLifetime {
		t.Fatal("reinstalled native peer inherited its former lifetime")
	}
}
