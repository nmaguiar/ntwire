package server

import (
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
)

func TestSessionsExpiredLookupsPreserveCleanup(t *testing.T) {
	checks := map[string]func(*Sessions, Session) bool{
		"token":     func(s *Sessions, v Session) bool { _, ok := s.Get(v.Token); return ok },
		"id":        func(s *Sessions, v Session) bool { _, ok := s.FindID(v.ID); return ok },
		"peer":      func(s *Sessions, v Session) bool { _, ok := s.FindWireGuardPublicKey(v.WireGuardPublicKey); return ok },
		"delete_id": func(s *Sessions, v Session) bool { _, ok := s.DeleteByID(v.ID); return ok },
		"count":     func(s *Sessions, v Session) bool { return s.CountIdentity(v.Method, v.Identity) != 0 },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			s := New(Config{}, nil)
			v := s.sessions.Create(CreateParams{Method: "ssh", Identity: "test", WireGuardPublicKey: "peer", TunnelIP: "100.64.0.2", Tunnels: []protocol.Tunnel{{Name: "test"}}, TTL: -time.Second})
			s.statsFor(v.TunnelIP, "test")
			if check(s.sessions, v) {
				t.Fatal("expired session accepted")
			}
			s.reapSessions()
			if _, ok := s.tunnelStats.Load(statsKey(v.TunnelIP, "test")); ok {
				t.Fatal("expired session resources were not cleaned up")
			}
			if dead := s.sessions.Reap(); len(dead) != 0 {
				t.Fatal("session reaped twice")
			}
		})
	}
}

func TestEstablishSessionReapsExpiredBeforeReplacement(t *testing.T) {
	s := New(Config{}, nil)
	old := s.sessions.Create(CreateParams{WireGuardPublicKey: "peer", TunnelIP: "100.64.0.2", Tunnels: []protocol.Tunnel{{Name: "test"}}, TTL: -time.Second})
	s.statsFor(old.TunnelIP, "test")
	s.operationMu.Lock()
	ok := s.establishSession(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/auth", nil), sessionRequest{Method: "ssh", Identity: "test", WireGuardPublicKey: "peer"}, nil)
	s.operationMu.Unlock()
	if !ok {
		t.Fatal("establish failed")
	}
	if _, ok := s.tunnelStats.Load(statsKey(old.TunnelIP, "test")); ok {
		t.Fatal("old session was not cleaned before replacement")
	}
	for _, v := range s.sessions.All() {
		if v.Token == old.Token {
			t.Fatal("expired generation retained")
		}
	}
}

type recoveringDNSConn struct {
	net.PacketConn
	reads    int
	stop     chan struct{}
	response chan []byte
}

func (c *recoveringDNSConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.reads++
	if c.reads == 1 {
		return 0, nil, errors.New("transient receive failure")
	}
	if c.reads == 2 {
		return copy(p, buildDNSQuery(42, "reports.ntwire.", dnsmessage.TypeA)), &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 1234}, nil
	}
	<-c.stop
	return 0, nil, net.ErrClosed
}
func (c *recoveringDNSConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.response <- append([]byte(nil), p...)
	return len(p), nil
}

func TestDNSLoopRecoversAfterReadError(t *testing.T) {
	s := newTestServerForDNS()
	c := &recoveringDNSConn{stop: make(chan struct{}), response: make(chan []byte, 1)}
	d := &dataPlane{dnsConn: c, stop: c.stop, serverIP: netip.MustParseAddr("100.64.0.1")}
	done := make(chan struct{})
	go func() { defer close(done); s.dnsLoop(d) }()
	defer func() { close(c.stop); <-done }()
	select {
	case raw := <-c.response:
		var response dnsmessage.Message
		if err := response.Unpack(raw); err != nil {
			t.Fatal(err)
		}
		if response.ID != 42 || response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 {
			t.Fatalf("unexpected DNS response: %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS stopped serving after a read error")
	}
}

func TestDropSessionRemovesMultipathPeer(t *testing.T) {
	s := New(Config{}, nil)
	stack, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	m := wstransport.NewServerMultipathBind(conn.NewDefaultBind(), wstransport.MultipathOptions{})
	defer m.Close()
	ep, err := m.ParseEndpoint("127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer := key.Public
	m.RegisterPath(peer, "wss", wstransport.PathWSS, ep, false)
	if _, err := m.ParseEndpoint(peer); err != nil {
		t.Fatal(err)
	}
	s.data = &dataPlane{stack: stack, multipath: m}
	s.dropSession(Session{WireGuardPublicKey: peer})
	if _, err := m.ParseEndpoint(peer); err == nil {
		t.Fatal("removed session still has a multipath endpoint")
	}
}

func TestDNSLoopStopsDuringReadErrorBackoff(t *testing.T) {
	s := newTestServerForDNS()
	c := &recoveringDNSConn{stop: make(chan struct{})}
	close(c.stop)
	done := make(chan struct{})
	go func() { defer close(done); s.dnsLoop(&dataPlane{dnsConn: c, stop: c.stop}) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not interrupt DNS retry")
	}
	if c.reads != 1 {
		t.Fatalf("retried after shutdown: %d reads", c.reads)
	}
}
