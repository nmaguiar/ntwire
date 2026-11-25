package server

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestSOCKSUDPAssociationRejectsRetiredPeer(t *testing.T) {
	for _, tc := range []struct {
		name      string
		retire    func(*Sessions, Session, CreateParams)
		replyOnly bool
	}{
		{"revoked", func(s *Sessions, old Session, _ CreateParams) { s.DeleteByID(old.ID) }, false},
		{"grant removed on renewal", func(s *Sessions, old Session, _ CreateParams) {
			s.renew(old.Token, nil, time.Minute, protocol.ClientInfo{})
		}, false},
		{"replacement with the same identity, address and key", func(s *Sessions, old Session, p CreateParams) {
			s.Delete(old.Token)
			s.Create(p)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loopback := netip.MustParseAddr("127.0.0.1")
			listen := func() *net.UDPConn {
				t.Helper()
				pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, 0)))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = pc.Close() })
				return pc
			}
			relay, origin := listen(), listen()
			tunnel := TunnelConfig{Name: "egress", Target: "socks", Socks: &SocksConfig{AllowAll: true, AllowLocalEgress: true}}
			s := New(Config{Tunnels: []TunnelConfig{tunnel}}, nil)
			params := CreateParams{Identity: "test", Method: "ssh", TunnelIP: loopback.String(), WireGuardPublicKey: "test-key",
				TTL: time.Minute, Tunnels: []protocol.Tunnel{{Name: tunnel.Name}}}
			old := s.sessions.Create(params)
			principal, ok := s.principalForIP(params.TunnelIP)
			if !ok {
				t.Fatal("missing original principal")
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.proxySocksUDP(relay, principal, tunnel, s.newSocksRuntime(tunnel).server, t.Context().Done())
			}()
			client, err := net.DialUDP("udp4", nil, relay.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			deadline := time.Now().Add(5 * time.Second)
			_ = origin.SetReadDeadline(deadline)
			packet := socksUDPFrame(origin.LocalAddr().(*net.UDPAddr).AddrPort(), []byte("test"))
			if _, err = client.Write(packet); err != nil {
				t.Fatal(err)
			}
			var buf [128]byte
			n, source, err := origin.ReadFromUDPAddrPort(buf[:])
			if err != nil || string(buf[:n]) != "test" {
				t.Fatalf("pre-revocation payload %q: %v", buf[:n], err)
			}
			tc.retire(s.sessions, old, params)
			if tc.replyOnly {
				_, err = origin.WriteToUDPAddrPort([]byte("late reply"), source)
			} else {
				_, err = client.Write(packet)
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("old relay survived loss of ownership or grant")
			}
			if tc.replyOnly {
				_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				_, err = client.Read(buf[:])
			} else {
				_ = origin.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				_, _, err = origin.ReadFromUDPAddrPort(buf[:])
			}
			if err == nil {
				t.Fatal("relay forwarded data after its owner was retired")
			}
		})
	}
}
