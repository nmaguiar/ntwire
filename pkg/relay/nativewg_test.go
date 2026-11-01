package relay

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestNativeWGRelayRoutesHandshakeByReceiverIndex(t *testing.T) {
	relayConn := mustListenUDPForTest(t)
	defer relayConn.Close()
	serverConn := mustListenUDPForTest(t)
	defer serverConn.Close()
	clientConn := mustListenUDPForTest(t)
	defer clientConn.Close()
	n := newNativeWGRelay(relayConn, relayConn.LocalAddr().String())
	token := n.issue("home")
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	n.handle(wstransport.EncodeControlFrame(wstransport.FrameNativeWireGuardAssociate, []byte(token)), serverAddr)
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr).AddrPort()
	init := make([]byte, 148)
	binary.LittleEndian.PutUint32(init, 1)
	binary.LittleEndian.PutUint32(init[4:8], 77)
	n.handle(init, clientAddr)
	if _, ok := readWithTimeout(t, serverConn, time.Second); !ok {
		t.Fatal("client handshake was not forwarded to associated server")
	}
	response := make([]byte, 92)
	binary.LittleEndian.PutUint32(response, 2)
	binary.LittleEndian.PutUint32(response[4:8], 99)
	binary.LittleEndian.PutUint32(response[8:12], 77)
	n.handle(response, serverAddr)
	if _, ok := readWithTimeout(t, clientConn, time.Second); !ok {
		t.Fatal("server handshake response was not routed to client")
	}
}

func TestNativeWGRelayRejectsMalformedAndUnassociatedPackets(t *testing.T) {
	pc := mustListenUDPForTest(t)
	defer pc.Close()
	n := newNativeWGRelay(pc, pc.LocalAddr().String())
	from := mustListenUDPForTest(t)
	defer from.Close()
	n.handle([]byte{1, 0, 0, 0}, from.LocalAddr().(*net.UDPAddr).AddrPort())
	if len(n.indices) != 0 {
		t.Fatal("malformed packet created routing state")
	}
}

func TestNativeWGHostnameListenAndWildcardAdvertisement(t *testing.T) {
	resolved, err := resolveNativeWGListenAddr("localhost:51821")
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(resolved)
	if err != nil || net.ParseIP(host) == nil {
		t.Fatalf("resolved hostname listener = %q, want numeric IP:port", resolved)
	}
	tests := []struct {
		name       string
		configured string
		bound      net.Addr
		want       string
	}{
		{"empty-host-wildcard", ":51821", &net.UDPAddr{IP: net.IPv4zero, Port: 51821}, "home.relay.example.com:51821"},
		{"ipv4-wildcard", "0.0.0.0:51821", &net.UDPAddr{IP: net.IPv4zero, Port: 51821}, "home.relay.example.com:51821"},
		{"ipv6-wildcard", "[::]:51821", &net.UDPAddr{IP: net.IPv6zero, Port: 51821}, "home.relay.example.com:51821"},
		{"concrete-ip", "127.0.0.1:0", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 56423}, "127.0.0.1:56423"},
		{"concrete-hostname", "localhost:0", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 56423}, "127.0.0.1:56423"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			advertised, err := nativeWGAdvertiseAddr("home", "relay.example.com", tc.configured, tc.bound)
			if err != nil {
				t.Fatalf("nativeWGAdvertiseAddr error: %v", err)
			}
			if advertised != tc.want {
				t.Fatalf("advertised = %q, want %q", advertised, tc.want)
			}
		})
	}
}

func TestNativeWGRelay_StaleRegistrationCleanupPreservesReplacement(t *testing.T) {
	relayConn := mustListenUDPForTest(t)
	defer relayConn.Close()
	serverConn := mustListenUDPForTest(t)
	defer serverConn.Close()
	clientConn := mustListenUDPForTest(t)
	defer clientConn.Close()
	n := newNativeWGRelay(relayConn, relayConn.LocalAddr().String())
	oldToken := n.issue("home")
	newToken := n.issue("home")
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	associate := func(token string) {
		n.handle(wstransport.EncodeControlFrame(wstransport.FrameNativeWireGuardAssociate, []byte(token)), serverAddr)
	}
	associate(newToken)
	n.remove("home", oldToken) // delayed cleanup of the old registration
	associate(newToken)        // periodic association must remain valid too
	if n.tokens[newToken] != "home" || n.servers["home"] != serverAddr {
		t.Fatal("old registration cleanup removed the replacement association")
	}
	init := make([]byte, 148)
	binary.LittleEndian.PutUint32(init, 1)
	binary.LittleEndian.PutUint32(init[4:8], 77)
	n.handle(init, clientConn.LocalAddr().(*net.UDPAddr).AddrPort())
	if _, ok := readWithTimeout(t, serverConn, time.Second); !ok {
		t.Fatal("client handshake was not forwarded after stale cleanup")
	}
	response := make([]byte, 92)
	binary.LittleEndian.PutUint32(response, 2)
	binary.LittleEndian.PutUint32(response[8:12], 77)
	n.handle(response, serverAddr)
	if _, ok := readWithTimeout(t, clientConn, time.Second); !ok {
		t.Fatal("client received no handshake response after stale cleanup")
	}
	n.remove("home", newToken)
	associate(newToken)
	if len(n.tokens) != 0 || len(n.servers) != 0 {
		t.Fatal("current registration cleanup retained an association or accepted its revoked token")
	}
}

func nativeWGHandshake(t *testing.T, n *nativeWGRelay, serverAddr, clientAddr netip.AddrPort, serverIdx, clientIdx uint32) {
	t.Helper()
	init := make([]byte, 148)
	binary.LittleEndian.PutUint32(init, 1)
	binary.LittleEndian.PutUint32(init[4:8], clientIdx)
	n.handle(init, clientAddr)
	response := make([]byte, 92)
	binary.LittleEndian.PutUint32(response, 2)
	binary.LittleEndian.PutUint32(response[4:8], serverIdx)
	binary.LittleEndian.PutUint32(response[8:12], clientIdx)
	n.handle(response, serverAddr)
}

func nativeWGTransport(receiver uint32) []byte {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint32(b, 4)
	binary.LittleEndian.PutUint32(b[4:8], receiver)
	return b
}

func TestNativeWGRelay_ClientRoamRefreshesRoute(t *testing.T) {
	relayConn := mustListenUDPForTest(t)
	defer relayConn.Close()
	serverConn := mustListenUDPForTest(t)
	defer serverConn.Close()
	oldClient := mustListenUDPForTest(t)
	defer oldClient.Close()
	newClient := mustListenUDPForTest(t)
	defer newClient.Close()
	n := newNativeWGRelay(relayConn, relayConn.LocalAddr().String())
	token := n.issue("home")
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	n.handle(wstransport.EncodeControlFrame(wstransport.FrameNativeWireGuardAssociate, []byte(token)), serverAddr)
	nativeWGHandshake(t, n, serverAddr, oldClient.LocalAddr().(*net.UDPAddr).AddrPort(), 99, 77)

	// Client roams: a transport packet for the server index arrives from a new address.
	n.handle(nativeWGTransport(99), newClient.LocalAddr().(*net.UDPAddr).AddrPort())
	// Server replies to client index 77 must now reach the new address.
	n.handle(nativeWGTransport(77), serverAddr)
	if _, ok := readWithTimeout(t, newClient, time.Second); !ok {
		t.Fatal("server transport packet was not routed to the roamed client address")
	}
}

func TestNativeWGRelay_RouteExpiryExtendedByTraffic(t *testing.T) {
	relayConn := mustListenUDPForTest(t)
	defer relayConn.Close()
	serverConn := mustListenUDPForTest(t)
	defer serverConn.Close()
	clientConn := mustListenUDPForTest(t)
	defer clientConn.Close()
	n := newNativeWGRelay(relayConn, relayConn.LocalAddr().String())
	token := n.issue("home")
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	n.handle(wstransport.EncodeControlFrame(wstransport.FrameNativeWireGuardAssociate, []byte(token)), serverAddr)
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr).AddrPort()
	nativeWGHandshake(t, n, serverAddr, clientAddr, 99, 77)

	n.mu.Lock()
	n.indices[77] = nativeWGRoute{client: clientAddr, expires: time.Now().Add(time.Second)}
	n.mu.Unlock()
	n.handle(nativeWGTransport(99), clientAddr) // client activity
	n.mu.Lock()
	remaining := time.Until(n.indices[77].expires)
	n.mu.Unlock()
	if remaining < time.Minute {
		t.Fatalf("route expiry not extended by client traffic: %s", remaining)
	}
}

type flakyPacketConn struct {
	net.PacketConn
	calls int
	got   chan struct{}
}

type tempErr struct{}

func (tempErr) Error() string   { return "temporary" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

func (f *flakyPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	f.calls++
	if f.calls == 1 {
		return 0, nil, tempErr{}
	}
	if f.calls == 2 {
		close(f.got)
	}
	return 0, nil, net.ErrClosed
}

func TestNativeWGRelay_ServeSurvivesTemporaryReadError(t *testing.T) {
	pc := mustListenUDPForTest(t)
	defer pc.Close()
	f := &flakyPacketConn{PacketConn: pc, got: make(chan struct{})}
	n := newNativeWGRelay(f, "x")
	done := make(chan struct{})
	go func() { n.serve(); close(done) }()
	select {
	case <-f.got:
	case <-time.After(2 * time.Second):
		t.Fatal("serve stopped after a temporary read error")
	}
	<-done
}
