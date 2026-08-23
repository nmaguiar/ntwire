package relay

import (
	"encoding/binary"
	"net"
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
