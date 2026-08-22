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
	n := newNativeWGRelay(relayConn)
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
	binary.LittleEndian.PutUint32(response[4:8], 77)
	n.handle(response, serverAddr)
	if _, ok := readWithTimeout(t, clientConn, time.Second); !ok {
		t.Fatal("server handshake response was not routed to client")
	}
}

func TestNativeWGRelayRejectsMalformedAndUnassociatedPackets(t *testing.T) {
	pc := mustListenUDPForTest(t)
	defer pc.Close()
	n := newNativeWGRelay(pc)
	from := mustListenUDPForTest(t)
	defer from.Close()
	n.handle([]byte{1, 0, 0, 0}, from.LocalAddr().(*net.UDPAddr).AddrPort())
	if len(n.indices) != 0 {
		t.Fatal("malformed packet created routing state")
	}
}
