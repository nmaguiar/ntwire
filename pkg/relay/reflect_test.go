package relay

import (
	"net"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestReflectorRepliesWithObservedAddress(t *testing.T) {
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	go newReflector(serverConn, 60, nil).serve()
	t.Cleanup(func() { _ = serverConn.Close() })

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	req := wstransport.EncodeControlFrame(wstransport.FrameReflectRequest, nil)
	if _, err := client.WriteTo(req, serverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no reflector reply: %v", err)
	}
	typ, payload, ok := wstransport.DecodeControlFrame(buf[:n])
	if !ok || typ != wstransport.FrameReflectResponse {
		t.Fatalf("unexpected reply frame: ok=%v typ=%d", ok, typ)
	}
	got := string(payload)
	want := client.LocalAddr().String()
	if got != want {
		t.Fatalf("reflected address = %q, want %q", got, want)
	}
}

// TestReflectorIgnoresNonReflectFrames guards against the reflector ever
// echoing a FramePrime or malformed datagram back at an arbitrary address:
// it must only ever answer FrameReflectRequest, since anything broader turns
// it into a generic (if small) UDP reflection amplifier.
func TestReflectorIgnoresNonReflectFrames(t *testing.T) {
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	go newReflector(serverConn, 60, nil).serve()
	t.Cleanup(func() { _ = serverConn.Close() })

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	cases := [][]byte{
		wstransport.EncodeControlFrame(wstransport.FramePrime, nil),
		wstransport.EncodeControlFrame(wstransport.FrameReflectResponse, []byte("spoofed")),
		[]byte("not a control frame at all"),
	}
	for _, b := range cases {
		if _, err := client.WriteTo(b, serverConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 128)
	if n, _, err := client.ReadFrom(buf); err == nil {
		t.Fatalf("reflector unexpectedly replied to a non-request frame: %q", buf[:n])
	}
}
