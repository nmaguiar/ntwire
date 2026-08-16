package wstransport

import "testing"

// FuzzAccept exercises the externally supplied WebSocket payload boundary.
// It must never panic or return a frame outside the WireGuard datagram limit.
func FuzzAccept(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 65535))
	f.Add(make([]byte, 65536))
	f.Fuzz(func(t *testing.T, frame []byte) {
		got, ok := Accept(frame)
		if ok != ValidDatagram(frame) {
			t.Fatalf("Accept validity = %v, want %v for %d-byte frame", ok, ValidDatagram(frame), len(frame))
		}
		if ok && (len(got) < 16 || len(got) > 65535) {
			t.Fatalf("accepted invalid frame length %d", len(got))
		}
	})
}
