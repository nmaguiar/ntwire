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

// FuzzControlFrameDecoding covers datagrams arriving on the public UDP relay
// and direct-upgrade control path. Decoding is allocation-free and must never
// classify a malformed prefix as a control packet.
func FuzzControlFrameDecoding(f *testing.F) {
	f.Add([]byte{})
	f.Add(EncodeControlFrame(FrameRelayBind, []byte("token")))
	f.Add(make([]byte, MaxRelayDatagram))
	f.Add(make([]byte, MaxRelayDatagram+1))
	f.Fuzz(func(t *testing.T, datagram []byte) {
		typ, payload, ok := DecodeControlFrame(datagram)
		if ok {
			if len(datagram) < controlHeaderLen || typ != datagram[4] {
				t.Fatalf("invalid control frame classification")
			}
			if len(payload) != len(datagram)-controlHeaderLen {
				t.Fatalf("payload length = %d, want %d", len(payload), len(datagram)-controlHeaderLen)
			}
		}
		if ValidRelayDatagram(datagram) != (len(datagram) > 0 && len(datagram) <= MaxRelayDatagram) {
			t.Fatalf("unexpected relay datagram validity for %d bytes", len(datagram))
		}
	})
}
