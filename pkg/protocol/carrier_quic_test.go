package protocol

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestCarrierQUICHelloAndProbe(t *testing.T) {
	hello := CarrierQUICHello{Lane: CarrierID{1}, Ticket: [32]byte{2}, Nonce: [32]byte{3}}
	data := hello.MarshalBinary()
	if decoded, err := ReadCarrierQUICHello(bytes.NewReader(data)); err != nil || decoded != hello {
		t.Fatalf("QUIC hello did not round trip: %v", err)
	}
	for n := range len(data) {
		if _, err := ReadCarrierQUICHello(bytes.NewReader(data[:n])); err == nil {
			t.Fatalf("accepted %d-byte truncated hello", n)
		}
	}
	data[0]++
	if _, err := ReadCarrierQUICHello(bytes.NewReader(data)); err == nil {
		t.Fatal("accepted unknown hello version")
	}
	ticket := base64.RawURLEncoding.EncodeToString(hello.Ticket[:])
	if decoded, ok := ParseCarrierTicket(ticket); !ok || decoded != hello.Ticket {
		t.Fatal("valid ticket did not decode")
	}
	if _, ok := ParseCarrierTicket(ticket[:42] + "B"); ok {
		t.Fatal("accepted noncanonical ticket")
	}
	probe := CarrierQUICProbe(1312, hello.Nonce)
	if !ValidCarrierQUICProbe(probe, 1312, hello.Nonce) || ValidCarrierQUICProbe(probe[:len(probe)-1], 1312, hello.Nonce) ||
		ValidCarrierQUICProbe(probe, 1312, [32]byte{4}) {
		t.Fatal("invalid QUIC probe verification")
	}
	probe[len(probe)-1] = 1
	if ValidCarrierQUICProbe(probe, 1312, hello.Nonce) {
		t.Fatal("accepted unexpected QUIC probe padding")
	}
}

func FuzzCarrierQUICHello(f *testing.F) {
	f.Add((CarrierQUICHello{}).MarshalBinary())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := ReadCarrierQUICHello(bytes.NewReader(data))
		if err == nil && !bytes.Equal(decoded.MarshalBinary(), data[:81]) {
			t.Fatal("decoding changed the fixed-length record")
		}
	})
}
