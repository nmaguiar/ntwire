package relay

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
)

// captureRawClientHello drives a real crypto/tls client handshake over a
// net.Pipe and returns the single raw TLS record it writes (a real
// ClientHello, with the exact framing Go's TLS stack produces), without
// depending on peekClientHello to capture it.
func captureRawClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
		_ = tls.Client(clientConn, cfg).Handshake()
	}()

	var header [tlsRecordHeaderSize]byte
	if _, err := io.ReadFull(serverConn, header[:]); err != nil {
		t.Fatalf("reading record header: %v", err)
	}
	length := int(header[3])<<8 | int(header[4])
	payload := make([]byte, length)
	if _, err := io.ReadFull(serverConn, payload); err != nil {
		t.Fatalf("reading record payload: %v", err)
	}
	return append(append([]byte{}, header[:]...), payload...)
}

func TestPeekClientHello_RealHandshake(t *testing.T) {
	cases := []struct {
		name   string
		server string
		want   string
	}{
		{"lowercase", "home.relay.test", "home.relay.test"},
		{"uppercase normalizes", "Home.Relay.Test", "home.relay.test"},
		{"trailing dot stripped", "home.relay.test.", "home.relay.test"},
		{"mixed case and dot", "HOME.Relay.TEST.", "home.relay.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := captureRawClientHello(t, tc.server)
			sni, gotRaw, err := peekClientHello(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("peekClientHello: %v", err)
			}
			if sni != tc.want {
				t.Fatalf("sni = %q, want %q", sni, tc.want)
			}
			if !bytes.Equal(gotRaw, raw) {
				t.Fatalf("raw bytes not returned verbatim: got %d bytes, want %d", len(gotRaw), len(raw))
			}
		})
	}
}

func TestPeekClientHello_NoSNI(t *testing.T) {
	// tls.Client omits the server_name extension entirely when ServerName is
	// empty and no other hook supplies one.
	raw := captureRawClientHello(t, "")
	sni, _, err := peekClientHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if sni != "" {
		t.Fatalf("sni = %q, want empty (no SNI extension present)", sni)
	}
}

func TestPeekClientHello_Fragmented(t *testing.T) {
	raw := captureRawClientHello(t, "home.relay.test")
	version := raw[1:3]
	payload := raw[tlsRecordHeaderSize:]

	// Split the handshake message across three separate TLS records, as a
	// large key-share extension would in a real fragmented ClientHello.
	third := len(payload) / 3
	chunks := [][]byte{payload[:third], payload[third : 2*third], payload[2*third:]}

	var synthetic bytes.Buffer
	for _, chunk := range chunks {
		synthetic.WriteByte(recordTypeHandshake)
		synthetic.Write(version)
		synthetic.WriteByte(byte(len(chunk) >> 8))
		synthetic.WriteByte(byte(len(chunk)))
		synthetic.Write(chunk)
	}

	sni, _, err := peekClientHello(bytes.NewReader(synthetic.Bytes()))
	if err != nil {
		t.Fatalf("peekClientHello over fragmented records: %v", err)
	}
	if sni != "home.relay.test" {
		t.Fatalf("sni = %q, want %q", sni, "home.relay.test")
	}
}

func TestPeekClientHello_TooManyRecords(t *testing.T) {
	raw := captureRawClientHello(t, "home.relay.test")
	version := raw[1:3]
	payload := raw[tlsRecordHeaderSize:]

	// Split into more fragments than maxClientHelloRecords allows so
	// reassembly must fail before the message ever completes.
	n := maxClientHelloRecords + 2
	chunkLen := (len(payload) + n - 1) / n
	var synthetic bytes.Buffer
	for i := 0; i < len(payload); i += chunkLen {
		end := min(i+chunkLen, len(payload))
		chunk := payload[i:end]
		synthetic.WriteByte(recordTypeHandshake)
		synthetic.Write(version)
		synthetic.WriteByte(byte(len(chunk) >> 8))
		synthetic.WriteByte(byte(len(chunk)))
		synthetic.Write(chunk)
	}

	_, _, err := peekClientHello(bytes.NewReader(synthetic.Bytes()))
	if err == nil {
		t.Fatal("expected an error for a ClientHello spanning too many records")
	}
}

func TestPeekClientHello_NonHandshakeFirstByte(t *testing.T) {
	// 0x15 is a TLS alert record, not a handshake record.
	raw := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x0a}
	_, _, err := peekClientHello(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected an error for a non-handshake first byte")
	}
}

func TestPeekClientHello_NotClientHello(t *testing.T) {
	// A well-formed record carrying a ServerHello (handshake type 0x02)
	// instead of a ClientHello (0x01).
	body := []byte{0x02, 0x00, 0x00, 0x02, 0xAA, 0xBB}
	raw := append([]byte{recordTypeHandshake, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...)
	_, _, err := peekClientHello(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected an error for a non-ClientHello handshake message")
	}
}

func TestPeekClientHello_TruncatedPayload(t *testing.T) {
	// Header claims 50 bytes of payload; only 10 are actually available.
	raw := []byte{recordTypeHandshake, 0x03, 0x03, 0x00, 50}
	raw = append(raw, make([]byte, 10)...)
	_, _, err := peekClientHello(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected an error for a truncated record payload")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Logf("truncated payload error (not necessarily io.ErrUnexpectedEOF wrapped): %v", err)
	}
}

func TestPeekClientHello_Oversized(t *testing.T) {
	// A single record claiming a length larger than the 16 KiB cap must be
	// rejected before the code attempts to read that much payload.
	big := maxClientHelloBytes + 1
	raw := []byte{recordTypeHandshake, 0x03, 0x03, byte(big >> 8), byte(big)}
	_, _, err := peekClientHello(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected an error for an oversized ClientHello record")
	}
}

func TestPeekClientHello_EmptyReader(t *testing.T) {
	_, _, err := peekClientHello(bytes.NewReader(nil))
	if err == nil {
		t.Fatal("expected an error reading from an empty stream")
	}
}
