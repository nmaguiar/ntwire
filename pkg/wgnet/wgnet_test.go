package wgnet

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecodeKeyConvertsProtocolBase64ToWireGuardIPCBytes(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}

	decoded, err := decodeKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(decoded), hex.EncodeToString(raw); got != want {
		t.Errorf("WireGuard IPC key = %q, want %q", got, want)
	}
}

func TestDecodeKeyRejectsInvalidLengths(t *testing.T) {
	_, err := decodeKey(base64.StdEncoding.EncodeToString([]byte("too short")))
	if err == nil || !strings.Contains(err.Error(), "expected 32 bytes") {
		t.Fatalf("decodeKey() error = %v, want 32-byte validation error", err)
	}
}
