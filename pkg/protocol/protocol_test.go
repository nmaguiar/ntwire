package protocol

import "testing"

func TestSigningPayloadCanonical(t *testing.T) {
	r := AuthRequest{Version: Version, PublicKey: "a", WireGuardPublicKey: "b", Timestamp: "2026-01-01T00:00:00Z", Nonce: "n", Info: ClientInfo{Extra: map[string]string{"z": "2", "a": "1"}}}
	a, _ := SigningPayload(r)
	r.Info.Extra = map[string]string{"a": "1", "z": "2"}
	b, _ := SigningPayload(r)
	if string(a) != string(b) {
		t.Fatal("not canonical")
	}
}
func FuzzSigningPayload(f *testing.F) {
	f.Add("a")
	f.Fuzz(func(t *testing.T, s string) { _, _ = SigningPayload(AuthRequest{Version: Version, PublicKey: s}) })
}
