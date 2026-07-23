package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSigningPayloadCanonical(t *testing.T) {
	r := AuthRequest{Version: Version, PublicKey: "a", WireGuardPublicKey: "b", Timestamp: "2026-01-01T00:00:00Z", Nonce: "n", Info: ClientInfo{Extra: map[string]string{"z": "2", "a": "1"}}}
	a, _ := SigningPayload(r)
	r.Info.Extra = map[string]string{"a": "1", "z": "2"}
	b, _ := SigningPayload(r)
	if string(a) != string(b) {
		t.Fatal("not canonical")
	}
}

func TestWireJSONFieldsAreDistinct(t *testing.T) {
	b, err := json.Marshal(AuthResponse{SessionID: "id", Token: "token", TunnelIP: "100.64.0.2", ServerPublicKey: "server", Tunnels: []Tunnel{{Name: "db", Description: "database", LocalPort: 58080}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"\"token\"", "\"tunnel_ip\"", "\"server_public_key\"", "\"description\"", "\"local_port\":58080"} {
		if !strings.Contains(string(b), field) {
			t.Fatalf("missing %s in %s", field, b)
		}
	}
}
func TestAuthResponseServerTunnelIPRoundTrip(t *testing.T) {
	b, err := json.Marshal(AuthResponse{SessionID: "id", Token: "token", TunnelIP: "fd00:ac1d::2", ServerTunnelIP: "fd00:ac1d::1", ServerPublicKey: "server"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\"server_tunnel_ip\":\"fd00:ac1d::1\"") {
		t.Fatalf("missing server_tunnel_ip in %s", b)
	}
	var out AuthResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ServerTunnelIP != "fd00:ac1d::1" {
		t.Fatalf("ServerTunnelIP = %q, want fd00:ac1d::1", out.ServerTunnelIP)
	}

	// omitempty: an unset ServerTunnelIP must not appear in the JSON at all,
	// and must decode back to the zero value (compatibility with an old
	// server's response, which never sends this key).
	b, err = json.Marshal(AuthResponse{SessionID: "id", Token: "token", TunnelIP: "100.64.0.2", ServerPublicKey: "server"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "server_tunnel_ip") {
		t.Fatalf("expected server_tunnel_ip to be omitted when empty, got %s", b)
	}
	out = AuthResponse{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ServerTunnelIP != "" {
		t.Fatalf("ServerTunnelIP = %q, want empty", out.ServerTunnelIP)
	}
}

func FuzzSigningPayload(f *testing.F) {
	f.Add("a")
	f.Fuzz(func(t *testing.T, s string) { _, _ = SigningPayload(AuthRequest{Version: Version, PublicKey: s}) })
}
