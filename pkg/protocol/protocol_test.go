package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIsBrowserSocksTarget(t *testing.T) {
	for hint, want := range map[string]bool{
		"socks":         true,
		"postgres:5432": false,
		"":              false,
	} {
		if got := IsBrowserSocksTarget(hint); got != want {
			t.Errorf("IsBrowserSocksTarget(%q) = %v, want %v", hint, got, want)
		}
	}
}

func TestSigningPayloadCanonical(t *testing.T) {
	r := AuthRequest{Version: Version, PublicKey: "a", WireGuardPublicKey: "b", Timestamp: "2026-01-01T00:00:00Z", Nonce: "n", Info: ClientInfo{Extra: map[string]string{"z": "2", "a": "1"}}}
	a, _ := SigningPayload(r)
	r.Info.Extra = map[string]string{"a": "1", "z": "2"}
	b, _ := SigningPayload(r)
	if string(a) != string(b) {
		t.Fatal("not canonical")
	}
}

func TestPortalCapabilitiesAreAdditivePresentationMetadata(t *testing.T) {
	r := AuthRequest{Version: Version, PublicKey: "a", WireGuardPublicKey: "b", Timestamp: "2026-01-01T00:00:00Z", Nonce: "n"}
	before, err := SigningPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Info.PortalCapabilities = []string{"local_ports", "socks"}
	after, err := SigningPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("presentation metadata changed authorization signature payload")
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"portal_capabilities"`) {
		t.Fatalf("metadata was not encoded: %s, %v", b, err)
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

// TestUDPRelayHopTelemetryJSONFieldNamesAndOmitempty covers item 1's new
// wire shapes: UDPRelayRequest.Stats and UDPRelayResponse.Stats (including
// its nested ClientObserved echo) must use the documented snake_case field
// names and be omitted entirely when nil/unset, so an old client posting a
// bare "{}" and an old server never sending "stats" both stay compatible
// with a peer that now understands these fields.
func TestUDPRelayHopTelemetryJSONFieldNamesAndOmitempty(t *testing.T) {
	reqBytes, err := json.Marshal(UDPRelayRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reqBytes), "stats") {
		t.Fatalf("UDPRelayRequest{} = %s, want no stats field when nil", reqBytes)
	}

	stats := &ClientUDPRelayStats{BytesSent: 1, PacketsSent: 2, BytesReceived: 3, PacketsReceived: 4}
	reqBytes, err = json.Marshal(UDPRelayRequest{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"bytes_sent":1`, `"packets_sent":2`, `"bytes_received":3`, `"packets_received":4`} {
		if !strings.Contains(string(reqBytes), field) {
			t.Fatalf("UDPRelayRequest with Stats = %s, missing %s", reqBytes, field)
		}
	}

	respBytes, err := json.Marshal(UDPRelayResponse{RelayAddr: "a", Token: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(respBytes), "stats") {
		t.Fatalf("UDPRelayResponse with no Stats = %s, want no stats field", respBytes)
	}

	hop := UDPRelayHopStats{ClientPacketsReceived: 5, ClientBytesReceived: 500, ClientObserved: stats}
	respBytes, err = json.Marshal(UDPRelayResponse{RelayAddr: "a", Token: "b", Stats: &hop})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"client_packets_received":5`, `"client_bytes_received":500`, `"client_observed"`, `"bytes_sent":1`} {
		if !strings.Contains(string(respBytes), field) {
			t.Fatalf("UDPRelayResponse with Stats = %s, missing %s", respBytes, field)
		}
	}

	var out UDPRelayResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		t.Fatal(err)
	}
	if out.Stats == nil || out.Stats.ClientObserved == nil || *out.Stats.ClientObserved != *stats {
		t.Fatalf("round-tripped Stats = %+v, want ClientObserved = %+v", out.Stats, stats)
	}
}

func FuzzSigningPayload(f *testing.F) {
	f.Add("a")
	f.Fuzz(func(t *testing.T, s string) { _, _ = SigningPayload(AuthRequest{Version: Version, PublicKey: s}) })
}
