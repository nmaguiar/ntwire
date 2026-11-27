package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestChildSession_OnlyInheritsNegotiatedCarriers(t *testing.T) {
	parent := AdaptiveSession{
		ParentID: "parent", LaneID: "anchor", AuthGeneration: 8, PathEpoch: 7,
		DirectUDP: "127.0.0.1:20800", AlternateUDP: "127.0.0.1:443", QUIC: "127.0.0.1:20801",
		UDPSelect: true, PathSelect: true, Performance: true, TunnelMTU: 1280,
		RelayCatalog: true, RelayUDP: true, RelaySelect: true, MaxLanes: 4,
	}
	legacyChild := parent.ChildSession("child")
	if legacyChild.DirectUDP != "" || legacyChild.AlternateUDP != "" || legacyChild.QUIC != "" ||
		legacyChild.UDPSelect || !legacyChild.RelaySelect || !legacyChild.PathSelect {
		t.Fatalf("legacy child changed its carrier permissions: %+v", legacyChild)
	}
	parent.LaneCarriers = true
	child := parent.ChildSession("child")
	if child.ParentID != parent.ParentID || child.AuthGeneration != parent.AuthGeneration ||
		!child.Child || child.LaneID != "child" || child.PathEpoch != 0 || child.MaxLanes != 0 || child.LaneCarriers {
		t.Fatalf("child inherited parent control state: %+v", child)
	}
	if child.DirectUDP != parent.DirectUDP || child.AlternateUDP != parent.AlternateUDP ||
		child.QUIC != parent.QUIC || !child.UDPSelect || !child.PathSelect || !child.RelaySelect ||
		!child.Performance || child.TunnelMTU != parent.TunnelMTU {
		t.Fatalf("child did not inherit the permitted carriers: %+v", child)
	}
}

func FuzzDecodeLaneRequest(f *testing.F) {
	f.Add([]byte(`{"request_id":"AAAAAAAAAAAAAAAAAAAAAA","auth_generation":1}`))
	f.Add([]byte(`{"request_id":"bad","auth_generation":0}`))
	f.Add([]byte(`{"request_id":"AAAAAAAAAAAAAAAAAAAAAA","auth_generation":2,"wireguard_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return
		}
		req, err := DecodeLaneRequest(bytes.NewReader(b))
		if err != nil {
			return
		}
		if !ValidCarrierID(req.RequestID) || req.Generation == 0 || len(req.WireGuardPublicKey) > 64 {
			t.Fatalf("accepted an invalid lane request: %+v", req)
		}
		canonical, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := DecodeLaneRequest(bytes.NewReader(canonical))
		if err != nil || reply != req {
			t.Fatalf("lane request changed on round trip: %+v, %v", reply, err)
		}
	})
}
