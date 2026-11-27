package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestAdaptiveUDP_ProofRequiresFullSizeBothWaysAndOneTuple(t *testing.T) {
	u := newUDPProofRegistry(10000)
	now := time.Now()
	scope := protocol.CarrierProofScope{Parent: protocol.CarrierID{1}, Lane: protocol.CarrierID{2}, Candidate: protocol.CarrierID{3}, AuthGeneration: 1, PathEpoch: 7}
	key := [32]byte{4}
	size := wstransport.MaxWireGuardDatagram(0)
	offer := &udpProofOffer{scope: scope, key: key, size: size, expires: now.Add(2 * time.Second)}
	u.offers[scope.Candidate] = offer
	peer, err := u.socket.ParseEndpoint("192.0.2.20:33333")
	if err != nil {
		t.Fatal(err)
	}
	wrongPort, err := u.socket.ParseEndpoint("192.0.2.20:33334")
	if err != nil {
		t.Fatal(err)
	}
	wrongIP, err := u.socket.ParseEndpoint("192.0.2.21:33333")
	if err != nil {
		t.Fatal(err)
	}
	first := protocol.CarrierProof{Kind: protocol.CarrierProbe, Direction: protocol.CarrierUpload, Nonce: protocol.CarrierID{8}, Size: uint16(size)}
	tooShort := first
	tooShort.Size--
	if reply := u.proofReply(protocol.EncodeCarrierProof(scope, key, tooShort), peer, now); reply != nil {
		t.Fatal("undersized proof elicited a reply")
	}
	if reply := u.proofReply(protocol.EncodeCarrierProof(scope, [32]byte{9}, first), peer, now); reply != nil {
		t.Fatal("unauthenticated probe elicited a reply")
	}
	wire := protocol.EncodeCarrierProof(scope, key, first)
	offer.expectedRemote = netip.MustParseAddrPort(peer.DstToString())
	if reply := u.proofReply(wire, wrongPort, now); reply != nil {
		t.Fatal("proof from a source other than the allocated relay tuple elicited a reply")
	}
	reply := u.proofReply(wire, peer, now)
	ack, ok := protocol.DecodeCarrierProof(scope, key, reply)
	if !ok || ack.Kind != protocol.CarrierACK || ack.Nonce != first.Nonce || len(reply) >= len(wire) || offer.ready {
		t.Fatal("first request did not return the bounded upload acknowledgement")
	}
	if reply := u.proofReply(wire, peer, now); reply != nil {
		t.Fatal("replayed upload probe elicited a reply")
	}
	first.Nonce[0]++
	wire = protocol.EncodeCarrierProof(scope, key, first)
	if u.proofReply(wire, wrongPort, now) != nil || u.proofReply(wire, wrongIP, now) != nil {
		t.Fatal("second upload probe could change the observed tuple")
	}
	reply = u.proofReply(wire, peer, now)
	down, ok := protocol.DecodeCarrierProof(scope, key, reply)
	if !ok || down.Kind != protocol.CarrierProbe || down.Direction != protocol.CarrierDownload || len(reply) != len(wire) || offer.ready {
		t.Fatal("second request did not return a bounded download challenge")
	}
	down.Kind = protocol.CarrierACK
	wire = protocol.EncodeCarrierProof(scope, key, down)
	if u.proofReply(wire, wrongPort, now) != nil || offer.ready {
		t.Fatal("download ACK from a different port qualified the path")
	}
	if u.proofReply(wire, peer, now.Add(3*time.Second)) != nil || offer.ready {
		t.Fatal("expired ACK qualified the path")
	}
	if u.proofReply(wire, peer, now.Add(time.Millisecond)) != nil || !offer.ready || offer.remote.Remote != netip.MustParseAddrPort("192.0.2.20:33333") {
		t.Fatal("valid download ACK did not qualify the observed path")
	}
	u.forget(offer)
	if u.proofReply(wire, peer, now) != nil || len(u.offers) != 0 {
		t.Fatal("retired offer remained accessible")
	}
}

func TestAdaptiveCarrierMTU_NegotiatesBeforeLaneAndPreservesLegacy(t *testing.T) {
	s := &Server{adaptive: &adaptiveServerPlane{mtu: 1280}}
	base := []string{protocol.CapabilityAdaptiveCarrierV1}
	modern := []string{protocol.CapabilityAdaptiveCarrierV1, protocol.CapabilityAdaptiveMTUV1}
	if got := s.negotiateAdaptiveTransport(true, sessionRequest{}, base); got != nil {
		t.Fatal("legacy client was assigned a reduced MTU lane")
	}
	if got := s.negotiateAdaptiveTransport(true, sessionRequest{TunnelMTU: 1400}, modern); got != nil {
		t.Fatal("adaptive MTU displaced the client's explicit MTU")
	}
	if got := s.negotiateAdaptiveTransport(true, sessionRequest{TunnelMTU: 1280}, modern); got == nil || got.TunnelMTU != 1280 {
		t.Fatalf("reduced MTU was not negotiated: %+v", got)
	}
	s.adaptive.mtu = wstransport.DefaultTunnelMTU
	if got := s.negotiateAdaptiveTransport(true, sessionRequest{}, base); got == nil || got.TunnelMTU != 0 {
		t.Fatalf("legacy adaptive response changed under default MTU: %+v", got)
	}
}

func TestAdaptiveCarrierAlternateUDP_NegotiatesOnlyWithSelectionSupport(t *testing.T) {
	s := &Server{adaptive: &adaptiveServerPlane{
		mtu:          wstransport.DefaultTunnelMTU,
		udp:          &udpProofRegistry{port: 31820},
		alternateUDP: &udpProofRegistry{port: 31821},
	}}
	s.Config.Network.AdvertisedEndpoint = "127.0.0.1:51820"
	legacy := []string{
		protocol.CapabilityAdaptiveCarrierV1, protocol.CapabilityAdaptiveUDPV1,
		protocol.CapabilityAdaptiveUDPSelectV1, protocol.CapabilityAdaptivePerformanceV1,
		protocol.CapabilityAdaptivePathSelectV1,
	}
	info := s.negotiateAdaptiveTransport(true, sessionRequest{}, legacy)
	if info == nil || info.DirectUDP != "127.0.0.1:31820" || !info.UDPSelect || info.AlternateUDP != "" {
		t.Fatalf("older adaptive client received unexpected listeners: %+v", info)
	}
	modern := append(legacy, protocol.CapabilityAdaptiveUDPAltV1)
	info = s.negotiateAdaptiveTransport(true, sessionRequest{}, modern)
	if info == nil || info.AlternateUDP != "127.0.0.1:31821" {
		t.Fatalf("new peer did not negotiate alternate UDP: %+v", info)
	}
	if got := s.negotiateAdaptiveTransport(true, sessionRequest{RequiredTransportCapabilities: []string{
		protocol.CapabilityAdaptiveUDPAltV1,
	}}, legacy); got != nil {
		t.Fatal("server accepted a required alternate capability that the peer did not offer")
	}
}

func TestAdaptiveMultiLane_ChildCarrierNegotiatesSeparately(t *testing.T) {
	s := &Server{adaptive: &adaptiveServerPlane{
		mtu: wstransport.DefaultTunnelMTU, maxLanes: 3,
		udp: &udpProofRegistry{port: 31820}, alternateUDP: &udpProofRegistry{port: 31821},
	}}
	s.Config.Network.AdvertisedEndpoint = "127.0.0.1:51820"
	legacy := []string{
		protocol.CapabilityAdaptiveCarrierV1, protocol.CapabilityAdaptiveUDPV1,
		protocol.CapabilityAdaptiveUDPSelectV1, protocol.CapabilityAdaptiveUDPAltV1, protocol.CapabilityAdaptivePerformanceV1,
		protocol.CapabilityAdaptivePathSelectV1, protocol.CapabilityMultiLaneV1,
	}
	info := s.negotiateAdaptiveTransport(true, sessionRequest{}, legacy)
	if info == nil || info.MaxLanes != 3 || info.LaneCarriers || info.ChildSession("child").DirectUDP != "" {
		t.Fatalf("older peers did not retain WSS children: %+v", info)
	}
	modern := append(legacy, protocol.CapabilityLaneCarriersV1)
	info = s.negotiateAdaptiveTransport(true, sessionRequest{}, modern)
	if info == nil || !info.LaneCarriers || info.ChildSession("child").AlternateUDP != "127.0.0.1:31821" {
		t.Fatalf("new peers did not negotiate a child carrier: %+v", info)
	}
	s.adaptive.maxLanes = 1
	req := sessionRequest{RequiredTransportCapabilities: []string{protocol.CapabilityLaneCarriersV1}}
	if info := s.negotiateAdaptiveTransport(true, req, modern); info != nil {
		t.Fatal("server accepted required lane carriers with a one-lane cap")
	}
}
