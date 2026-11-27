package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestAdaptiveRelayUDP_PrepareQualifyAndRelease(t *testing.T) {
	pool := startRelayCatalogPool(t, 2)
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		if conn, err := target.Accept(); err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	s, identity, _ := newTestServer(t, []TunnelConfig{{Name: "echo", VirtualPort: 18080, Target: target.Addr().String(), Allow: []string{"*"}}})
	s.Config.Relay.Enabled, s.Config.Relay.AdaptiveUDP, s.Config.Transport.Adaptive = true, true, true
	s.Config.Network.TunnelCIDR = "100.73.0.0/24"
	s.Config.Listen.WireGuard = "127.0.0.1:0"
	s.SetRelayPool(pool)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	handler := s.Handler()
	https := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The test drives allocation requests directly against Handler.
		// Keep the live client's background worker from claiming the slot.
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/relay/prepare") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer https.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: https.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := client.ConnectWithOptions(https.URL, identity, protocol.ClientInfo{}, client.Options{
		AdaptiveCarrier: true, CAFile: ca, NoWebUI: true, NoBrowser: true, NoSystemProxy: true,
		Ports: map[string]int{"echo": 0}, StatusFile: filepath.Join(dir, "status.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	info, bearer := c.Response.Adaptive, c.Response.Token
	if info == nil || !info.RelayUDP || !info.RelayCatalog {
		t.Fatal("relay UDP qualification was not negotiated")
	}
	conn, err := net.DialTimeout("tcp", c.State().Tunnels[0].LocalAddress, 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var echo [1]byte
	if _, err := io.ReadFull(conn, echo[:]); err != nil || echo[0] != 42 {
		t.Fatalf("could not confirm the existing WireGuard lane: %v", err)
	}
	catalog := fetchRelayCatalog(t, s, bearer, info.LaneID, "https", http.StatusOK)
	if len(catalog.Candidates) != 2 {
		t.Fatal("two real relays should be available to the lane")
	}
	s.operationMu.Lock()
	p := s.adaptive
	lane := p.lanes[info.LaneID]
	selected, epoch, _ := p.bind.LaneState(lane.endpoint)
	s.operationMu.Unlock()
	if selected != protocol.CarrierWSS {
		t.Fatalf("initial carrier = %s", selected)
	}
	requestID, err := randomRequestID()
	if err != nil {
		t.Fatal(err)
	}
	req := protocol.CarrierAttachRequest{RequestID: requestID, Candidate: catalog.Candidates[0],
		Generation: info.AuthGeneration, ExpectedEpoch: epoch}
	call := func(suffix, token string, request protocol.CarrierAttachRequest) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "https://fixture/v1/transport/lanes/"+info.LaneID+"/relay/"+suffix, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	stale := req
	stale.Generation++
	if w := call("prepare", bearer, stale); w.Code != http.StatusConflict {
		t.Fatalf("stale authorization returned %d", w.Code)
	}
	if w := call("prepare", "", req); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized prepare returned %d", w.Code)
	}
	first := call("prepare", bearer, req)
	var offer protocol.CarrierRelayUDPOffer
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &offer) != nil || offer.BindToken == "" {
		t.Fatalf("relay prepare returned %d", first.Code)
	}
	var duplicate protocol.CarrierRelayUDPOffer
	if w := call("prepare", bearer, req); w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &duplicate) != nil ||
		duplicate.ID != offer.ID || duplicate.BindToken != offer.BindToken {
		t.Fatal("prepare replay did not reuse its allocation")
	}
	other := req
	other.Candidate = catalog.Candidates[1]
	if w := call("prepare", bearer, other); w.Code != http.StatusTooManyRequests {
		t.Fatalf("a competing allocation returned %d", w.Code)
	}
	if w := call("qualify", bearer, req); w.Code != http.StatusConflict {
		t.Fatalf("qualifying without UDP proof returned %d", w.Code)
	}

	sendRelayUDPProof(t, *info, epoch, offer)
	deadline := time.Now().Add(2 * time.Second)
	for {
		w := call("qualify", bearer, req)
		if w.Code == http.StatusOK {
			var status protocol.CarrierUDPStatus
			if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status.Candidate != offer.ID || status.DatagramMax != offer.DatagramMax {
				t.Fatalf("invalid qualified path: %v", err)
			}
			break
		}
		if time.Now().After(deadline) || w.Code != http.StatusConflict {
			t.Fatalf("fully proven relay failed qualification: %d %s", w.Code, w.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.operationMu.Lock()
	primary, _, _ := p.bind.LaneState(lane.endpoint)
	s.reapRelayAllocations(time.Now().Add(time.Minute))
	retired := lane.relayAllocations[0] == nil && lane.relayAllocations[1] == nil
	s.operationMu.Unlock()
	if primary != protocol.CarrierWSS || !retired {
		t.Fatal("qualification changed the primary or expiry failed to retire the relay")
	}
	deadline = time.Now().Add(2 * time.Second)
	for len(p.relaySlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("expired allocation retained its capacity slot")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := call("qualify", bearer, req); w.Code != http.StatusConflict {
		t.Fatalf("retired proof could be reused: %d", w.Code)
	}
	registration := pool.udpRegistrations(false)[0]
	releaseCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for {
		token, address, err := registration.agent.AllocateUDPSession(releaseCtx)
		if token != "" && address != "" {
			registration.agent.ReleaseUDPSession(token)
			break
		}
		if err != nil || releaseCtx.Err() != nil {
			t.Fatalf("relay could not reclaim its single port after expiry: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Replacing a relay registration must fence a still-unexpired catalog ID.
	pool.mu.Lock()
	secondMember, secondResponse := pool.members[1], pool.members[1].response
	pool.mu.Unlock()
	pool.update(secondMember, true, secondResponse)
	requestID, err = randomRequestID()
	if err != nil {
		t.Fatal(err)
	}
	_, epoch, _ = p.bind.LaneState(lane.endpoint)
	other.RequestID, other.ExpectedEpoch = requestID, epoch
	if w := call("prepare", bearer, other); w.Code != http.StatusConflict {
		t.Fatalf("superseded registration was allocatable: %d", w.Code)
	}
	newCatalog := fetchRelayCatalog(t, s, bearer, info.LaneID, "https", http.StatusOK)
	if len(newCatalog.Candidates) != 2 {
		t.Fatal("re-registration lost a configured relay")
	}
	other.Candidate = newCatalog.Candidates[1]
	nonpreferred := call("prepare", bearer, other)
	var secondOffer protocol.CarrierRelayUDPOffer
	if nonpreferred.Code != http.StatusOK || json.Unmarshal(nonpreferred.Body.Bytes(), &secondOffer) != nil ||
		secondOffer.RelayAddr != secondResponse.UDPRelayAddr || secondOffer.RelayAddr == offer.RelayAddr {
		t.Fatalf("nonpreferred relay did not provide an independent allocation: %d", nonpreferred.Code)
	}
	s.operationMu.Lock()
	session, _ := s.sessions.Get(bearer)
	s.sessions.Delete(bearer)
	s.dropSession(session)
	s.operationMu.Unlock()
	if w := call("qualify", bearer, other); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked lane could qualify a relay lease: %d", w.Code)
	}
}

func sendRelayUDPProof(t *testing.T, session protocol.AdaptiveSession, epoch uint64, offer protocol.CarrierRelayUDPOffer) {
	t.Helper()
	parent, _ := protocol.ParseCarrierID(session.ParentID)
	lane, _ := protocol.ParseCarrierID(session.LaneID)
	id, ok := protocol.ParseCarrierID(offer.ID)
	key, err := base64.RawURLEncoding.DecodeString(offer.ProofKey)
	if !ok || err != nil || len(key) != 32 || offer.DatagramMax != wstransport.MaxWireGuardDatagram(session.TunnelMTU) {
		t.Fatal("invalid proof credential")
	}
	scope := protocol.CarrierProofScope{Parent: parent, Lane: lane, Candidate: id, AuthGeneration: session.AuthGeneration, PathEpoch: epoch}
	relayAddr := netip.MustParseAddrPort(offer.RelayAddr)
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(relayAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(4 * time.Second))
	send := func(frame []byte) {
		t.Helper()
		if _, err := c.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, protocol.CarrierProofMax)
	read := func(stage string) []byte {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		return buf[:n]
	}
	send(wstransport.EncodeControlFrame(wstransport.FrameRelayBind, []byte(offer.BindToken)))
	if !bytes.Equal(read("client relay binding"), wstransport.EncodeControlFrame(wstransport.FrameRelayBindAck, nil)) {
		t.Fatal("client leg failed to bind")
	}
	proof := protocol.CarrierProof{Kind: protocol.CarrierProbe, Direction: protocol.CarrierUpload,
		Nonce: protocol.CarrierID{1}, Size: uint16(offer.DatagramMax)}
	send(protocol.EncodeCarrierProof(scope, [32]byte(key), proof))
	if ack, ok := protocol.DecodeCarrierProof(scope, [32]byte(key), read("upload acknowledgement")); !ok || ack.Kind != protocol.CarrierACK || ack.Nonce != proof.Nonce {
		t.Fatal("invalid upload acknowledgement")
	}
	proof.Nonce[0]++
	send(protocol.EncodeCarrierProof(scope, [32]byte(key), proof))
	down, ok := protocol.DecodeCarrierProof(scope, [32]byte(key), read("download challenge"))
	if !ok || down.Kind != protocol.CarrierProbe || down.Direction != protocol.CarrierDownload || down.Size != proof.Size {
		t.Fatal("invalid full-size download challenge")
	}
	down.Kind = protocol.CarrierACK
	send(protocol.EncodeCarrierProof(scope, [32]byte(key), down))
}

func TestRelayServerEndpoint_UsesAdvertisedRelayIP(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.1:443")
	for _, input := range []string{"192.0.2.1:5555", "0.0.0.0:5555", "[::]:5555"} {
		if got, ok := relayServerEndpoint(client, input); !ok || got.String() != "192.0.2.1:5555" {
			t.Fatalf("relay server endpoint %q = %s, %v", input, got, ok)
		}
	}
	for _, input := range []string{"192.0.2.2:5555", "relay.example:5555", "192.0.2.1:0", "192.0.2.1:443"} {
		if _, ok := relayServerEndpoint(client, input); ok {
			t.Fatalf("relay server endpoint accepted %q", input)
		}
	}
}
