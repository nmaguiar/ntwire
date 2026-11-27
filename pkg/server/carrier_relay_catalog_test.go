package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func startRelayCatalogServer(t *testing.T, pool *RelayPool) *Server {
	t.Helper()
	cfg := Config{}
	cfg.Transport.Adaptive = true
	cfg.Transport.AdaptiveMaxLanes = 2
	cfg.Network.TunnelCIDR = "100.73.0.0/24"
	cfg.Listen.WireGuard = "127.0.0.1:0"
	s := New(cfg, nil)
	s.SetRelayPool(pool)
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func relayCatalogSession(t *testing.T, s *Server, ip string, catalog bool) Session {
	t.Helper()
	caps := []string{protocol.CapabilityAdaptiveCarrierV1}
	if catalog {
		caps = append(caps, protocol.CapabilityAdaptiveRelayCatalogV1, protocol.CapabilityMultiLaneV1)
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	info := s.negotiateAdaptiveTransport(true, sessionRequest{}, caps)
	if info == nil || info.RelayCatalog != catalog {
		t.Fatalf("unexpected relay catalog negotiation: %+v", info)
	}
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := s.adaptive.add(info, key.Public, ip)
	if err != nil {
		t.Fatal(err)
	}
	return s.sessions.Create(CreateParams{TTL: time.Minute, TunnelIP: ip,
		WireGuardPublicKey: key.Public, Adaptive: info, FlowLifetime: ctx})
}

func fetchRelayCatalog(t *testing.T, s *Server, bearer, lane, scheme string, code int) protocol.RelayCandidateCatalog {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, scheme+"://fixture/v1/transport/lanes/"+lane+"/relay-candidates", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != code || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("catalog status %d, want %d", w.Code, code)
	}
	var reply protocol.RelayCandidateCatalog
	if code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if reply.LaneID != lane || reply.AuthGeneration == 0 || len(reply.Candidates) > relayCatalogLimit || reply.ExpiresInMS > 15000 {
			t.Fatalf("invalid catalog descriptor: %+v", reply)
		}
		for _, id := range reply.Candidates {
			if !protocol.ValidCarrierID(id) {
				t.Fatal("candidate ID is not an opaque carrier ID")
			}
		}
	}
	return reply
}

func TestAdaptiveRelayCatalog_ScopesOffersAndInvalidatesGeneration(t *testing.T) {
	cfg := RelayConfig{Name: "home", IdentityFile: "unused"}
	for i := 0; i < relayCatalogLimit+2; i++ {
		cfg.Endpoints = append(cfg.Endpoints, RelayEndpoint{URL: fmt.Sprintf("wss://relay-%d.test:8443", i)})
	}
	pool, err := NewRelayPool(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	for _, m := range pool.members {
		pool.update(m, true, protocol.RelayRegisterResponse{Domain: "relay.test", UDPRelayAddr: "127.0.0.1:1234"})
	}
	s := startRelayCatalogServer(t, pool)
	a := relayCatalogSession(t, s, "100.73.0.2", true)
	b := relayCatalogSession(t, s, "100.73.0.3", true)
	old := relayCatalogSession(t, s, "100.73.0.4", false)
	get := func(v Session) protocol.RelayCandidateCatalog {
		t.Helper()
		return fetchRelayCatalog(t, s, v.Token, v.Adaptive.LaneID, "https", http.StatusOK)
	}
	fetchRelayCatalog(t, s, "", a.Adaptive.LaneID, "https", http.StatusUnauthorized)
	fetchRelayCatalog(t, s, a.Token, a.Adaptive.LaneID, "http", http.StatusUnauthorized)
	fetchRelayCatalog(t, s, b.Token, a.Adaptive.LaneID, "https", http.StatusNotFound)
	fetchRelayCatalog(t, s, old.Token, old.Adaptive.LaneID, "https", http.StatusNotFound)
	initial := get(a)
	if len(initial.Candidates) != relayCatalogLimit || initial.ExpiresInMS <= 0 ||
		!slices.Equal(initial.Candidates, get(a).Candidates) ||
		slices.Contains(get(b).Candidates, initial.Candidates[0]) {
		t.Fatal("catalog does not preserve bounded, lane-scoped offers")
	}
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	create, err := json.Marshal(protocol.LaneRequest{RequestID: "AQAAAAAAAAAAAAAAAAAAAA", Generation: 1, WireGuardPublicKey: key.Public})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://fixture/v1/session/lanes", bytes.NewReader(create))
	req.Header.Set("Authorization", "Bearer "+a.Token)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	var child protocol.LaneDescriptor
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &child) != nil || !child.Adaptive.RelayCatalog {
		t.Fatalf("child did not inherit relay catalog: %s", res.Body)
	}
	childOffers := fetchRelayCatalog(t, s, a.Token, child.Adaptive.LaneID, "https", http.StatusOK)
	if len(childOffers.Candidates) != relayCatalogLimit || slices.Contains(childOffers.Candidates, initial.Candidates[0]) {
		t.Fatal("child reused a parent candidate ID")
	}
	fetchRelayCatalog(t, s, b.Token, child.Adaptive.LaneID, "https", http.StatusNotFound)

	member := pool.members[0]
	pool.update(member, true, protocol.RelayRegisterResponse{Domain: "relay.test", UDPRelayAddr: "127.0.0.1:1234"})
	refreshed := get(a)
	if slices.Contains(refreshed.Candidates, initial.Candidates[0]) {
		t.Fatal("registration reconnect retained the old offer")
	}
	s.operationMu.Lock()
	s.adaptive.lanes[a.Adaptive.LaneID].relayCatalog.expires = time.Now().Add(-time.Millisecond)
	s.operationMu.Unlock()
	afterExpiry := get(a)
	if slices.Contains(afterExpiry.Candidates, refreshed.Candidates[0]) {
		t.Fatal("expired candidate was reused")
	}
	s.operationMu.Lock()
	renewed, ok := s.sessions.renew(a.Token, nil, time.Minute, protocol.ClientInfo{}, nil)
	if ok {
		s.adaptive.renew(renewed)
	}
	s.operationMu.Unlock()
	if !ok {
		t.Fatal("renew failed")
	}
	fetchRelayCatalog(t, s, a.Token, a.Adaptive.LaneID, "https", http.StatusUnauthorized)
	if after := get(renewed); after.AuthGeneration != 2 || slices.Contains(after.Candidates, afterExpiry.Candidates[0]) {
		t.Fatal("renewal reused candidate from previous authorization generation")
	}
	if after := fetchRelayCatalog(t, s, renewed.Token, child.Adaptive.LaneID, "https", http.StatusOK); after.AuthGeneration != 2 ||
		slices.Contains(after.Candidates, childOffers.Candidates[0]) {
		t.Fatal("renewal reused a child offer from the previous authorization generation")
	}
	for _, m := range pool.members {
		pool.update(m, false, protocol.RelayRegisterResponse{})
	}
	pool.update(pool.members[0], true, protocol.RelayRegisterResponse{Domain: "untrusted.test", UDPRelayAddr: "127.0.0.1:1234"})
	pool.update(pool.members[1], true, protocol.RelayRegisterResponse{Domain: "relay.test", UDPRelayAddr: "127.0.0.1:0"})
	if after := get(renewed); after.Candidates == nil || len(after.Candidates) != 0 || after.ExpiresInMS != 0 {
		t.Fatalf("disconnected catalog = %+v", after)
	}
	s.operationMu.Lock()
	s.sessions.Delete(renewed.Token)
	s.dropSession(renewed)
	s.operationMu.Unlock()
	fetchRelayCatalog(t, s, renewed.Token, child.Adaptive.LaneID, "https", http.StatusUnauthorized)
}

func TestAdaptiveRelayCatalog_MemberBudgetAndExclusions(t *testing.T) {
	pool, err := NewRelayPool(RelayConfig{Name: "home", IdentityFile: "unused", Endpoints: []RelayEndpoint{
		{URL: "wss://allowed.test"},
		{URL: "wss://legacy-only.test", DisablePerformanceRouting: true},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	response := protocol.RelayRegisterResponse{Domain: "relay.test", UDPRelayAddr: "127.0.0.1:1234"}
	for _, member := range pool.members {
		pool.update(member, true, response)
	}
	legacy, allowed := pool.udpRegistrations(false), pool.udpRegistrations(true)
	if len(legacy) != 2 || len(allowed) != 1 || allowed[0] != legacy[0] {
		t.Fatal("performance exclusion changed the legacy relay set")
	}
	old := allowed[0]
	if !old.reservePerformance(1) || old.reservePerformance(1) || legacy[1].reservePerformance(1) {
		t.Fatal("per-member admission or exclusion failed")
	}
	pool.update(pool.members[0], true, response)
	next := pool.udpRegistrations(true)[0]
	if old.performanceID == next.performanceID || old.reservePerformance(1) || next.reservePerformance(1) {
		t.Fatal("re-registration bypassed the member quota")
	}
	old.releasePerformance()
	if !next.reservePerformance(1) {
		t.Fatal("retirement did not free the member quota")
	}
	next.releasePerformance()
}

func startRelayCatalogPool(t *testing.T, count int) *RelayPool {
	t.Helper()
	idPath := filepath.Join(t.TempDir(), "identity")
	if _, err := sshkey.GenerateIdentityFile(idPath); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(idPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	cfg := RelayConfig{Name: "home", IdentityFile: idPath}
	for range count {
		r, _ := startLoopbackUDPRelay(t, string(key))
		cfg.Endpoints = append(cfg.Endpoints, RelayEndpoint{URL: "wss://" + r.AgentsAddr().String(), Fingerprint: r.Fingerprint()})
	}
	pool, err := NewRelayPool(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool.Run(t.Context())
	t.Cleanup(func() { _ = pool.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for len(pool.udpRegistrations(false)) != count {
		select {
		case <-ctx.Done():
			t.Fatal("configured relays failed to register")
		case <-time.After(10 * time.Millisecond):
		}
	}
	return pool
}

func TestAdaptiveRelayCatalog_RegisteredRelaysCarryOpaqueProof(t *testing.T) {
	pool := startRelayCatalogPool(t, 2)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s := startRelayCatalogServer(t, pool)
	session := relayCatalogSession(t, s, "100.73.0.2", true)
	catalog := fetchRelayCatalog(t, s, session.Token, session.Adaptive.LaneID, "https", http.StatusOK)
	if len(catalog.Candidates) != 2 {
		t.Fatal("expected a candidate from each configured live relay")
	}
	parent, _ := protocol.ParseCarrierID(session.Adaptive.ParentID)
	lane, _ := protocol.ParseCarrierID(session.Adaptive.LaneID)
	for _, offer := range s.adaptive.lanes[session.Adaptive.LaneID].relayCatalog.offers {
		if success, failure := offer.registration.agent.AllocationStats(); success != 0 || failure != 0 {
			t.Fatal("catalog discovery attempted a relay allocation")
		}
		candidate, _ := protocol.ParseCarrierID(offer.id)
		scope := protocol.CarrierProofScope{Parent: parent, Lane: lane, Candidate: candidate, AuthGeneration: 1}
		verifyRelayCatalogProof(t, ctx, offer.registration, scope)
	}
}

func verifyRelayCatalogProof(t *testing.T, ctx context.Context, registration *relayUDPRegistration, scope protocol.CarrierProofScope) {
	t.Helper()
	token, serverAddr, err := registration.agent.AllocateUDPSession(ctx)
	if err != nil || token == "" || serverAddr == "" {
		t.Fatalf("registered relay allocation failed: %v", err)
	}
	defer registration.agent.ReleaseUDPSession(token)
	bind := func(addr string) (*net.UDPConn, netip.AddrPort) {
		t.Helper()
		endpoint, err := netip.ParseAddrPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.WriteToUDPAddrPort(wstransport.EncodeControlFrame(wstransport.FrameRelayBind, []byte(token)), endpoint); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 128)
		n, from, err := c.ReadFromUDPAddrPort(reply)
		if err != nil || from != endpoint || !bytes.Equal(reply[:n], wstransport.EncodeControlFrame(wstransport.FrameRelayBindAck, nil)) {
			t.Fatalf("relay bind acknowledgement invalid: %v", err)
		}
		return c, endpoint
	}
	serverLeg, serverEndpoint := bind(serverAddr)
	clientLeg, clientEndpoint := bind(registration.addr)
	key := [32]byte{1}
	probe := protocol.CarrierProof{Kind: protocol.CarrierProbe, Direction: protocol.CarrierUpload, Nonce: protocol.CarrierID{1}, Size: 1452}
	verify := func(sender, receiver *net.UDPConn, to, wantFrom netip.AddrPort) {
		t.Helper()
		_ = sender.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
		frame := protocol.EncodeCarrierProof(scope, key, probe)
		if _, err := sender.WriteToUDPAddrPort(frame, to); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, protocol.CarrierProofMax)
		n, from, err := receiver.ReadFromUDPAddrPort(buf)
		got, authenticated := protocol.DecodeCarrierProof(scope, key, buf[:n])
		if err != nil || from != wantFrom || !authenticated || got != probe || !bytes.Equal(buf[:n], frame) {
			t.Fatalf("relay altered or failed to forward scoped proof in direction %d: %v", probe.Direction, err)
		}
	}
	verify(clientLeg, serverLeg, clientEndpoint, serverEndpoint)
	probe.Direction = protocol.CarrierDownload
	verify(serverLeg, clientLeg, serverEndpoint, clientEndpoint)
}
