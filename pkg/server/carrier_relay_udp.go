package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// Pending allocations own a slot until the requesting operation completes.
// Published allocations transfer that slot to the lane until retirement.
type laneRelayAllocation struct {
	request      protocol.CarrierAttachRequest
	registration *relayUDPRegistration
	clientAddr   netip.AddrPort
	localPort    uint16
	lane         *serverCarrierLane
	slot         int
	performance  bool
	scope        protocol.CarrierProofScope
	token        string
	proof        *udpProofOffer
}

func (s *Server) decodeRelayOperation(w http.ResponseWriter, r *http.Request) (protocol.CarrierAttachRequest, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.sessions.Get(carrierBearer(r)); !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return protocol.CarrierAttachRequest{}, false
	}
	request, err := protocol.DecodeCarrierAttach(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil || !protocol.ValidCarrierID(request.Candidate) {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "invalid relay carrier operation")
		return protocol.CarrierAttachRequest{}, false
	}
	return request, true
}

func (s *Server) relayLane(w http.ResponseWriter, r *http.Request, req protocol.CarrierAttachRequest) (Session, *serverCarrierLane, bool) {
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		return v, nil, false
	}
	if !v.Adaptive.RelayUDP || s.adaptive.relayUDP == nil {
		http.NotFound(w, r)
		return v, nil, false
	}
	_, epoch, _ := s.adaptive.bind.LaneState(lane.endpoint)
	if req.Generation != v.Adaptive.AuthGeneration || req.ExpectedEpoch != epoch {
		fail(w, http.StatusConflict, "stale_carrier_state", "carrier state changed")
		return v, nil, false
	}
	return v, lane, true
}

func (s *Server) reserveRelayAllocation(w http.ResponseWriter, r *http.Request, req protocol.CarrierAttachRequest) (*adaptiveServerPlane, *laneRelayAllocation) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.relayLane(w, r, req)
	if !ok {
		return nil, nil
	}
	p, now := s.adaptive, time.Now()
	limit := 1
	if v.Adaptive.RelayPerformance {
		limit = len(lane.relayAllocations)
	}
	slot := -1
	for i, active := range lane.relayAllocations[:limit] {
		if active == nil {
			slot = i
			continue
		}
		if active.request == req && active.proof != nil && active.proof.qualifiedUntil.IsZero() &&
			now.Before(active.proof.expires) && s.currentRelay(active.registration) {
			write(w, http.StatusOK, active.offer(now))
			return nil, nil
		}
	}
	if slot == -1 {
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "relay allocation already pending or current")
		return nil, nil
	}
	var registration *relayUDPRegistration
	if now.Before(lane.relayCatalog.expires) {
		for _, candidate := range lane.relayCatalog.offers {
			if candidate.id == req.Candidate {
				registration = candidate.registration
				break
			}
		}
	}
	if registration == nil || registration.ws == nil || !s.currentRelay(registration) {
		fail(w, http.StatusConflict, "stale_relay_offer", "relay candidate is unavailable")
		return nil, nil
	}
	clientAddr, err := netip.ParseAddrPort(registration.addr)
	if err != nil || !validAdaptiveUDPAddress(clientAddr.Addr().Unmap()) || clientAddr.Port() == 0 {
		fail(w, http.StatusConflict, "relay_endpoint_unavailable", "relay requires a literal UDP endpoint")
		return nil, nil
	}
	clientAddr = netip.AddrPortFrom(clientAddr.Addr().Unmap(), clientAddr.Port())
	for _, existing := range lane.relayAllocations {
		if existing != nil && (existing.registration.owner == registration.owner || existing.clientAddr == clientAddr) {
			fail(w, http.StatusConflict, "relay_already_attached", "relay endpoint already belongs to this lane")
			return nil, nil
		}
	}
	port, open := p.bind.CarrierPort(protocol.CarrierRelayUDP)
	last, found, err := p.data.stack.LastHandshake(v.WireGuardPublicKey)
	if !open || port == 0 || err != nil || !found || last.IsZero() || now.Sub(last) > 3*time.Minute {
		fail(w, http.StatusConflict, "wireguard_unconfirmed", "existing WireGuard lane is unavailable or unconfirmed")
		return nil, nil
	}
	select {
	case p.relaySlots <- struct{}{}:
	default:
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "adaptive relay budget exhausted")
		return nil, nil
	}
	if !lane.reserveCarrierRequest(w, req.RequestID, now) {
		<-p.relaySlots
		return nil, nil
	}
	if v.Adaptive.RelayPerformance {
		maximum := s.Config.Relay.PerformanceMaxAllocationsPerRelay
		if maximum == 0 {
			maximum = adaptiveRelaySlots / 2
		}
		if !registration.reservePerformance(maximum) {
			<-p.relaySlots
			w.Header().Set("Retry-After", "1")
			fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "relay member allocation budget exhausted")
			return nil, nil
		}
	}
	parent, _ := protocol.ParseCarrierID(v.Adaptive.ParentID)
	id, _ := protocol.ParseCarrierID(v.Adaptive.LaneID)
	x := &laneRelayAllocation{request: req, registration: registration, clientAddr: clientAddr, localPort: port, lane: lane,
		slot: slot, performance: v.Adaptive.RelayPerformance,
		scope: protocol.CarrierProofScope{Parent: parent, Lane: id, AuthGeneration: req.Generation, PathEpoch: req.ExpectedEpoch}}
	lane.relayAllocations[slot] = x
	return p, x
}

func (s *Server) currentRelay(registration *relayUDPRegistration) bool {
	return s.relayPool.Load() == registration.pool && registration.current()
}

// The relay allocates a distinct server-leg port. Constrain that leg to the
// advertised relay IP and substitute it for a wildcard returned by the pool.
func relayServerEndpoint(client netip.AddrPort, raw string) (netip.AddrPort, bool) {
	server, err := netip.ParseAddrPort(raw)
	if err != nil || server.Port() == 0 || server.Port() == client.Port() || server.Addr().Zone() != "" ||
		(!server.Addr().IsUnspecified() && server.Addr().Unmap() != client.Addr().Unmap()) {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(client.Addr().Unmap(), server.Port()), true
}

func (s *Server) carrierRelayPrepare(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeRelayOperation(w, r)
	if !ok {
		return
	}
	p, x := s.reserveRelayAllocation(w, r, req)
	if x == nil {
		return
	}
	// Let the bounded control exchange finish after a caller disconnects so a
	// returned relay token can still be released. Publication rechecks ownership.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), udpRelayAllocateTimeout)
	defer cancel()
	token, serverAddr, err := x.registration.agent.allocateUDPSession(ctx, x.registration.ws)
	remote, usable := relayServerEndpoint(x.clientAddr, serverAddr)
	_, validToken := protocol.ParseCarrierTicket(token)
	var proof *udpProofOffer
	if err == nil && usable && validToken && r.Context().Err() == nil && s.currentRelay(x.registration) {
		next := &udpProofOffer{request: req, scope: x.scope, size: wstransport.MaxWireGuardDatagram(p.mtu),
			expectedRemote: remote, localPort: x.localPort}
		if _, err = rand.Read(next.scope.Candidate[:]); err == nil {
			_, err = rand.Read(next.key[:])
		}
		if err == nil && p.relayUDP.socket.SendControl(wstransport.FrameRelayBind, []byte(token), remote.String()) == nil {
			proof = next
		}
	}
	if !s.publishRelayAllocation(w, r, p, x, token, proof) {
		p.releaseRelaySlot(x, token)
	}
}

func (s *Server) publishRelayAllocation(w http.ResponseWriter, r *http.Request, p *adaptiveServerPlane, x *laneRelayAllocation, token string, proof *udpProofOffer) bool {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if r.Context().Err() != nil || s.adaptive != p || x.lane.relayAllocations[x.slot] != x || !s.currentRelay(x.registration) {
		if x.lane.relayAllocations[x.slot] == x {
			x.lane.relayAllocations[x.slot] = nil
		}
		fail(w, http.StatusConflict, "stale_relay_offer", "relay allocation was superseded")
		return false
	}
	v, lane, ok := s.relayLane(w, r, x.request)
	if !ok || lane != x.lane {
		x.lane.relayAllocations[x.slot] = nil
		return false
	}
	if proof == nil {
		lane.relayAllocations[x.slot] = nil
		fail(w, http.StatusServiceUnavailable, protocol.ErrorNoCapacity, "relay allocation unavailable")
		return false
	}
	now := time.Now()
	proof.expires = minTime(v.Expires, now.Add(carrierTicketTTL))
	x.token, x.proof = token, proof
	p.relayUDP.mu.Lock()
	p.relayUDP.offers[proof.scope.Candidate] = proof
	p.relayUDP.mu.Unlock()
	write(w, http.StatusOK, x.offer(now))
	return true
}

func (x *laneRelayAllocation) offer(now time.Time) protocol.CarrierRelayUDPOffer {
	return protocol.CarrierRelayUDPOffer{
		CarrierUDPOffer: protocol.CarrierUDPOffer{
			ID: base64.RawURLEncoding.EncodeToString(x.proof.scope.Candidate[:]), ProofKey: base64.RawURLEncoding.EncodeToString(x.proof.key[:]),
			DatagramMax: x.proof.size, ExpiresInMS: x.proof.expires.Sub(now).Milliseconds(),
		},
		RelayAddr: x.clientAddr.String(), BindToken: x.token,
	}
}

func (x *laneRelayAllocation) pathID() string {
	if x.proof == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(x.proof.scope.Candidate[:])
}

func (l *serverCarrierLane) relayPath(id string) *laneRelayAllocation {
	for _, allocation := range l.relayAllocations {
		if allocation != nil && id != "" && allocation.pathID() == id {
			return allocation
		}
	}
	return nil
}

func (p *adaptiveServerPlane) extendRelayPath(lane *serverCarrierLane, x *laneRelayAllocation, until time.Time) {
	x.proof.qualifiedUntil = until
	p.bind.ExtendPath(lane.endpoint, x.pathID(), until)
}

func (s *Server) carrierRelayQualify(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeRelayOperation(w, r)
	if !ok {
		return
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.relayLane(w, r, req)
	if !ok {
		return
	}
	var x *laneRelayAllocation
	for _, allocation := range lane.relayAllocations {
		if allocation != nil && allocation.request == req {
			x = allocation
			break
		}
	}
	if x == nil || x.proof == nil || !s.currentRelay(x.registration) {
		fail(w, http.StatusConflict, "stale_relay_offer", "relay allocation is unavailable")
		return
	}
	p, proof, now := s.adaptive, x.proof, time.Now()
	candidate := x.pathID()
	if proof.qualifiedUntil.IsZero() {
		p.relayUDP.mu.Lock()
		ready, endpoint := proof.ready, proof.endpoint
		p.relayUDP.mu.Unlock()
		if !ready || !now.Before(proof.expires) {
			fail(w, http.StatusConflict, "udp_proof_pending", "both relay UDP directions must be proven")
			return
		}
		until := minTime(v.Expires, now.Add(udpQualificationLifetime))
		if err := p.bind.InstallQualifiedPath(lane.endpoint, req.ExpectedEpoch, wstransport.QualifiedPath{
			ID: candidate, Carrier: protocol.CarrierRelayUDP, Endpoint: endpoint,
			SendMax: proof.size, ReceiveMax: proof.size, ValidUntil: until,
		}); err != nil {
			fail(w, http.StatusConflict, "udp_path_unavailable", "could not qualify this relay path")
			return
		}
		p.relayUDP.forget(proof)
		proof.qualifiedUntil = until
	}
	if !now.Before(proof.qualifiedUntil) {
		fail(w, http.StatusConflict, "udp_offer_expired", "relay qualification expired")
		return
	}
	write(w, http.StatusOK, protocol.CarrierUDPStatus{Candidate: candidate, DatagramMax: proof.size,
		ExpiresInMS: proof.qualifiedUntil.Sub(now).Milliseconds()})
}

func (p *adaptiveServerPlane) releaseRelaySlot(x *laneRelayAllocation, token string) {
	if token != "" {
		x.registration.agent.releaseUDPSession(token, x.registration.ws)
	}
	if x.performance {
		x.registration.releasePerformance()
	}
	<-p.relaySlots
}

func (p *adaptiveServerPlane) retireRelayAllocation(lane *serverCarrierLane, slot int) {
	x := lane.relayAllocations[slot]
	lane.relayAllocations[slot] = nil
	if x == nil || x.proof == nil {
		return // a detached pending request still owns its slot
	}
	p.relayUDP.forget(x.proof)
	if !x.proof.qualifiedUntil.IsZero() {
		fallback := protocol.CarrierWSS
		if x.performance {
			laneID := base64.RawURLEncoding.EncodeToString(x.scope.Lane[:])
			if _, err := p.ws.CarrierEndpoint(laneID); err != nil {
				for _, candidate := range lane.relayAllocations {
					if candidate != nil && candidate.proof != nil && !candidate.proof.qualifiedUntil.IsZero() &&
						candidate.registration.current() && !candidate.expired(time.Now()) {
						fallback = candidate.pathID()
						break
					}
				}
			}
		}
		p.bind.FailPath(lane.endpoint, x.pathID(), x.proof.endpoint, fallback)
	}
	go p.releaseRelaySlot(x, x.token)
}

func (p *adaptiveServerPlane) retireRelayAllocations(lane *serverCarrierLane) {
	for i := range lane.relayAllocations {
		p.retireRelayAllocation(lane, i)
	}
}

func (s *Server) reapRelayAllocations(now time.Time) {
	p := s.adaptive
	if p == nil || p.relayUDP == nil {
		return
	}
	for _, lane := range p.lanes {
		for i, x := range lane.relayAllocations {
			if x != nil && (!s.currentRelay(x.registration) || x.expired(now)) {
				p.retireRelayAllocation(lane, i)
			}
		}
	}
	p.refreshRelayBindings(now)
}

// A single batch owns server-leg keepalives, outside the operation lock.
func (p *adaptiveServerPlane) refreshRelayBindings(now time.Time) {
	if now.Before(p.nextRelayBind) {
		return
	}
	p.nextRelayBind = now.Add(10 * time.Second)
	type binding struct{ address, token string }
	var due []binding
	for _, lane := range p.lanes {
		primary, _, _ := p.bind.LaneState(lane.endpoint)
		for _, x := range lane.relayAllocations {
			if x != nil && x.proof != nil && !x.proof.qualifiedUntil.IsZero() && (x.performance || x.pathID() == primary) {
				due = append(due, binding{x.proof.expectedRemote.String(), x.token})
			}
		}
	}
	if len(due) == 0 {
		return
	}
	select {
	case p.relayBindingBatch <- struct{}{}:
		go func() {
			defer func() { <-p.relayBindingBatch }()
			for _, b := range due {
				_ = p.relayUDP.socket.SendControl(wstransport.FrameRelayBind, []byte(b.token), b.address)
			}
		}()
	default:
	}
}

func (x *laneRelayAllocation) expired(now time.Time) bool {
	if x.proof == nil {
		return false
	}
	if !x.proof.qualifiedUntil.IsZero() {
		return !now.Before(x.proof.qualifiedUntil)
	}
	return !now.Before(x.proof.expires)
}
