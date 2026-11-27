package server

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

const udpQualificationLifetime = 30 * time.Second

type udpProofRegistry struct {
	port   uint16
	socket *wstransport.FilterBind
	mu     sync.Mutex // never takes operationMu or the adaptive bind's mutex
	offers map[protocol.CarrierID]*udpProofOffer
}

type udpProofOffer struct {
	request        protocol.CarrierAttachRequest
	scope          protocol.CarrierProofScope
	key            [32]byte
	expires        time.Time
	size           int
	expectedRemote netip.AddrPort
	localPort      uint16

	// Mutable observation state is owned by the registry until completion.
	remote         protocol.CarrierUDPPath
	endpoint       conn.Endpoint
	firstNonce     protocol.CarrierID
	down           *protocol.CarrierChallenge
	ready          bool
	qualifiedUntil time.Time // published under operationMu after registry removal
}

// The caller holds operationMu and owns the completed proof.
func (p *adaptiveServerPlane) extendUDPPath(lane *serverCarrierLane, candidate string, until time.Time) {
	lane.udpOffers[candidate].qualifiedUntil = until
	p.bind.ExtendPath(lane.endpoint, candidate, until)
}

func (p *adaptiveServerPlane) nativeUDP(candidate string) *udpProofRegistry {
	switch candidate {
	case protocol.CarrierDirectUDP:
		return p.udp
	case protocol.CarrierAlternateUDP:
		return p.alternateUDP
	default:
		return nil
	}
}

func newUDPProofRegistry(port uint16) *udpProofRegistry {
	u := &udpProofRegistry{
		port: port, socket: wstransport.NewFilterBind(wstransport.NewProbeUDPBind()),
		offers: make(map[protocol.CarrierID]*udpProofOffer),
	}
	u.socket.SetRawControlHandler(u.receive)
	return u
}

func (u *udpProofRegistry) forget(offer *udpProofOffer) {
	if u == nil || offer == nil {
		return
	}
	u.mu.Lock()
	delete(u.offers, offer.scope.Candidate)
	clear(offer.key[:])
	u.mu.Unlock()
}

func (u *udpProofRegistry) receive(frame []byte, ep conn.Endpoint) bool {
	if !protocol.IsCarrierProof(frame) {
		return false
	}
	if reply := u.proofReply(frame, ep, time.Now()); reply != nil {
		_ = u.socket.Send([][]byte{reply}, ep)
	}
	return true
}

func (u *udpProofRegistry) proofReply(frame []byte, ep conn.Endpoint, now time.Time) []byte {
	id, ok := protocol.CarrierProofCandidate(frame)
	if !ok {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	offer := u.offers[id]
	if offer == nil || !now.Before(offer.expires) || offer.ready {
		return nil
	}
	if len(frame) != protocol.CarrierProofACKSize && len(frame) != offer.size {
		return nil
	}
	remote, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil || remote.Port() == 0 || !validAdaptiveUDPAddress(remote.Addr()) ||
		(offer.expectedRemote.IsValid() && offer.expectedRemote != remote) {
		return nil
	}
	port := u.port
	if offer.localPort != 0 {
		port = offer.localPort
	}
	path := protocol.CarrierUDPPath{LocalPort: port, Remote: remote}
	if offer.endpoint != nil && offer.remote != path {
		return nil
	}
	if offer.down != nil {
		_, offer.ready = offer.down.AcceptACK(path, frame, now)
		return nil
	}
	proof, ok := protocol.DecodeCarrierProof(offer.scope, offer.key, frame)
	if !ok || proof.Kind != protocol.CarrierProbe || proof.Direction != protocol.CarrierUpload || int(proof.Size) != offer.size {
		return nil
	}
	if offer.endpoint == nil {
		offer.endpoint, offer.remote, offer.firstNonce = ep, path, proof.Nonce
		proof.Kind = protocol.CarrierACK
		return protocol.EncodeCarrierProof(offer.scope, offer.key, proof)
	}
	if proof.Nonce == offer.firstNonce {
		return nil
	}
	// The second full-size request funds the same-size download challenge.
	// Each request has at most one reply, of equal or smaller size.
	down, reply, err := protocol.BeginCarrierChallenge(offer.scope, offer.key, path, protocol.CarrierDownload, proof.Size, now)
	if err != nil {
		return nil
	}
	offer.down = down
	return reply
}

func validAdaptiveUDPAddress(a netip.Addr) bool {
	return a.Zone() == "" && (a.IsGlobalUnicast() || a.IsLoopback())
}

func (s *Server) adaptiveUDPAdvertisement() string {
	if s.adaptive == nil || s.adaptive.udp == nil {
		return ""
	}
	return s.adaptiveDatagramAdvertisement(s.adaptive.udp.port)
}

func (s *Server) adaptiveDatagramAdvertisement(port uint16) string {
	host, _, err := net.SplitHostPort(s.advertisedUDPEndpoint())
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !validAdaptiveUDPAddress(ip) {
		return ""
	}
	return net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(int(port)))
}

func (s *Server) carrierUDPPrepare(w http.ResponseWriter, r *http.Request) {
	request, ok := s.decodeCarrierUDPRequest(w, r)
	if !ok {
		return
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.validateCarrierUDPRequest(w, r, request)
	if !ok {
		return
	}
	p, now := s.adaptive, time.Now()
	registry := p.nativeUDP(request.Candidate)
	if existing := lane.udpOffers[request.Candidate]; existing != nil {
		if existing.request == request && now.Before(existing.expires) && existing.qualifiedUntil.IsZero() {
			writeCarrierUDPOffer(w, existing, now)
			return
		}
		if existing.request.RequestID == request.RequestID {
			fail(w, http.StatusConflict, "udp_offer_reused", "UDP offer already used or expired")
			return
		}
		if now.Before(existing.expires) || now.Before(existing.qualifiedUntil) {
			w.Header().Set("Retry-After", "1")
			fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "UDP qualification already pending or current")
			return
		}
	}
	// Confirm possession of the installed WireGuard key on the existing lane.
	// This is checked before issuing a UDP proof credential, and raw UDP
	// remains receive-disabled until it completes a separate qualification.
	last, found, err := p.data.stack.LastHandshake(v.WireGuardPublicKey)
	if err != nil || !found || last.IsZero() || now.Sub(last) > 3*time.Minute {
		fail(w, http.StatusConflict, "wireguard_unconfirmed", "WireGuard peer has not authenticated")
		return
	}
	parent, _ := protocol.ParseCarrierID(v.Adaptive.ParentID)
	id, _ := protocol.ParseCarrierID(v.Adaptive.LaneID)
	offer := &udpProofOffer{
		request: request, expires: minTime(v.Expires, now.Add(carrierTicketTTL)),
		size:  wstransport.MaxWireGuardDatagram(p.mtu),
		scope: protocol.CarrierProofScope{Parent: parent, Lane: id, AuthGeneration: request.Generation, PathEpoch: request.ExpectedEpoch},
	}
	if _, err := rand.Read(offer.scope.Candidate[:]); err != nil {
		fail(w, 503, protocol.ErrorNoCapacity, "could not create UDP offer")
		return
	}
	if _, err := rand.Read(offer.key[:]); err != nil {
		fail(w, 503, protocol.ErrorNoCapacity, "could not create UDP offer")
		return
	}
	if !lane.reserveCarrierRequest(w, request.RequestID, now) {
		return
	}
	registry.forget(lane.udpOffers[request.Candidate])
	if lane.udpOffers == nil {
		lane.udpOffers = make(map[string]*udpProofOffer, 2)
	}
	lane.udpOffers[request.Candidate] = offer
	registry.mu.Lock()
	registry.offers[offer.scope.Candidate] = offer
	registry.mu.Unlock()
	writeCarrierUDPOffer(w, offer, now)
}

func writeCarrierUDPOffer(w http.ResponseWriter, offer *udpProofOffer, now time.Time) {
	w.Header().Set("Cache-Control", "no-store")
	write(w, http.StatusOK, protocol.CarrierUDPOffer{
		ID: base64.RawURLEncoding.EncodeToString(offer.scope.Candidate[:]), ProofKey: base64.RawURLEncoding.EncodeToString(offer.key[:]),
		DatagramMax: offer.size, ExpiresInMS: offer.expires.Sub(now).Milliseconds(),
	})
}

func (s *Server) carrierUDPQualify(w http.ResponseWriter, r *http.Request) {
	request, ok := s.decodeCarrierUDPRequest(w, r)
	if !ok {
		return
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.validateCarrierUDPRequest(w, r, request)
	if !ok {
		return
	}
	p, offer, now := s.adaptive, lane.udpOffers[request.Candidate], time.Now()
	if offer == nil || offer.request != request {
		fail(w, http.StatusConflict, "udp_offer_unknown", "UDP offer unavailable")
		return
	}
	if offer.qualifiedUntil.IsZero() {
		registry := p.nativeUDP(request.Candidate)
		registry.mu.Lock()
		ready, endpoint := offer.ready, offer.endpoint
		registry.mu.Unlock()
		if !ready || !now.Before(offer.expires) {
			fail(w, http.StatusConflict, "udp_proof_pending", "both UDP directions must be proven")
			return
		}
		until := minTime(v.Expires, now.Add(udpQualificationLifetime))
		if err := p.bind.InstallQualifiedPath(lane.endpoint, request.ExpectedEpoch, wstransport.QualifiedPath{
			ID: request.Candidate, Carrier: request.Candidate, Endpoint: endpoint,
			SendMax: offer.size, ReceiveMax: offer.size, ValidUntil: until,
		}); err != nil {
			fail(w, http.StatusConflict, "udp_path_unavailable", "could not qualify this UDP path")
			return
		}
		registry.forget(offer)
		offer.qualifiedUntil = until
	}
	if !now.Before(offer.qualifiedUntil) {
		fail(w, http.StatusConflict, "udp_offer_expired", "UDP qualification expired")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	write(w, http.StatusOK, protocol.CarrierUDPStatus{Candidate: request.Candidate,
		DatagramMax: offer.size, ExpiresInMS: offer.qualifiedUntil.Sub(now).Milliseconds()})
}

func (s *Server) decodeCarrierUDPRequest(w http.ResponseWriter, r *http.Request) (protocol.CarrierAttachRequest, bool) {
	if _, ok := s.sessions.Get(carrierBearer(r)); !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return protocol.CarrierAttachRequest{}, false
	}
	request, err := protocol.DecodeCarrierAttach(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil || !protocol.IsNativeUDPCarrier(request.Candidate) {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "invalid UDP carrier request")
		return protocol.CarrierAttachRequest{}, false
	}
	return request, true
}

func (s *Server) validateCarrierUDPRequest(w http.ResponseWriter, r *http.Request, request protocol.CarrierAttachRequest) (Session, *serverCarrierLane, bool) {
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		return Session{}, nil, false
	}
	if v.Adaptive.NativeUDPAddress(request.Candidate) == "" || s.adaptive.nativeUDP(request.Candidate) == nil {
		http.NotFound(w, r)
		return Session{}, nil, false
	}
	_, epoch, _ := s.adaptive.bind.LaneState(lane.endpoint)
	if request.Generation != v.Adaptive.AuthGeneration || request.ExpectedEpoch != epoch {
		fail(w, http.StatusConflict, "stale_carrier_state", "carrier state changed")
		return Session{}, nil, false
	}
	return v, lane, true
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
