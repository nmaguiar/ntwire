package server

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

const laneRequestLimit = 32
const laneQualificationTimeout = 30 * time.Second

type laneMutation struct {
	request protocol.LaneRequest
	laneID  string
	retired bool
	expires time.Time
}

// carrierView inherits all authorization from the authenticated parent.
// An empty lane selects the anchor for the existing WebSocket endpoint.
func (v Session) carrierView(laneID string) (Session, bool) {
	if v.Adaptive == nil {
		return Session{}, false
	}
	if laneID == "" || laneID == v.Adaptive.LaneID {
		return v, true
	}
	for _, child := range v.children {
		if child.id == laneID {
			info := v.Adaptive.ChildSession(child.id)
			v.Adaptive = &info
			v.WireGuardPublicKey, v.TunnelIP = child.key, child.ip
			v.peerLifetime, v.flowLifetime = child.id, child.flowLifetime
			v.children = nil
			return v, true
		}
	}
	return Session{}, false
}

func (s *Server) laneParent(w http.ResponseWriter, r *http.Request) (Session, *serverCarrierLane, bool) {
	v, ok := s.sessions.Get(carrierBearer(r))
	if !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return Session{}, nil, false
	}
	if p := s.adaptive; p != nil && v.Adaptive != nil && v.Adaptive.MaxLanes > 1 {
		if anchor := p.lanes[v.Adaptive.LaneID]; anchor != nil {
			return v, anchor, true
		}
	}
	http.NotFound(w, r)
	return Session{}, nil, false
}

func (p *adaptiveServerPlane) descriptor(v Session) protocol.LaneDescriptor {
	result := protocol.LaneDescriptor{
		Adaptive: *v.Adaptive, TunnelIP: v.TunnelIP, ServerTunnelIP: p.data.serverIP.String(),
		ServerPublicKey: p.data.stack.PublicKey(), TTLSeconds: int(v.Expires.Sub(time.Now()).Seconds()),
		State: "creating",
	}
	if lane := p.lanes[v.Adaptive.LaneID]; lane != nil {
		path, epoch, _ := p.bind.LaneState(lane.endpoint)
		result.Adaptive.PathEpoch = epoch
		if path != "" {
			result.State = "qualifying"
			if p.laneConfirmed(lane, v.WireGuardPublicKey) {
				result.State = "ready"
			}
		}
	}
	return result
}

func (p *adaptiveServerPlane) laneConfirmed(lane *serverCarrierLane, key string) bool {
	if !lane.confirmed {
		last, known, err := p.data.stack.LastHandshake(key)
		lane.confirmed = err == nil && known && !last.Before(lane.started)
	}
	return lane.confirmed
}

func (s *Server) reapUnconfirmedLanes(now time.Time) {
	p := s.adaptive
	if p == nil || p.maxLanes <= 1 {
		return
	}
	for _, parent := range s.sessions.All() {
		for _, child := range parent.children {
			lane := p.lanes[child.id]
			if lane != nil && now.Sub(lane.started) >= laneQualificationTimeout && !p.laneConfirmed(lane, child.key) {
				s.sessions.forgetChild(parent, child.id)
				p.removeLane(child.id, child.key, child.ip)
				s.clearLaneStats(parent.Tunnels, child.ip)
			}
		}
	}
}

func (s *Server) listLanes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s.operationMu.Lock()
	v, _, ok := s.laneParent(w, r)
	if !ok {
		s.operationMu.Unlock()
		return
	}
	result := protocol.LaneList{ParentID: v.Adaptive.ParentID, Generation: v.Adaptive.AuthGeneration,
		Lanes: []protocol.LaneDescriptor{s.adaptive.descriptor(v)}}
	for _, child := range v.children {
		childView, _ := v.carrierView(child.id)
		result.Lanes = append(result.Lanes, s.adaptive.descriptor(childView))
	}
	s.operationMu.Unlock()
	write(w, http.StatusOK, result)
}

func (s *Server) createLane(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	req, ok := s.decodeLaneMutation(w, r)
	if !ok {
		return
	}
	key, err := wgnet.CanonicalPublicKey(req.WireGuardPublicKey)
	if err != nil || !validLanePeerKey(key) {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidWireGuardKey, "invalid child peer key")
		return
	}
	req.WireGuardPublicKey = key
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	s.reapSessionsLocked()
	v, anchor, ok := s.laneParent(w, r)
	if !ok || !currentLaneGeneration(w, v, req) {
		return
	}
	p := s.adaptive
	now := time.Now()
	previous, allowed := anchor.laneRequest(w, req, "", now)
	if !allowed {
		return
	}
	if previous.laneID != "" {
		if child, exists := v.carrierView(previous.laneID); exists {
			write(w, http.StatusOK, p.descriptor(child))
		} else {
			fail(w, http.StatusConflict, "stale_lane_request", "child lane has retired")
		}
		return
	}
	if p.full() || len(v.children)+1 >= v.Adaptive.MaxLanes || s.sessions.childCount(v) >= protocol.MaxAdaptiveLanes-1 {
		fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "child lane limit reached")
		return
	}
	if s.laneKeyUnavailable(p, key) {
		fail(w, http.StatusForbidden, protocol.ErrorNotAllowed, "child peer key is unavailable")
		return
	}
	if now.Sub(anchor.lastLaneCreate) < carrierAttachGap {
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "child lane creation rate exceeded")
		return
	}
	anchor.lastLaneCreate = now
	ip, err := s.allocateIP()
	if err != nil {
		fail(w, http.StatusServiceUnavailable, protocol.ErrorNoCapacity, "tunnel address pool exhausted")
		return
	}
	id := newAdaptiveSession().LaneID
	info := v.Adaptive.ChildSession(id)
	lifetime, err := p.add(&info, key, ip)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, protocol.ErrorNoCapacity, "child peer setup failed")
		return
	}
	child := sessionLane{id: id, key: key, ip: ip, flowLifetime: lifetime}
	if !s.sessions.trackChild(v.Token, req.Generation, child) {
		p.removeLane(id, key, ip)
		fail(w, http.StatusConflict, "stale_lane_request", "parent session changed")
		return
	}
	anchor.laneRequests[req.RequestID] = laneMutation{request: req, laneID: id, expires: now.Add(time.Minute)}
	v.children = []sessionLane{child} // local view for this response only
	newLane, _ := v.carrierView(id)
	write(w, http.StatusOK, p.descriptor(newLane))
}

func (s *Server) retireLane(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	req, ok := s.decodeLaneMutation(w, r)
	if !ok {
		return
	}
	id := r.PathValue("lane")
	if req.WireGuardPublicKey != "" || !protocol.ValidCarrierID(id) {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "invalid child retirement")
		return
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, anchor, ok := s.laneParent(w, r)
	if !ok || !currentLaneGeneration(w, v, req) {
		return
	}
	if id == v.Adaptive.LaneID {
		fail(w, http.StatusForbidden, protocol.ErrorNotAllowed, "anchor belongs to the parent lifetime")
		return
	}
	now := time.Now()
	previous, allowed := anchor.laneRequest(w, req, id, now)
	if !allowed {
		return
	}
	if previous.laneID == "" {
		child, removed := s.sessions.forgetChild(v, id)
		if !removed {
			http.NotFound(w, r)
			return
		}
		s.adaptive.removeLane(child.id, child.key, child.ip)
		s.clearLaneStats(v.Tunnels, child.ip)
		anchor.laneRequests[req.RequestID] = laneMutation{request: req, laneID: id, expires: now.Add(time.Minute), retired: true}
	}
	w.WriteHeader(http.StatusNoContent)
}

func currentLaneGeneration(w http.ResponseWriter, v Session, req protocol.LaneRequest) bool {
	if req.Generation == v.Adaptive.AuthGeneration {
		return true
	}
	fail(w, http.StatusConflict, "stale_lane_request", "parent authorization changed")
	return false
}

func (s *Server) decodeLaneMutation(w http.ResponseWriter, r *http.Request) (protocol.LaneRequest, bool) {
	if _, ok := s.sessions.Get(carrierBearer(r)); !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return protocol.LaneRequest{}, false
	}
	req, err := protocol.DecodeLaneRequest(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "invalid lane request")
		return protocol.LaneRequest{}, false
	}
	return req, true
}

func (lane *serverCarrierLane) laneRequest(w http.ResponseWriter, req protocol.LaneRequest, retirement string, now time.Time) (laneMutation, bool) {
	for id, entry := range lane.laneRequests {
		if !now.Before(entry.expires) {
			delete(lane.laneRequests, id)
		}
	}
	if entry, exists := lane.laneRequests[req.RequestID]; exists {
		if entry.request == req && entry.retired == (retirement != "") && (!entry.retired || entry.laneID == retirement) {
			return entry, true
		}
		fail(w, http.StatusConflict, "lane_request_conflict", "request ID was already used")
		return laneMutation{}, false
	}
	if len(lane.laneRequests) >= laneRequestLimit {
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "lane request budget exhausted")
		return laneMutation{}, false
	}
	if lane.laneRequests == nil {
		lane.laneRequests = make(map[string]laneMutation)
	}
	return laneMutation{}, true
}

func validLanePeerKey(key string) bool {
	// WireGuard's zero key denotes no peer.
	return key != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}

func (s *Server) laneKeyUnavailable(p *adaptiveServerPlane, key string) bool {
	if key == p.data.stack.PublicKey() || s.sessions.childKeyInUse(key) || p.isQuarantinedKey(key) {
		return true
	}
	if _, inUse := s.sessions.FindWireGuardPublicKey(key); inUse {
		return true
	}
	for _, peer := range s.Config.NativeWireGuard.Peers {
		if native, err := wgnet.CanonicalPublicKey(peer.PublicKey); err == nil && native == key {
			return true
		}
	}
	return false
}

func sessionConflictsNative(v Session, key string, ip netip.Addr) bool {
	same := func(peerKey, tunnelIP string) bool {
		canonical, _ := wgnet.CanonicalPublicKey(peerKey)
		addr, _ := netip.ParseAddr(tunnelIP)
		return (key != "" && key == canonical) || (ip.IsValid() && ip.Unmap() == addr.Unmap())
	}
	if same(v.WireGuardPublicKey, v.TunnelIP) {
		return true
	}
	for _, child := range v.children {
		if same(child.key, child.ip) {
			return true
		}
	}
	return false
}

func (s *Server) clearLaneStats(tunnels []protocol.Tunnel, ip string) {
	for _, tunnel := range tunnels {
		s.tunnelStats.Delete(statsKey(ip, tunnel.Name))
	}
}
