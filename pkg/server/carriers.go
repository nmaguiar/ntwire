package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	adaptiveLaneLimit  = 128
	carrierTicketTTL   = 15 * time.Second
	carrierAttachGap   = 250 * time.Millisecond
	adaptiveRelaySlots = 32
)

// The adaptive device has no legacy UDP or WSS ingress. Its peers can only
// receive packets admitted by an authenticated adaptive carrier.
type adaptiveServerPlane struct {
	data              *dataPlane
	bind              *wstransport.AdaptiveBind
	ws                *wstransport.Bind
	http2             *wstransport.QUICBind
	http3             *adaptiveQUICServer
	udp               *udpProofRegistry
	alternateUDP      *udpProofRegistry
	relayUDP          *udpProofRegistry
	relaySlots        chan struct{}
	relayBindingBatch chan struct{}
	nextRelayBind     time.Time
	quic              *adaptiveQUICServer
	mtu               int
	maxLanes          int
	lanes             map[string]*serverCarrierLane // keyed by lane ID under operationMu
	retiredMu         sync.RWMutex
	retired           map[string]string // quarantined IP to peer key
}

type serverCarrierLane struct {
	endpoint         *wstransport.LaneEndpoint
	attach           *carrierTicket
	quicAttach       *carrierTicket
	httpAttach       *carrierTicket
	http3Attach      *carrierTicket
	httpLink         wstransport.DatagramLink
	quicConnection   *quic.Conn
	cancel           context.CancelFunc
	recent           map[string]time.Time
	udpOffers        map[string]*udpProofOffer
	relayCatalog     relayCandidateCatalog
	relayAllocations [2]*laneRelayAllocation
	started          time.Time
	lastFeedback     time.Time
	lastSelection    *carrierSelection
	laneRequests     map[string]laneMutation // on the anchor only
	lastLaneCreate   time.Time
	confirmed        bool
}

type carrierTicket struct {
	request  protocol.CarrierAttachRequest
	secret   string
	bearer   string
	expires  time.Time
	issued   time.Time
	consumed bool
}

func (s *Server) startAdaptiveServerPlane(config wgnet.Config) (*adaptiveServerPlane, error) {
	ws := wstransport.NewServer()
	if err := ws.SetDatagramReadLimit(protocol.CarrierWSSDatagramMax); err != nil {
		return nil, err
	}
	if s.Config.Transport.SampleWSS {
		ws.EnableQueuePerformance()
	}
	if err := validateAdaptiveCarrierConfig(s.Config); err != nil {
		return nil, err
	}
	carriers := []wstransport.Carrier{{Name: protocol.CarrierWSS, Bind: ws, DatagramMax: protocol.CarrierWSSDatagramMax}}
	var http2Bind *wstransport.QUICBind
	if s.Config.Transport.AdaptiveHTTP2 {
		http2Bind, _ = wstransport.NewQUICBind(nil)
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierHTTP2, Bind: http2Bind, DatagramMax: protocol.CarrierWSSDatagramMax})
	}
	var udp *udpProofRegistry
	if port := s.Config.Transport.AdaptiveUDPPort; port != 0 {
		udp = newUDPProofRegistry(uint16(port))
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierDirectUDP, Bind: udp.socket,
			ListenPort: udp.port, DatagramMax: protocol.CarrierProofMax})
	}
	var alternateUDP *udpProofRegistry
	if port := s.Config.Transport.AdaptiveUDPAltPort; port != 0 {
		alternateUDP = newUDPProofRegistry(uint16(port))
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierAlternateUDP, Bind: alternateUDP.socket,
			ListenPort: alternateUDP.port, DatagramMax: protocol.CarrierProofMax})
	}
	var relayUDP *udpProofRegistry
	var relaySlots chan struct{}
	if s.Config.Relay.AdaptiveUDP {
		relayUDP = newUDPProofRegistry(0)
		relaySlots = make(chan struct{}, adaptiveRelaySlots)
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierRelayUDP, Bind: relayUDP.socket, DatagramMax: protocol.CarrierProofMax})
	}
	var quicBind *wstransport.QUICBind
	if s.Config.Transport.QUICListen != "" {
		var err error
		quicBind, err = wstransport.NewQUICBind(s.Config.Transport.QUICSendWait)
		if err != nil {
			return nil, err
		}
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierQUIC, Bind: quicBind, DatagramMax: protocol.CarrierWSSDatagramMax})
	}
	var h3Bind *wstransport.QUICBind
	if s.Config.Transport.HTTP3Listen != "" {
		h3Bind, _ = wstransport.NewQUICBind(nil)
		carriers = append(carriers, wstransport.Carrier{Name: protocol.CarrierHTTP3, Bind: h3Bind, DatagramMax: protocol.CarrierWSSDatagramMax})
	}
	bind, err := wstransport.NewAdaptiveBind(adaptiveLaneLimit, carriers...)
	if err != nil {
		return nil, err
	}
	mtu := s.Config.Transport.AdaptiveTunnelMTU
	if mtu == 0 {
		mtu = wstransport.DefaultTunnelMTU
	}
	config.MTU = mtu
	config.ListenPort = 0
	config.Bind = bind
	config.PinPeerEndpoints = true
	stack, err := wgnet.New(config)
	if err != nil {
		return nil, dataPlaneStartupError(err, bind.Close())
	}
	d := &dataPlane{stack: stack, serverIP: config.Addresses[0], stop: make(chan struct{}), stopASN: make(chan struct{}), listeners: map[string]*tunnelListener{}}
	for _, tunnel := range s.Config.Tunnels {
		if err := s.listenTunnel(d, tunnel); err != nil {
			return nil, dataPlaneStartupError(err, s.closePlane(d))
		}
	}
	if s.Config.Network.DNS.IsEnabled() {
		if err := s.startDNS(d); err != nil {
			return nil, dataPlaneStartupError(err, s.closePlane(d))
		}
	}
	if s.Config.Portal.Enabled && s.Config.Portal.Web.Enabled && s.Config.Portal.Web.Listen != "" {
		if err := s.startWebPortal(d, false); err != nil {
			return nil, dataPlaneStartupError(err, s.closePlane(d))
		}
	}
	p := &adaptiveServerPlane{data: d, bind: bind, ws: ws, http2: http2Bind, udp: udp, alternateUDP: alternateUDP, relayUDP: relayUDP, relaySlots: relaySlots, mtu: mtu,
		maxLanes: max(1, s.Config.Transport.AdaptiveMaxLanes), lanes: map[string]*serverCarrierLane{}}
	if relayUDP != nil {
		p.relayBindingBatch = make(chan struct{}, 1)
	}
	if quicBind != nil {
		p.quic, err = s.startAdaptiveQUIC(quicBind, s.Config.Transport.QUICListen, protocol.CarrierQUICALPN)
		if err != nil {
			return nil, dataPlaneStartupError(err, s.closePlane(d))
		}
		go s.acceptAdaptiveQUIC(p)
	}
	if h3Bind != nil {
		p.http3, err = s.startHTTP3Carrier(p, h3Bind)
		if err != nil {
			return nil, dataPlaneStartupError(err, errors.Join(p.quic.close(), s.closePlane(d)))
		}
	}
	return p, nil
}

func (s *Server) negotiateAdaptiveTransport(secured bool, req sessionRequest, caps []string) *protocol.AdaptiveSession {
	if !secured || s.adaptive == nil || !protocol.HasCapability(caps, protocol.CapabilityAdaptiveCarrierV1) || req.TunnelMTU > wstransport.DefaultTunnelMTU {
		return nil
	}
	mtuNegotiated := protocol.HasCapability(caps, protocol.CapabilityAdaptiveMTUV1)
	mtu := s.adaptive.mtu
	if (!mtuNegotiated && mtu != wstransport.DefaultTunnelMTU) || (mtuNegotiated && req.TunnelMTU != 0 && req.TunnelMTU != mtu) {
		return nil
	}
	info := newAdaptiveSession()
	info.Performance = protocol.HasCapability(caps, protocol.CapabilityAdaptivePerformanceV1)
	info.HTTP2 = s.adaptive.http2 != nil && protocol.HasCapability(caps, protocol.CapabilityHTTP2CarrierV1)
	info.RelayCatalog = s.relayPool.Load() != nil && protocol.HasCapability(caps, protocol.CapabilityAdaptiveRelayCatalogV1)
	info.RelayUDP = info.RelayCatalog && s.adaptive.relayUDP != nil && protocol.HasCapability(caps, protocol.CapabilityAdaptiveRelayUDPV1)
	if mtuNegotiated {
		info.TunnelMTU = mtu
	}
	if protocol.HasCapability(caps, protocol.CapabilityAdaptiveUDPV1) {
		info.DirectUDP = s.adaptiveUDPAdvertisement()
	}
	if mtuNegotiated && protocol.HasCapability(caps, protocol.CapabilityQUICDatagramV1) {
		info.QUIC = s.adaptiveQUICAdvertisement()
	}
	if mtuNegotiated && s.adaptive.http3 != nil && protocol.HasCapability(caps, protocol.CapabilityMASQUECarrierV1) {
		port := s.adaptive.http3.packet.LocalAddr().(*net.UDPAddr).Port
		info.HTTP3 = s.adaptiveDatagramAdvertisement(uint16(port))
	}
	pathSelect := protocol.HasCapability(caps, protocol.CapabilityAdaptivePathSelectV1)
	info.UDPSelect = info.DirectUDP != "" && info.Performance && pathSelect && protocol.HasCapability(caps, protocol.CapabilityAdaptiveUDPSelectV1)
	if info.UDPSelect && s.adaptive.alternateUDP != nil && protocol.HasCapability(caps, protocol.CapabilityAdaptiveUDPAltV1) {
		info.AlternateUDP = s.adaptiveDatagramAdvertisement(s.adaptive.alternateUDP.port)
	}
	info.RelaySelect = info.RelayUDP && pathSelect && protocol.HasCapability(caps, protocol.CapabilityAdaptiveRelaySelectV1)
	info.RelayPerformance = s.Config.Relay.PerformanceRouting && info.Performance && info.RelaySelect &&
		protocol.HasCapability(caps, protocol.CapabilityRelayPerformanceV1)
	info.PathSelect = pathSelect && (info.QUIC != "" || info.RelaySelect || info.UDPSelect)
	if s.adaptive.maxLanes > 1 && protocol.HasCapability(caps, protocol.CapabilityMultiLaneV1) {
		info.MaxLanes = s.adaptive.maxLanes
		info.LaneCarriers = info.PathSelect && (info.UDPSelect || info.QUIC != "") &&
			protocol.HasCapability(caps, protocol.CapabilityLaneCarriersV1)
	}
	if protocol.ValidateRequiredCapabilities(info.Capabilities(), req.RequiredTransportCapabilities) != nil {
		return nil
	}
	return info
}

func newAdaptiveSession() *protocol.AdaptiveSession {
	var ids [32]byte
	if _, err := rand.Read(ids[:]); err != nil {
		panic("adaptive session: crypto/rand unavailable")
	}
	return &protocol.AdaptiveSession{
		ParentID: base64.RawURLEncoding.EncodeToString(ids[:16]), LaneID: base64.RawURLEncoding.EncodeToString(ids[16:]), AuthGeneration: 1,
	}
}

func (p *adaptiveServerPlane) add(info *protocol.AdaptiveSession, key, ip string) (context.Context, error) {
	if p.full() || p.isQuarantinedKey(key) {
		return nil, errors.New("adaptive lane limit reached")
	}
	ep, err := p.bind.RegisterLane(info.LaneID, wstransport.MaxWireGuardDatagram(p.mtu))
	if err != nil {
		return nil, err
	}
	if err := addDataPlanePeer(p.data, key, ip, ep.DstToString()); err != nil {
		p.bind.RemoveLane(ep)
		p.removePeer(key, ip)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.lanes[info.LaneID] = &serverCarrierLane{endpoint: ep, cancel: cancel, started: time.Now()}
	return ctx, nil
}

func (p *adaptiveServerPlane) remove(v Session) {
	for _, child := range v.children {
		p.removeLane(child.id, child.key, child.ip)
	}
	p.removeLane(v.Adaptive.LaneID, v.WireGuardPublicKey, v.TunnelIP)
}

func (p *adaptiveServerPlane) removeLane(id, key, ip string) {
	if lane := p.lanes[id]; lane != nil {
		delete(p.lanes, id)
		lane.cancel()
		for candidate, offer := range lane.udpOffers {
			p.nativeUDP(candidate).forget(offer)
		}
		p.retireRelayAllocations(lane)
		p.bind.RemoveLane(lane.endpoint)
		p.ws.CloseSession(id)
		if lane.httpLink != nil {
			go lane.httpLink.Close()
		}
		if lane.quicConnection != nil {
			// Removal already fenced the lane. Close the transport without
			// waiting for its QUIC event loop under operationMu.
			go lane.quicConnection.CloseWithError(0, "session closed")
		}
		p.removePeer(key, ip)
	}
}

func (p *adaptiveServerPlane) full() bool {
	// Lane and quarantine mutations are serialized by operationMu.
	return len(p.lanes)+len(p.retired) >= adaptiveLaneLimit
}

func (p *adaptiveServerPlane) removePeer(key, ip string) {
	if err := p.data.stack.RemovePeer(key); err != nil {
		p.retiredMu.Lock()
		defer p.retiredMu.Unlock()
		if p.retired == nil {
			p.retired = make(map[string]string)
		}
		p.retired[ip] = key
	}
}

func (p *adaptiveServerPlane) isQuarantinedIP(ip string) bool {
	p.retiredMu.RLock()
	defer p.retiredMu.RUnlock()
	return p.retired[ip] != ""
}

func (p *adaptiveServerPlane) isQuarantinedKey(key string) bool {
	for _, retired := range p.retired {
		if retired == key {
			return true
		}
	}
	return false
}

func (p *adaptiveServerPlane) resetFlows(v *Session) {
	if p == nil || v.Adaptive == nil || v.Adaptive.MaxLanes <= 1 {
		return
	}
	v.flowLifetime = p.resetLaneFlows(v.Adaptive.LaneID)
	for i, child := range v.children {
		v.children[i].flowLifetime = p.resetLaneFlows(child.id)
	}
}

func (p *adaptiveServerPlane) resetLaneFlows(id string) context.Context {
	lane := p.lanes[id]
	if lane == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	lane.cancel()
	ctx, cancel := context.WithCancel(context.Background())
	lane.cancel = cancel
	return ctx
}

func (p *adaptiveServerPlane) renew(v Session) *protocol.AdaptiveSession {
	if p == nil {
		return nil
	}
	lane := p.lanes[v.Adaptive.LaneID]
	if lane == nil {
		return nil
	}
	lane.laneRequests = nil
	p.renewLane(lane, v.Expires)
	for _, child := range v.children {
		if childLane := p.lanes[child.id]; childLane != nil {
			p.renewLane(childLane, v.Expires)
		}
	}
	info := *v.Adaptive
	_, info.PathEpoch, _ = p.bind.LaneState(lane.endpoint)
	return &info
}

func (p *adaptiveServerPlane) renewLane(lane *serverCarrierLane, expires time.Time) {
	lane.attach = nil
	lane.quicAttach = nil
	lane.httpAttach = nil
	lane.http3Attach = nil
	lane.recent = nil
	lane.lastSelection = nil
	lane.relayCatalog = relayCandidateCatalog{}
	primary, _, _ := p.bind.LaneState(lane.endpoint)
	for i, x := range lane.relayAllocations {
		if x != nil && primary != "" && primary == x.pathID() && x.registration.current() {
			p.extendRelayPath(lane, x, expires)
		} else {
			p.retireRelayAllocation(lane, i)
		}
	}
	for candidate, offer := range lane.udpOffers {
		if primary == candidate && !offer.qualifiedUntil.IsZero() {
			p.extendUDPPath(lane, candidate, expires)
		} else {
			p.nativeUDP(candidate).forget(offer)
			delete(lane.udpOffers, candidate)
			p.bind.RemovePath(lane.endpoint, candidate)
		}
	}
	p.bind.ExtendPath(lane.endpoint, protocol.CarrierWSS, expires)
	p.bind.ExtendPath(lane.endpoint, protocol.CarrierQUIC, expires)
	p.bind.ExtendPath(lane.endpoint, protocol.CarrierHTTP2, expires)
	p.bind.ExtendPath(lane.endpoint, protocol.CarrierHTTP3, expires)
}

func carrierBearer(r *http.Request) string {
	value, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || r.TLS == nil {
		return ""
	}
	return value
}

// carrierLane is called with operationMu held on each admission, including
// after WebSocket upgrade. Old bearer generations can never publish a route.
func (s *Server) carrierLane(w http.ResponseWriter, r *http.Request) (Session, *serverCarrierLane, bool) {
	v, ok := s.sessions.Get(carrierBearer(r))
	if !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return Session{}, nil, false
	}
	v, ok = v.carrierView(r.PathValue("lane"))
	if !ok || s.adaptive == nil {
		http.NotFound(w, r)
		return Session{}, nil, false
	}
	lane := s.adaptive.lanes[v.Adaptive.LaneID]
	if lane == nil {
		http.NotFound(w, r)
		return Session{}, nil, false
	}
	return v, lane, true
}

func (s *Server) carrierCandidates(w http.ResponseWriter, r *http.Request) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		return
	}
	selected, epoch, _ := s.adaptive.bind.LaneState(lane.endpoint)
	info := *v.Adaptive
	info.PathEpoch = epoch
	w.Header().Set("Cache-Control", "no-store")
	ids := []string{protocol.CarrierWSS}
	if info.DirectUDP != "" {
		ids = append(ids, protocol.CarrierDirectUDP)
	}
	if info.AlternateUDP != "" {
		ids = append(ids, protocol.CarrierAlternateUDP)
	}
	if info.QUIC != "" {
		ids = append(ids, protocol.CarrierQUIC)
	}
	if info.HTTP2 && !info.Child {
		ids = append(ids, protocol.CarrierHTTP2)
	}
	if info.HTTP3 != "" && !info.Child {
		ids = append(ids, protocol.CarrierHTTP3)
	}
	write(w, http.StatusOK, protocol.CarrierCandidates{AdaptiveSession: info, Selected: selected, IDs: ids})
}

func (s *Server) carrierAttach(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.Get(carrierBearer(r)); !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return
	}
	request, err := protocol.DecodeCarrierAttach(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "invalid carrier request")
		return
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		return
	}
	_, epoch, _ := s.adaptive.bind.LaneState(lane.endpoint)
	if request.Generation != v.Adaptive.AuthGeneration || request.ExpectedEpoch != epoch {
		fail(w, http.StatusConflict, "stale_carrier_state", "carrier state changed")
		return
	}
	slot := &lane.attach
	datagramMax := protocol.CarrierWSSDatagramMax
	switch request.Candidate {
	case protocol.CarrierWSS:
	case protocol.CarrierHTTP2:
		if !v.Adaptive.HTTP2 || v.Adaptive.Child || s.adaptive.http2 == nil {
			http.NotFound(w, r)
			return
		}
		if lane.httpLink != nil {
			fail(w, http.StatusConflict, "attach_conflict", "carrier already active")
			return
		}
		slot = &lane.httpAttach
	case protocol.CarrierHTTP3:
		if v.Adaptive.HTTP3 == "" || v.Adaptive.Child || s.adaptive.http3 == nil {
			http.NotFound(w, r)
			return
		}
		if lane.httpLink != nil {
			fail(w, http.StatusConflict, "attach_conflict", "carrier already active")
			return
		}
		slot = &lane.http3Attach
		datagramMax = wstransport.MaxWireGuardDatagram(s.adaptive.mtu)
	case protocol.CarrierQUIC:
		if v.Adaptive.QUIC == "" {
			http.NotFound(w, r)
			return
		}
		if lane.quicConnection != nil && lane.quicConnection.Context().Err() == nil {
			fail(w, http.StatusConflict, "attach_conflict", "carrier already active")
			return
		}
		slot = &lane.quicAttach
		datagramMax = wstransport.MaxWireGuardDatagram(s.adaptive.mtu)
	default:
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	current := *slot
	if current != nil && (current.request.Generation != request.Generation || current.request.ExpectedEpoch != epoch) {
		// Stale tickets cannot publish a carrier. Free the slot so a
		// returning standby can attach against the committed epoch.
		*slot, current = nil, nil
	}
	if current != nil && current.request.RequestID == request.RequestID {
		if current.request != request || current.consumed || !now.Before(current.expires) {
			fail(w, http.StatusConflict, "attach_conflict", "carrier request is no longer available")
			return
		}
	} else {
		if current != nil && (now.Sub(current.issued) < carrierAttachGap || (!current.consumed && now.Before(current.expires))) {
			w.Header().Set("Retry-After", "1")
			fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "carrier attachment pending")
			return
		}
		if !lane.reserveCarrierRequest(w, request.RequestID, now) {
			return
		}
		*slot = &carrierTicket{request: request, secret: token(), issued: now, expires: v.Expires}
		if request.Candidate == protocol.CarrierQUIC || request.Candidate == protocol.CarrierHTTP3 {
			(*slot).bearer = v.Token
		}
		if until := now.Add(carrierTicketTTL); until.Before((*slot).expires) {
			(*slot).expires = until
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	write(w, http.StatusOK, protocol.CarrierAttachResponse{
		Ticket: (*slot).secret, ExpiresInMS: (*slot).expires.Sub(now).Milliseconds(), DatagramMax: datagramMax,
	})
}

// reserveCarrierRequest keeps a shared, bounded replay window across public
// carrier operations. It runs under the server operation lock.
func (lane *serverCarrierLane) reserveCarrierRequest(w http.ResponseWriter, id string, now time.Time) bool {
	for key, expires := range lane.recent {
		if !now.Before(expires) {
			delete(lane.recent, key)
		}
	}
	if _, seen := lane.recent[id]; seen {
		fail(w, http.StatusConflict, "attach_conflict", "carrier request is no longer available")
		return false
	}
	if len(lane.recent) >= 32 {
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "carrier attachment budget exhausted")
		return false
	}
	if lane.recent == nil {
		lane.recent = make(map[string]time.Time)
	}
	lane.recent[id] = now.Add(time.Minute)
	return true
}

func (s *Server) carrierWebSocket(w http.ResponseWriter, r *http.Request) {
	s.operationMu.Lock()
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		s.operationMu.Unlock()
		return
	}
	p, ticket := s.adaptive, lane.attach
	if ticket == nil || ticket.consumed || !time.Now().Before(ticket.expires) ||
		subtle.ConstantTimeCompare([]byte(ticket.secret), []byte(r.Header.Get(protocol.CarrierTicketHeader))) != 1 {
		s.operationMu.Unlock()
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid carrier ticket")
		return
	}
	ticket.consumed = true
	ticket.secret = ""
	s.operationMu.Unlock()
	_ = p.ws.ServeCarrier(w, r, v.Adaptive.LaneID, func(endpoint conn.Endpoint) (func(bool), error) {
		s.operationMu.Lock()
		current, valid := s.sessions.Get(carrierBearer(r))
		if valid {
			current, valid = current.carrierView(r.PathValue("lane"))
		}
		if !valid || current.Adaptive == nil || current.Adaptive.LaneID != v.Adaptive.LaneID ||
			current.Adaptive.AuthGeneration != ticket.request.Generation || s.adaptive != p || p.lanes[v.Adaptive.LaneID] != lane ||
			lane.attach != ticket || !time.Now().Before(ticket.expires) {
			s.operationMu.Unlock()
			return nil, errors.New("carrier authorization expired")
		}
		err := p.bind.AttachStream(lane.endpoint, ticket.request.ExpectedEpoch, wstransport.QualifiedPath{
			ID: protocol.CarrierWSS, Carrier: protocol.CarrierWSS, Endpoint: endpoint,
			SendMax: protocol.CarrierWSSDatagramMax, ReceiveMax: protocol.CarrierWSSDatagramMax, ValidUntil: current.Expires,
		})
		if err != nil {
			s.operationMu.Unlock()
			return nil, err
		}
		return func(published bool) {
			if !published {
				p.bind.RemovePath(lane.endpoint, protocol.CarrierWSS)
			}
			s.operationMu.Unlock()
		}, nil
	})
}
