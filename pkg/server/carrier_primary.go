package server

import (
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

type carrierSelection struct {
	request protocol.CarrierAttachRequest
	result  protocol.CarrierPrimary
}

func (s *Server) carrierPrimary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.sessions.Get(carrierBearer(r)); !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return
	}
	request, err := protocol.DecodeCarrierAttach(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "invalid primary selection request")
		return
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		return
	}
	if !v.Adaptive.PathSelect {
		http.NotFound(w, r)
		return
	}
	p := s.adaptive
	selected, epoch, _ := p.bind.LaneState(lane.endpoint)
	now := time.Now()
	var relay *laneRelayAllocation
	switch request.Candidate {
	case protocol.CarrierWSS, protocol.CarrierQUIC:
	case protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP:
		if !v.Adaptive.UDPSelect || v.Adaptive.NativeUDPAddress(request.Candidate) == "" {
			http.NotFound(w, r)
			return
		}
		if offer := lane.udpOffers[request.Candidate]; offer == nil || !now.Before(offer.qualifiedUntil) {
			fail(w, http.StatusConflict, "path_not_qualified", "direct UDP carrier unavailable")
			return
		}
	default:
		if !v.Adaptive.RelaySelect || !protocol.ValidCarrierID(request.Candidate) {
			http.NotFound(w, r)
			return
		}
		x := lane.relayPath(request.Candidate)
		if x == nil || x.proof.qualifiedUntil.IsZero() ||
			!s.currentRelay(x.registration) || x.expired(now) {
			fail(w, http.StatusConflict, "path_not_qualified", "relay carrier unavailable")
			return
		}
		relay = x
	}
	if request.Generation != v.Adaptive.AuthGeneration {
		fail(w, http.StatusConflict, "stale_carrier_state", "carrier authorization changed")
		return
	}
	if previous := lane.lastSelection; previous != nil && previous.request.RequestID == request.RequestID {
		if previous.request == request && selected == previous.result.Candidate && epoch == previous.result.PathEpoch &&
			now.Before(lane.recent[request.RequestID]) {
			write(w, http.StatusOK, previous.result)
			return
		}
		fail(w, http.StatusConflict, "stale_carrier_state", "primary selection no longer current")
		return
	}
	if selected == "" || request.ExpectedEpoch != epoch {
		fail(w, http.StatusConflict, "stale_carrier_state", "carrier path changed")
		return
	}
	if request.Candidate == protocol.CarrierWSS {
		if _, err := p.ws.CarrierEndpoint(v.Adaptive.LaneID); err != nil {
			fail(w, http.StatusConflict, "path_not_qualified", "WebSocket carrier unavailable")
			return
		}
	} else if request.Candidate == protocol.CarrierQUIC && (lane.quicConnection == nil || lane.quicConnection.Context().Err() != nil) {
		fail(w, http.StatusConflict, "path_not_qualified", "QUIC carrier unavailable")
		return
	}
	if !lane.reserveCarrierRequest(w, request.RequestID, now) {
		return
	}
	nextEpoch, err := p.bind.CommitPath(lane.endpoint, request.Candidate, epoch)
	if err != nil {
		fail(w, http.StatusConflict, "path_not_qualified", "carrier is no longer selectable")
		return
	}
	if relay != nil {
		p.extendRelayPath(lane, relay, v.Expires)
	}
	if x := lane.relayPath(selected); x != nil && selected != request.Candidate {
		p.extendRelayPath(lane, x, minTime(v.Expires, now.Add(udpQualificationLifetime)))
	}
	if protocol.IsNativeUDPCarrier(request.Candidate) {
		p.extendUDPPath(lane, request.Candidate, v.Expires)
	}
	if selected != request.Candidate && lane.udpOffers[selected] != nil {
		p.extendUDPPath(lane, selected, minTime(v.Expires, now.Add(udpQualificationLifetime)))
	}
	result := protocol.CarrierPrimary{Candidate: request.Candidate, PathEpoch: nextEpoch}
	lane.lastSelection = &carrierSelection{request: request, result: result}
	write(w, http.StatusOK, result)
}
