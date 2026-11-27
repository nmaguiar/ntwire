package server

import (
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func (s *Server) carrierPerformance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s.operationMu.Lock()
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		s.operationMu.Unlock()
		return
	}
	if !v.Adaptive.Performance {
		s.operationMu.Unlock()
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	if now.Sub(lane.lastFeedback) < time.Second {
		s.operationMu.Unlock()
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusTooManyRequests, protocol.ErrorNoCapacity, "carrier feedback rate exceeded")
		return
	}
	lane.lastFeedback = now
	bind := s.adaptive.bind
	primary, epoch, _ := bind.LaneState(lane.endpoint)
	sample := protocol.CarrierPerformance{
		AuthGeneration: v.Adaptive.AuthGeneration, PathEpoch: epoch, Primary: primary,
		ElapsedUS: uint64(now.Sub(lane.started).Microseconds()),
	}
	if primary == protocol.CarrierWSS && v.Adaptive.MaxLanes > 1 {
		sample.WSSBacklogged, _ = s.adaptive.ws.PeerQueuePressure(v.Adaptive.LaneID)
	}
	for _, tunnel := range v.Tunnels {
		if value, ok := s.tunnelStats.Load(statsKey(v.TunnelIP, tunnel.Name)); ok {
			stats := value.(*serverTunnelStats)
			sample.ReceivedBytes += stats.toTarget.Load()
			sample.OfferedBytes += stats.fromTarget.Load()
		}
	}
	finalPrimary, finalEpoch, _ := bind.LaneState(lane.endpoint)
	s.operationMu.Unlock()
	if primary == "" || primary != finalPrimary || epoch != finalEpoch {
		fail(w, http.StatusConflict, "stale_carrier_state", "carrier path changed during measurement")
		return
	}
	write(w, http.StatusOK, sample)
}
