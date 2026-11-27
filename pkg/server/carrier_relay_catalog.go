package server

import (
	"net/http"
	"slices"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

type relayCatalogOffer struct {
	id           string
	registration *relayUDPRegistration
}

type relayCandidateCatalog struct {
	expires time.Time
	offers  []relayCatalogOffer
}

// SetRelayPool supplies the server's configured relay pool before serving
// traffic. The caller retains ownership of the pool and its lifecycle.
func (s *Server) SetRelayPool(pool *RelayPool) {
	s.relayPool.Store(pool)
}

func (s *Server) carrierRelayCandidates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "relay catalog requires TLS")
		return
	}
	result, ok := s.relayCandidatesForLane(w, r)
	if ok {
		write(w, http.StatusOK, result)
	}
}

func (s *Server) relayCandidatesForLane(w http.ResponseWriter, r *http.Request) (protocol.RelayCandidateCatalog, bool) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		return protocol.RelayCandidateCatalog{}, false
	}
	pool := s.relayPool.Load()
	if !v.Adaptive.RelayCatalog || pool == nil {
		http.NotFound(w, r)
		return protocol.RelayCandidateCatalog{}, false
	}
	now := time.Now()
	registrations := pool.udpRegistrations(v.Adaptive.RelayPerformance)
	catalog := &lane.relayCatalog
	if !now.Before(catalog.expires) || !slices.EqualFunc(catalog.offers, registrations,
		func(offer relayCatalogOffer, registration *relayUDPRegistration) bool {
			return offer.registration == registration
		}) {
		next := relayCandidateCatalog{
			expires: minTime(now.Add(carrierTicketTTL), v.Expires),
			offers:  make([]relayCatalogOffer, 0, len(registrations)),
		}
		for _, registration := range registrations {
			id, err := randomRequestID()
			if err != nil {
				fail(w, http.StatusServiceUnavailable, "relay_catalog_unavailable", "cannot issue relay candidates")
				return protocol.RelayCandidateCatalog{}, false
			}
			next.offers = append(next.offers, relayCatalogOffer{id: id, registration: registration})
		}
		*catalog = next
	}
	result := protocol.RelayCandidateCatalog{
		LaneID: v.Adaptive.LaneID, AuthGeneration: v.Adaptive.AuthGeneration,
		Candidates: make([]string, 0, len(catalog.offers)),
	}
	if len(catalog.offers) > 0 {
		result.ExpiresInMS = max(1, catalog.expires.Sub(now).Milliseconds())
	}
	for _, offer := range catalog.offers {
		result.Candidates = append(result.Candidates, offer.id)
		if v.Adaptive.RelayPerformance {
			result.Members = append(result.Members, offer.registration.performanceID)
		}
	}
	return result, true
}
