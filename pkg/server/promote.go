package server

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// promoteMinInterval rate-limits POST /v1/transport/primary per session. The
// client's own policy promotes far less often (a 60 s dwell plus 15 s
// qualification); this only bounds a misbehaving or hostile client.
const promoteMinInterval = 10 * time.Second

// promoteLimiter remembers each session's last promotion attempt.
type promoteLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (l *promoteLimiter) allow(sessionID string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	if prev, ok := l.last[sessionID]; ok && now.Sub(prev) < promoteMinInterval {
		return false
	}
	// Bound memory: drop entries old enough to no longer limit anything.
	if len(l.last) > 4096 {
		for id, at := range l.last {
			if now.Sub(at) >= promoteMinInterval {
				delete(l.last, id)
			}
		}
	}
	l.last[sessionID] = now
	return true
}

// promoteTransport is the server half of opt-in path-promote-v1: an
// authenticated client asks to move its session's primary carrier to a
// candidate it has proven better. The server accepts only a candidate that
// is registered for this session's own peer and healthy by the server's own
// probes, so a client can never select a path the server cannot use.
func (s *Server) promoteTransport(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	sess, ok := s.sessions.Get(token)
	if !ok {
		fail(w, 401, protocol.ErrorInvalidRequest, "invalid session")
		return
	}
	if !s.Config.Transport.Promotion || !sess.Promote {
		http.NotFound(w, r)
		return
	}
	var body protocol.TransportPrimaryRequest
	if decodeControlBody(w, r, 1024, &body) != nil {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid request")
		return
	}
	name, err := wstransport.ValidateTransportName(body.Path)
	if err != nil || name == "" {
		fail(w, 400, protocol.ErrorInvalidRequest, "invalid path")
		return
	}
	if !s.promotions.allow(sess.ID, time.Now()) {
		fail(w, 429, protocol.ErrorInvalidRequest, "promotion rate limited")
		return
	}
	s.mu.Lock()
	data := s.data
	s.mu.Unlock()
	if data == nil || data.multipath == nil || !sess.Multipath {
		http.Error(w, "multipath transport is not active", http.StatusConflict)
		return
	}
	if err := data.multipath.Promote(sess.WireGuardPublicKey, name); err != nil {
		reason := "rejected"
		switch {
		case errors.Is(err, wstransport.ErrPromoteUnknownPath):
			reason = "unknown_path"
		case errors.Is(err, wstransport.ErrPromoteUnhealthy):
			reason = "unhealthy"
		case errors.Is(err, wstransport.ErrPromoteMTULimited):
			reason = "mtu_limited"
		case errors.Is(err, wstransport.ErrPromoteForced):
			reason = "forced"
		}
		s.observe("transport_promotion_"+reason, sess.Method)
		http.Error(w, "promotion rejected: "+err.Error(), http.StatusConflict)
		return
	}
	s.observe("transport_promotion_accepted", sess.Method)
	s.log.Info("transport event", "event", "promoted", "session", sess.ID, "path", name)
	w.WriteHeader(http.StatusNoContent)
}
