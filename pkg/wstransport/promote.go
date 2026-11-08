package wstransport

import (
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Promotion errors returned by Scheduler.Promote.
var (
	ErrPromoteUnknownPath = errors.New("candidate is not registered")
	ErrPromoteUnhealthy   = errors.New("candidate is not healthy")
	ErrPromoteMTULimited  = errors.New("candidate cannot carry full-size tunnel packets")
	ErrPromoteForced      = errors.New("a different healthy transport is forced")
)

// Promote commits name as the primary path even though the incumbent is
// still healthy. It is the only way v3 leaves a healthy incumbent and is used
// solely by the opt-in path-promote-v1 flow, where the client and server each
// call it for the same candidate so both directions move together. Afterwards
// selection is sticky and failure-driven as usual.
func (s *Scheduler) Promote(name string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.candidates[name]
	if p == nil {
		return ErrPromoteUnknownPath
	}
	if !p.Healthy {
		return ErrPromoteUnhealthy
	}
	if p.MTUState == MTUStateLimited {
		return ErrPromoteMTULimited
	}
	if forced := s.Forced(); forced != "" && forced != name {
		if f := s.candidates[forced]; f != nil && f.Healthy {
			return ErrPromoteForced
		}
	}
	cur := s.primary.Load()
	from := ""
	if cur != nil {
		from = cur.name
	}
	if from == name {
		return nil
	}
	s.primary.Store(&primaryState{name: name})
	slog.Debug("multipath primary promoted", "from", from, "to", name)
	s.switches.record(SwitchEvent{At: now, From: from, To: name, Reason: SwitchPromoted})
	return nil
}

// Promote commits name as peerID's primary path; see Scheduler.Promote.
func (m *ServerMultipathBind) Promote(peerID, name string) error {
	m.mu.RLock()
	p := m.peers[peerID]
	m.mu.RUnlock()
	if p == nil {
		return ErrPromoteUnknownPath
	}
	return p.scheduler.Promote(name, time.Now())
}

// Client-side promotion policy constants. They are deliberately conservative:
// promotion is for leaving the WSS bootstrap (or a clearly worse UDP path)
// once a better path has been stable for a while, not for chasing noise.
const (
	promoteQualifyingProbes = 15               // consecutive healthy probes (~15 s)
	promoteMaxQualifying    = 600              // backoff cap (~10 min)
	promoteDwell            = 60 * time.Second // since the last non-initial switch
	promoteFlapWindow       = 5 * time.Minute  // a promoted path failing sooner is a flap
	promoteMinRTTGain       = 15 * time.Millisecond
	promoteRequestTimeout   = 10 * time.Second
)

// pathRank orders path kinds for promotion: a proven direct path beats the
// relay's UDP tier, which beats the TCP WSS carrier.
func pathRank(k PathKind) int {
	switch k {
	case PathDirect:
		return 3
	case PathUDPRelay:
		return 2
	case PathWSS:
		return 1
	}
	return 0
}

// promotionCandidate returns the best candidate that qualifies to replace the
// healthy incumbent, given the required number of consecutive healthy probes.
func (s *Scheduler) promotionCandidate(need int) (string, bool) {
	if s.Forced() != "" {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	cur := s.primary.Load()
	if cur == nil {
		return "", false
	}
	inc := s.candidates[cur.name]
	if inc == nil || !inc.Healthy {
		return "", false // failure handling, not promotion, applies
	}
	var best *candidate
	for name, c := range s.candidates {
		// streak >= need means the last need probes all succeeded, which
		// is the loss criterion; the rolling Loss window would otherwise
		// keep penalizing the probe routinely lost while the server is
		// still registering the path.
		if name == cur.name || c.Kind == PathWSS || !c.Healthy || c.streak < need {
			continue
		}
		if c.MTUState != "" && c.MTUState != MTUStateOK {
			continue // MTU-aware sessions promote only to a proven full-size path
		}
		if !promotionBetter(c, inc) {
			continue
		}
		if best == nil || pathRank(c.Kind) > pathRank(best.Kind) || (pathRank(c.Kind) == pathRank(best.Kind) && c.RTT < best.RTT) {
			best = c
		}
	}
	if best == nil {
		return "", false
	}
	return best.Name, true
}

func promotionBetter(c, inc *candidate) bool {
	if rc, ri := pathRank(c.Kind), pathRank(inc.Kind); rc != ri {
		return rc > ri
	}
	// Same kind: require a clear RTT win, so noise never moves a flow.
	return inc.RTT > 0 && c.RTT > 0 && c.RTT*4 <= inc.RTT*3 && inc.RTT-c.RTT >= promoteMinRTTGain
}

// lastSwitchAt returns when the most recent non-initial primary change
// happened, or the zero time.
func (s *Scheduler) lastSwitchAt() time.Time {
	events := s.SwitchEvents()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Reason != SwitchInitial {
			return events[i].At
		}
	}
	return time.Time{}
}

// promoter is one client session's promotion state.
type promoter struct {
	// request asks the server to commit path as primary (POST
	// /v1/transport/primary). It must return nil only on acceptance.
	request func(path string) error
	// qualifying overrides promoteQualifyingProbes (tests only).
	qualifying int

	mu           sync.Mutex
	inFlight     bool
	failures     int
	notBefore    time.Time
	promotedPath string
	promotedAt   time.Time
	// done, when set by tests, is signalled after each attempt completes.
	done chan struct{}
}

// EnablePromotion opts this bind into client-led promotion. request performs
// the authenticated server call; the bind commits locally only after it
// succeeds. Passing nil disables promotion again.
func (m *MultipathBind) EnablePromotion(request func(path string) error) {
	if request == nil {
		m.promo.Store(nil)
		return
	}
	m.promo.Store(&promoter{request: request, qualifying: m.promoteQualifying})
}

func (p *promoter) required() int {
	base := p.qualifying
	if base <= 0 {
		base = promoteQualifyingProbes
	}
	need := base << p.failures
	if need > promoteMaxQualifying || need <= 0 {
		return promoteMaxQualifying
	}
	return need
}

// evaluate runs once per probe tick.
func (p *promoter) evaluate(s *Scheduler, now time.Time) {
	p.mu.Lock()
	if p.inFlight || now.Before(p.notBefore) {
		p.mu.Unlock()
		return
	}
	primary, _, _ := s.Select()
	if p.promotedPath != "" && primary != p.promotedPath {
		if now.Sub(p.promotedAt) < promoteFlapWindow && p.failures < 6 {
			p.failures++
		}
		p.promotedPath = ""
	}
	if last := s.lastSwitchAt(); !last.IsZero() && now.Sub(last) < promoteDwell {
		p.mu.Unlock()
		return
	}
	name, ok := s.promotionCandidate(p.required())
	if !ok {
		p.mu.Unlock()
		return
	}
	p.inFlight = true
	p.mu.Unlock()
	go p.attempt(s, name)
}

func (p *promoter) attempt(s *Scheduler, name string) {
	err := p.request(name)
	if err == nil {
		err = s.Promote(name, time.Now())
	}
	now := time.Now()
	p.mu.Lock()
	if err != nil {
		slog.Debug("multipath promotion not applied", "candidate", name, "error", err)
		if p.failures < 6 {
			p.failures++
		}
		p.notBefore = now.Add(time.Duration(p.required()) * probeInterval)
	} else {
		p.promotedPath, p.promotedAt = name, now
	}
	p.inFlight = false
	done := p.done
	p.mu.Unlock()
	if done != nil {
		done <- struct{}{}
	}
}
