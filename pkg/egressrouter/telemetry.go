package egressrouter

import (
	"math/bits"
	"time"
)

const outcomeLimit = 32
const destinationLimit = 1024
const measurementTTL = 5 * time.Minute

type measurements struct {
	latency, deviation float64
	lastSuccess        time.Time
	samples            int
	revision           uint64
}

func (m *measurements) observe(now time.Time, elapsed time.Duration) {
	sample := float64(elapsed)
	if m.samples == 0 || now.Sub(m.lastSuccess) > measurementTTL {
		m.samples = 0
		m.latency = sample
		m.deviation = 0
	} else {
		if delta := sample - m.latency; delta < 0 {
			m.deviation += .2 * (-delta - m.deviation)
		} else {
			m.deviation += .2 * (delta - m.deviation)
		}
		m.latency += .2 * (sample - m.latency)
	}
	m.samples++
	m.revision++
	m.lastSuccess = now
}

type outcomeWindow struct {
	outcomes uint32
	count    int
	updated  time.Time
}

func (w *outcomeWindow) observe(now time.Time, success bool) {
	if now.Sub(w.updated) > measurementTTL {
		w.outcomes = 0
		w.count = 0
	}
	w.outcomes <<= 1
	if success {
		w.outcomes |= 1
	}
	w.count = min(w.count+1, outcomeLimit)
	w.updated = now
}
func (w outcomeWindow) recent(now time.Time) (count, successes int) {
	if now.Sub(w.updated) > measurementTTL {
		return 0, 0
	}
	return w.count, bits.OnesCount32(w.outcomes)
}

type observationKey struct {
	member MemberID
	host   string
	port   uint16
}
type destinationObservation struct {
	measurements
	outcomes   outcomeWindow
	generation string
	updated    time.Time
	diagnostic outcomeWindow
	transfer   transferEstimate
}

func destinationKey(id MemberID, dst Destination) observationKey {
	return observationKey{id, hostKey(dst), dst.Port}
}
func (s *routeState) observeDestination(now time.Time, c ranked, dst Destination, elapsed time.Duration, failure *Failure) {
	if failure != nil && !isDestinationFailure(failure) {
		return
	}
	key := destinationKey(c.ID(), dst)
	item := s.destinationEntry(key, now, c.Generation)
	item.diagnostic.observe(now, failure == nil)
	if failure == nil || (failure.Code >= 3 && failure.Code <= 6) {
		item.outcomes.observe(now, failure == nil)
	}
	if failure == nil {
		item.observe(now, elapsed)
	}
	s.destinations[key] = item
}

func (s *routeState) destinationEntry(key observationKey, now time.Time, generation string) destinationObservation {
	if s.destinations == nil {
		s.destinations = map[observationKey]destinationObservation{}
	}
	item, exists := s.destinations[key]
	if !exists && len(s.destinations) >= destinationLimit {
		var oldest observationKey
		var seen time.Time
		for k, v := range s.destinations {
			if seen.IsZero() || v.updated.Before(seen) {
				oldest, seen = k, v.updated
			}
		}
		delete(s.destinations, oldest)
	}
	if item.generation != generation || now.Sub(item.updated) > measurementTTL {
		item = destinationObservation{generation: generation}
	}
	item.updated = now
	return item
}
func isDestinationFailure(f *Failure) bool {
	return f.Stage == "socks_connect" && !f.Retry
}
