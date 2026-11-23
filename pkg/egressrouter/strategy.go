package egressrouter

import (
	"sort"
	"time"
)

// RankedCandidate contains only already-approved, eligible routing candidates.
type RankedCandidate struct {
	Member
	Score    time.Duration
	Measured bool
}

// Selector orders eligible candidates. Unknown and duplicate IDs are ignored.
// Implementations must not retain the slice or perform network I/O.
type Selector interface {
	Rank(time.Time, Destination, []RankedCandidate) []MemberID
}

type builtinSelector struct {
	strategy string
	sequence uint64
}

func (s builtinSelector) Rank(_ time.Time, _ Destination, candidates []RankedCandidate) []MemberID {
	measured := s.strategy == "sticky-fastest" || s.strategy == "fastest-healthy" || s.strategy == "destination-aware"
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if measured {
			if a.Measured != b.Measured {
				return a.Measured
			}
			if a.Measured && a.Score != b.Score {
				return a.Score < b.Score
			}
		}
		return a.Priority > b.Priority
	})
	ids := make([]MemberID, len(candidates))
	shift := 0
	if s.strategy == "round-robin" && len(candidates) > 0 {
		shift = int((s.sequence - 1) % uint64(len(candidates)))
	}
	for i := range ids {
		ids[i] = candidates[(i+shift)%len(candidates)].ID()
	}
	return ids
}

func score(now time.Time, m measurements, w outcomeWindow, penalty time.Duration) (time.Duration, bool) {
	if m.samples < 3 || now.Sub(m.lastSuccess) > measurementTTL {
		return 0, false
	}
	count, successes := w.recent(now)
	cost := float64(penalty) * float64(count-successes) / float64(max(1, count))
	return time.Duration(m.latency + .5*m.deviation + cost), true
}
