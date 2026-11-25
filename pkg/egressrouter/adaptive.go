package egressrouter

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Fixed groups count toward the shared resource budget, but only Auto
// groups use that budget for admission.
var processBudget = resourceBudget{sample: machineBudget}

type resourceBudget struct {
	mu     sync.Mutex
	sample func(int) (int, string)
	active int
	limit  int
	reason string
	next   time.Time
}

func (b *resourceBudget) refresh(now time.Time) {
	if !now.Before(b.next) {
		b.limit, b.reason = b.sample(b.active)
		b.next = now.Add(2 * time.Second)
	}
}

func (b *resourceBudget) acquire(auto bool, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if auto {
		b.refresh(now)
		if b.active >= b.limit {
			return false
		}
	}
	b.active++
	return true
}
func (b *resourceBudget) release() { b.mu.Lock(); b.active--; b.mu.Unlock() }

type LimitStatus struct {
	Auto               bool   `json:"auto"`
	Connections        int    `json:"connections"`
	ConcurrentAttempts int    `json:"concurrent_attempts"`
	Reason             string `json:"reason,omitempty"`
}

type admission struct {
	mu                            sync.Mutex
	ceilings                      Limits
	current                       LimitStatus
	start                         time.Time
	peakConnections, peakAttempts int
	samples, failures             int
	elapsed, baseline             time.Duration
}

func newAdmission(l Limits) *admission {
	a := &admission{ceilings: l, current: LimitStatus{Auto: l.Auto, Connections: l.Connections, ConcurrentAttempts: l.ConcurrentAttempts}}
	if l.Auto {
		a.current.Connections = min(512, l.Connections)
		a.current.ConcurrentAttempts = min(32, l.ConcurrentAttempts)
		a.current.Reason = "Initial limits"
	}
	return a
}

// Evaluate completed windows on demand. Idle groups use no sampling goroutines.
func (a *admission) adjust(now time.Time) {
	if a.start.IsZero() {
		a.start = now
	}
	if now.Sub(a.start) < 2*time.Second {
		return
	}
	c := &a.current
	if a.peakConnections*4 >= c.Connections*3 && c.Connections < a.ceilings.Connections {
		c.Connections = min(a.ceilings.Connections, c.Connections+max(1, c.Connections/4))
		c.Reason = "Connection demand increased"
	}
	if a.samples >= 4 {
		mean := a.elapsed / time.Duration(a.samples)
		slow := a.baseline > 0 && mean > a.baseline+a.baseline/2+10*time.Millisecond
		switch {
		case slow || a.failures*4 >= a.samples:
			if c.ConcurrentAttempts > 1 {
				c.ConcurrentAttempts = max(1, c.ConcurrentAttempts*3/4)
				c.Reason = "Setups slowed or failed"
			}
		case a.peakAttempts*4 >= c.ConcurrentAttempts*3 && c.ConcurrentAttempts < a.ceilings.ConcurrentAttempts:
			c.ConcurrentAttempts = min(a.ceilings.ConcurrentAttempts, c.ConcurrentAttempts+max(1, c.ConcurrentAttempts/4))
			c.Reason = "Setup demand increased"
		}
		if a.baseline == 0 {
			a.baseline = mean
		} else {
			a.baseline += (mean - a.baseline) / 4
		}
	}
	a.start = now
	a.samples, a.failures, a.elapsed, a.peakConnections, a.peakAttempts = 0, 0, 0, 0, 0
}

func (a *admission) take(counter *atomic.Int64, setup bool, now time.Time) bool {
	if !a.ceilings.Auto {
		limit := a.ceilings.Connections
		if setup {
			limit = a.ceilings.ConcurrentAttempts
		}
		return claim(counter, limit)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.adjust(now)
	demand := int(counter.Load()) + 1
	if setup {
		a.peakAttempts = max(a.peakAttempts, demand)
		return claim(counter, a.current.ConcurrentAttempts)
	}
	a.peakConnections = max(a.peakConnections, demand)
	return claim(counter, a.current.Connections)
}

func (a *admission) observe(start time.Time, err error) {
	if !a.ceilings.Auto {
		return
	}
	var failure *Failure
	if err != nil && (!errors.As(err, &failure) || (failure.Class != "timeout" && failure.Class != "transport" && failure.Class != "capacity")) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.samples++
	if err != nil {
		a.failures++
	}
	a.elapsed += time.Since(start)
}

func (a *admission) status(active int, b *resourceBudget, now time.Time) LimitStatus {
	a.mu.Lock()
	s := a.current
	a.mu.Unlock()
	if s.Auto {
		b.mu.Lock()
		b.refresh(now)
		available := max(0, b.limit-b.active+active)
		if available < s.Connections {
			s.Connections = available
			s.Reason = b.reason
		}
		b.mu.Unlock()
	}
	return s
}
