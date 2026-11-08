package wstransport

import (
	"sync"
	"time"
)

// SwitchReason explains why a Scheduler committed a new primary path.
type SwitchReason string

const (
	SwitchInitial        SwitchReason = "initial"
	SwitchForced         SwitchReason = "forced"
	SwitchCarrierFailure SwitchReason = "carrier_failure"
	SwitchProbeMisses    SwitchReason = "probe_misses"
	SwitchPromoted       SwitchReason = "promoted"
)

// SwitchEvent is one committed primary change. From is empty for the first
// selection of a session.
type SwitchEvent struct {
	At     time.Time    `json:"at"`
	From   string       `json:"from,omitempty"`
	To     string       `json:"to"`
	Reason SwitchReason `json:"reason"`
}

// switchLogLimit bounds the per-scheduler history; it is diagnostic only.
const switchLogLimit = 32

// switchLog is a fixed-size ring of SwitchEvents. It is written only when a
// primary change is actually committed, never on the per-packet Select path,
// so its mutex is uncontended in steady state.
type switchLog struct {
	mu     sync.Mutex
	events [switchLogLimit]SwitchEvent
	next   int
	n      int
	// OnSwitch, when set, observes each recorded event (for example server
	// metrics). It runs after the log mutex is released.
	onSwitch func(SwitchEvent)
}

func (l *switchLog) record(e SwitchEvent) {
	l.mu.Lock()
	l.events[l.next] = e
	l.next = (l.next + 1) % switchLogLimit
	if l.n < switchLogLimit {
		l.n++
	}
	fn := l.onSwitch
	l.mu.Unlock()
	if fn != nil {
		fn(e)
	}
}

// snapshot returns the recorded events, oldest first.
func (l *switchLog) snapshot() []SwitchEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]SwitchEvent, 0, l.n)
	start := (l.next - l.n + switchLogLimit) % switchLogLimit
	for i := 0; i < l.n; i++ {
		out = append(out, l.events[(start+i)%switchLogLimit])
	}
	return out
}

func (l *switchLog) setObserver(fn func(SwitchEvent)) {
	l.mu.Lock()
	l.onSwitch = fn
	l.mu.Unlock()
}

// SwitchEvents returns the bounded primary-change history, oldest first.
func (s *Scheduler) SwitchEvents() []SwitchEvent { return s.switches.snapshot() }

// SetSwitchObserver registers fn to be called once per committed primary
// change. Passing nil removes the observer.
func (s *Scheduler) SetSwitchObserver(fn func(SwitchEvent)) { s.switches.setObserver(fn) }
