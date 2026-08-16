package server

import (
	"sort"
	"sync"
)

// lifecycleCounters records bounded, process-lifetime event totals for the
// Prometheus endpoint. Neither key is caller controlled: event names are
// constants in server lifecycle paths and method is ssh, oidc, or unknown.
// This deliberately avoids identities, session IDs, tunnel targets, and error
// text as labels.
type lifecycleCounters struct {
	mu     sync.Mutex
	values map[lifecycleCounterKey]uint64
}

type lifecycleCounterKey struct {
	event  string
	method string
}

func newLifecycleCounters() *lifecycleCounters {
	return &lifecycleCounters{values: make(map[lifecycleCounterKey]uint64)}
}

func (c *lifecycleCounters) add(event, method string) {
	if method == "" {
		method = "unknown"
	}
	c.mu.Lock()
	c.values[lifecycleCounterKey{event: event, method: method}]++
	c.mu.Unlock()
}

type lifecycleCounter struct {
	lifecycleCounterKey
	total uint64
}

func (c *lifecycleCounters) snapshot() []lifecycleCounter {
	c.mu.Lock()
	defer c.mu.Unlock()
	values := make([]lifecycleCounter, 0, len(c.values))
	for key, total := range c.values {
		values = append(values, lifecycleCounter{lifecycleCounterKey: key, total: total})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].event == values[j].event {
			return values[i].method < values[j].method
		}
		return values[i].event < values[j].event
	})
	return values
}

func (s *Server) observe(event, method string) {
	s.lifecycle.add(event, method)
}

// auditLifecycle emits a session-less audit record for a control-plane
// decision made before a session exists. reason is a stable category, never
// an error string.
func (s *Server) auditLifecycle(event, method, reason string) {
	s.mu.Lock()
	l := s.auditLog
	s.mu.Unlock()
	if l == nil {
		l = s.log
	}
	l.Info("audit", "event", event, "method", method, "reason", reason)
}
