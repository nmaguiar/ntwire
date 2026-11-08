package server

import (
	"sort"
	"sync"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
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

// transportSwitchCounters records committed multipath primary changes for the
// opt-in transport.metrics Prometheus series. Every label is drawn from a
// fixed vocabulary (path names and wstransport.SwitchReason values), never
// from identities or addresses.
type transportSwitchCounters struct {
	mu     sync.Mutex
	values map[transportSwitchKey]uint64
}

type transportSwitchKey struct {
	from, to, reason string
}

func newTransportSwitchCounters() *transportSwitchCounters {
	return &transportSwitchCounters{values: make(map[transportSwitchKey]uint64)}
}

func (c *transportSwitchCounters) observe(e wstransport.SwitchEvent) {
	from := e.From
	if from == "" {
		from = "none"
	}
	c.mu.Lock()
	c.values[transportSwitchKey{from: from, to: e.To, reason: string(e.Reason)}]++
	c.mu.Unlock()
}

type transportSwitchCounter struct {
	transportSwitchKey
	total uint64
}

func (c *transportSwitchCounters) snapshot() []transportSwitchCounter {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]transportSwitchCounter, 0, len(c.values))
	for k, v := range c.values {
		out = append(out, transportSwitchCounter{transportSwitchKey: k, total: v})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].transportSwitchKey, out[j].transportSwitchKey
		if a.from != b.from {
			return a.from < b.from
		}
		if a.to != b.to {
			return a.to < b.to
		}
		return a.reason < b.reason
	})
	return out
}
