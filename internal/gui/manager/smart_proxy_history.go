package manager

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

const (
	smartProxySampleInterval = 2 * time.Second
	smartProxyHistoryWindow  = 5 * time.Minute
	smartProxySampleLimit    = int(smartProxyHistoryWindow / smartProxySampleInterval)
)

type smartProxyHistoryMember struct {
	egressrouter.MemberID
	Sent          uint64        `json:"sent"`
	Received      uint64        `json:"received"`
	ConnectMillis float64       `json:"connect_millis,omitempty"`
	HTTPSMillis   float64       `json:"https_ttfb_millis,omitempty"`
	RTT           time.Duration `json:"carrier_rtt,omitempty"`
	Outage        string        `json:"outage,omitempty"`
}

// SmartProxyHistorySample contains only fields used by the trend charts.
type SmartProxyHistorySample struct {
	Time      int64                     `json:"time"`
	Listening bool                      `json:"listening"`
	Active    int64                     `json:"active"`
	Members   []smartProxyHistoryMember `json:"members,omitempty"`
	Direct    *smartProxyHistoryMember  `json:"direct,omitempty"`
}

type smartProxyHistory struct {
	mu     sync.Mutex
	frames []map[string]SmartProxyHistorySample
	cancel context.CancelFunc
	done   chan struct{}
}

func (m *Manager) startSmartProxyHistory() {
	ctx, cancel := context.WithCancel(context.Background())
	m.smartHistory.cancel = cancel
	m.smartHistory.done = make(chan struct{})
	go func() {
		defer close(m.smartHistory.done)
		ticker := time.NewTicker(smartProxySampleInterval)
		defer ticker.Stop()
		var previous map[string]SmartProxyHistorySample
		for {
			previous = m.recordSmartProxyHistory(previous)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (m *Manager) recordSmartProxyHistory(previous map[string]SmartProxyHistorySample) map[string]SmartProxyHistorySample {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if !m.smartConfigured {
		return nil
	}
	var status egressrouter.Status
	if m.smartProxyEnabled() {
		status = m.smartRouter.Status()
	}
	now := time.Now().UnixMilli()
	m.mu.Lock()
	groups := make(map[string]SmartProxyHistorySample, 1+len(m.smartConfig.Groups))
	groups["default"] = m.smartProxyHistorySample(now, m.smartConfig, status, previous["default"])
	for name, config := range m.smartConfig.Groups {
		groups[name] = m.smartProxyHistorySample(now, config, status.Groups[name], previous[name])
	}
	m.mu.Unlock()

	history := &m.smartHistory
	history.mu.Lock()
	defer history.mu.Unlock()
	cutoff := now - smartProxyHistoryWindow.Milliseconds()
	trim := 0
	for trim < len(history.frames) && history.frames[trim]["default"].Time <= cutoff {
		trim++
	}
	trim = max(trim, len(history.frames)-smartProxySampleLimit+1)
	if trim > 0 {
		remaining := copy(history.frames, history.frames[trim:])
		clear(history.frames[remaining:])
		history.frames = history.frames[:remaining]
	}
	history.frames = append(history.frames, groups)
	return groups
}

// smartProxyHistorySample requires m.mu.
func (m *Manager) smartProxyHistorySample(now int64, cfg egressrouter.Config, status egressrouter.Status, previous SmartProxyHistorySample) SmartProxyHistorySample {
	sample := SmartProxyHistorySample{Time: now, Listening: status.Listening != "", Active: status.Active}
	if !sample.Listening {
		return sample
	}
	seen := make(map[egressrouter.MemberID]bool, len(status.Members))
	for _, member := range status.Members {
		id := member.ID()
		seen[id] = true
		outage := m.smartProxyProfileOutage(id.ProfileID)
		if outage == "" && member.Reason == "transport" && member.Circuit == "closed" {
			outage = "transport"
		}
		sample.Members = append(sample.Members, smartProxyHistoryMember{
			MemberID: id, Sent: member.Sent, Received: member.Received,
			ConnectMillis: member.ConnectMillis, HTTPSMillis: member.HTTPSMillis, RTT: member.RTT, Outage: outage,
		})
	}
	// Disconnected enrollments disappear from router status. Keep a known
	// tunnel in each new sample while its enrolled profile is down.
	for _, old := range previous.Members {
		if seen[old.MemberID] || !slices.ContainsFunc(cfg.Egress.Enroll, func(entry egressrouter.Enrollment) bool {
			return entry.ProfileID == old.ProfileID
		}) {
			continue
		}
		if outage := m.smartProxyProfileOutage(old.ProfileID); outage != "" {
			sample.Members = append(sample.Members, smartProxyHistoryMember{MemberID: old.MemberID, Outage: outage})
		}
	}
	if direct := status.Direct; direct != nil {
		sample.Direct = &smartProxyHistoryMember{Sent: direct.Sent + direct.UDPSent,
			Received: direct.Received + direct.UDPReceived, ConnectMillis: direct.ConnectMillis}
	}
	return sample
}

func (m *Manager) smartProxyProfileOutage(id string) string {
	if s := m.sessions[id]; s != nil {
		switch s.state {
		case StateIdle, StateFailed, StateReconnecting:
			return string(s.state)
		}
	}
	return ""
}

// SmartProxyHistory returns this group's recent samples newer than after,
// expressed as Unix milliseconds. Reading never drives data collection.
func (m *Manager) SmartProxyHistory(group string, after int64) []SmartProxyHistorySample {
	if group == "" {
		group = "default"
	}
	after = max(after, time.Now().Add(-smartProxyHistoryWindow).UnixMilli())
	history := &m.smartHistory
	history.mu.Lock()
	defer history.mu.Unlock()
	samples := make([]SmartProxyHistorySample, 0)
	for _, frame := range history.frames {
		if sample, ok := frame[group]; ok && sample.Time > after {
			sample.Members = slices.Clone(sample.Members)
			if sample.Direct != nil {
				direct := *sample.Direct
				sample.Direct = &direct
			}
			samples = append(samples, sample)
		}
	}
	return samples
}
