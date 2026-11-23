package egressrouter

import "time"

type Status struct {
	RaceAttempts    uint64            `json:"race_preparations,omitempty"`
	RaceBackups     uint64            `json:"race_backup_wins,omitempty"`
	Groups          map[string]Status `json:"groups,omitempty"`
	PACListen       string            `json:"pac_listen,omitempty"`
	Selected        *MemberID         `json:"last_selected,omitempty"`
	SelectionReason string            `json:"selection_reason,omitempty"`
	Error           string            `json:"error,omitempty"`
	Enabled         bool              `json:"enabled"`
	Listen          string            `json:"listen"`
	Listening       string            `json:"listening,omitempty"`
	Selection       string            `json:"selection"`
	Active          int64             `json:"active"`
	Failovers       uint64            `json:"failovers"`
	Recovered       uint64            `json:"recovered"`
	Members         []MemberStatus    `json:"members"`
}
type MemberStatus struct {
	RecentSamples       int     `json:"recent_samples"`
	DestinationFailures uint64  `json:"recent_destination_failures"`
	ConsecutiveFailures int     `json:"consecutive_infrastructure_failures"`
	LastFailureStage    string  `json:"last_failure_stage,omitempty"`
	SOCKSMillis         float64 `json:"socks_connect_millis,omitempty"`
	ServiceMillis       float64 `json:"virtual_service_millis,omitempty"`
	AttachmentMillis    float64 `json:"attachment_overhead_millis,omitempty"`
	HTTPSMillis         float64 `json:"https_ttfb_millis,omitempty"`
	Member
	Candidate
	Eligible          bool       `json:"eligible"`
	Circuit           string     `json:"circuit"`
	ConnectMillis     float64    `json:"connect_millis,omitempty"`
	VariabilityMillis float64    `json:"variability_millis,omitempty"`
	SuccessRate       float64    `json:"success_rate,omitempty"`
	Attempts          uint64     `json:"attempts"`
	LastFailure       string     `json:"last_failure,omitempty"`
	LastProbe         *time.Time `json:"last_probe,omitempty"`
	LastSuccess       *time.Time `json:"last_success,omitempty"`
	Active            int64      `json:"active"`
	Sent              uint64     `json:"sent"`
	Received          uint64     `json:"received"`
}

func (r *Router) Status() Status {
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if state == nil {
		return Status{}
	}
	candidates := r.candidates(state)
	r.mu.Lock()
	defer r.mu.Unlock()
	status := Status{Enabled: state.config.Enabled, Listen: state.config.Listen, Selection: state.config.Egress.Selection,
		RaceAttempts: r.raceAttempts.Load(), RaceBackups: r.raceBackups.Load(), Active: r.active.Load(), Failovers: r.failovers.Load(), Recovered: r.recovered.Load()}
	if r.lastSelection != (MemberID{}) {
		selected := r.lastSelection
		status.Selected = &selected
		status.SelectionReason = r.lastReason
	}
	if r.listener != nil {
		status.Listening = r.listener.Addr().String()
	}
	now := r.now()
	destinationFailures := make(map[MemberID]uint64)
	for key, d := range state.destinations {
		h := state.health[key.member]
		if h != nil && d.generation == h.generation && now.Sub(d.updated) <= measurementTTL {
			count, ok := d.diagnostic.recent(now)
			destinationFailures[key.member] += uint64(count - ok)
		}
	}
	for _, c := range candidates {
		id := c.ID()
		item := MemberStatus{Member: c.Member, Candidate: c.Candidate, Circuit: "closed", Eligible: status.Enabled && c.Dialer != nil}
		if h := state.health[id]; h != nil && h.generation == c.Generation {
			switch {
			case h.quarantined:
				item.Circuit = "quarantined"
				item.Eligible = false
				item.Reason = h.failureClass
			case now.Before(h.openUntil):
				item.Circuit = "open"
				item.Eligible = false
				item.Reason = "circuit_open"
			case !h.openUntil.IsZero():
				item.Circuit = "half-open"
			}
			item.ConnectMillis = h.latency / float64(time.Millisecond)
			item.SOCKSMillis = float64(h.timing.SOCKS) / float64(time.Millisecond)
			item.ServiceMillis = float64(h.timing.Service) / float64(time.Millisecond)
			item.AttachmentMillis = float64(h.overhead) / float64(time.Millisecond)
			item.HTTPSMillis = float64(h.httpsTTFB) / float64(time.Millisecond)
			item.VariabilityMillis = h.deviation / float64(time.Millisecond)
			item.Attempts = h.attempts
			if now.Sub(h.lastSuccess) > measurementTTL && !h.lastSuccess.IsZero() {
				item.ConnectMillis = 0
			}
			if item.Reason == "" && h.samples < 3 {
				item.Reason = "insufficient_samples"
			}
			count, successes := h.passiveWindow.recent(now)
			item.RecentSamples = count
			if count > 0 {
				item.SuccessRate = float64(successes) / float64(count)
			}
			item.ConsecutiveFailures = h.consecutive
			item.DestinationFailures = destinationFailures[id]
			item.LastFailure = h.failureClass
			item.LastFailureStage = h.failureStage
			if !h.lastProbe.IsZero() {
				t := h.lastProbe
				item.LastProbe = &t
			}
			if !h.lastSuccess.IsZero() {
				t := h.lastSuccess
				item.LastSuccess = &t
			}
			item.Active = h.active.Load()
			item.Sent = h.sent.Load()
			item.Received = h.received.Load()
		}
		item.Candidate.Dialer = nil
		item.Candidate.ControlProxy = ""
		if r.excluded[id] {
			item.Eligible = false
			item.Reason = "excluded"
		}
		if item.Eligible && id == r.preferred {
			item.Reason = "preferred"
		}
		status.Members = append(status.Members, item)
	}
	return status
}
