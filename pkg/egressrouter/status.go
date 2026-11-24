package egressrouter

import "time"

type DirectStatus struct {
	Active        int64   `json:"active"`
	Attempts      uint64  `json:"attempts"`
	Successes     uint64  `json:"successes"`
	Failures      uint64  `json:"failures"`
	Sent          uint64  `json:"sent"`
	Received      uint64  `json:"received"`
	ConnectMillis float64 `json:"connect_millis"`
	UDPActive     int64   `json:"udp_active"`
	UDPSent       uint64  `json:"udp_sent"`
	UDPReceived   uint64  `json:"udp_received"`
}

type Status struct {
	Direct             *DirectStatus     `json:"direct,omitempty"`
	ASNDatabase        *ASNStatus        `json:"asn_database,omitempty"`
	Denied             uint64            `json:"destination_denied,omitempty"`
	Indeterminate      uint64            `json:"routing_indeterminate,omitempty"`
	ASNMatches         uint64            `json:"asn_lookups_succeeded,omitempty"`
	ASNFailures        uint64            `json:"asn_lookups_failed,omitempty"`
	RaceAttempts       uint64            `json:"race_preparations,omitempty"`
	RaceBackups        uint64            `json:"race_backup_wins,omitempty"`
	Groups             map[string]Status `json:"groups,omitempty"`
	PACListen          string            `json:"pac_listen,omitempty"`
	Selected           *MemberID         `json:"last_selected,omitempty"`
	SelectionReason    string            `json:"selection_reason,omitempty"`
	Error              string            `json:"error,omitempty"`
	Enabled            bool              `json:"enabled"`
	Listen             string            `json:"listen"`
	Listening          string            `json:"listening,omitempty"`
	NumericDomainReady bool              `json:"numeric_domain_ready,omitempty"`
	Selection          string            `json:"selection"`
	Active             int64             `json:"active"`
	Failovers          uint64            `json:"failovers"`
	Recovered          uint64            `json:"recovered"`
	Members            []MemberStatus    `json:"members"`
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
	Routed            uint64     `json:"routed"`
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
	status.ASNDatabase = state.asn.status(r.now())
	status.Denied, status.Indeterminate = r.denied.Load(), r.indeterminate.Load()
	status.ASNMatches, status.ASNFailures = r.asnHits.Load(), r.asnMisses.Load()
	if attempts := r.direct.attempts.Load(); attempts != 0 || state.config.Routing.mayDirect() {
		successes := r.direct.successes.Load()
		status.Direct = &DirectStatus{Attempts: attempts, Successes: successes, Failures: r.direct.failures.Load(), Active: r.direct.active.Load(),
			Sent: r.direct.sent.Load(), Received: r.direct.received.Load(), UDPActive: r.direct.udpActive.Load(), UDPSent: r.direct.udpSent.Load(), UDPReceived: r.direct.udpReceived.Load()}
		if successes != 0 {
			status.Direct.ConnectMillis = float64(r.direct.latency.Load()) / float64(successes) / float64(time.Millisecond)
		}
	}
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
	hasMember, allCapable := false, true
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
			item.Routed = h.routed.Load()
			item.Sent = h.sent.Load()
			item.Received = h.received.Load()
		}
		item.Candidate.Dialer = nil
		item.Candidate.ControlProxy = ""
		if r.excluded[id] {
			item.Eligible = false
			item.Reason = "excluded"
		} else {
			hasMember = true
			allCapable = allCapable && c.NumericDomain && c.Dialer != nil
		}
		if item.Eligible && id == r.preferred {
			item.Reason = "preferred"
		}
		status.Members = append(status.Members, item)
	}
	status.NumericDomainReady = !state.config.Routing.proxyPossible() || hasMember && allCapable
	return status
}
