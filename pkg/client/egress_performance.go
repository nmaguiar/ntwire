package client

import (
	"time"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

func (c *Connection) egressPathPerformance(grant *egressGrant) *egressrouter.PathPerformance {
	c.mu.Lock()
	n := c.network
	if n == nil || n.adaptive == nil || n.stack != grant.stack || c.egressGrants[grant.name] != grant {
		c.mu.Unlock()
		return nil
	}
	a := n.adaptive
	roster := c.laneRosterRevision
	count := len(c.childLanes) + 1
	out := &egressrouter.PathPerformance{ActiveFlows: n.activeFlows}
	if a.laneReady(true) {
		out.ReadyLanes++
	}
	for _, child := range c.childLanes {
		if !child.draining && child.adaptive.laneReady(true) {
			out.ReadyLanes++
		}
		out.ActiveFlows += child.activeFlows
	}
	c.mu.Unlock()
	now := time.Now()
	out.ObservedAt = now
	info, _, _ := a.credentials()
	path, epoch, _ := a.bind.LaneState(a.lane)
	a.measurements.egressEvidence(out, now, info.AuthGeneration, path, epoch, roster, count)
	return out
}

func (h *adaptivePerformanceHistory) egressEvidence(out *egressrouter.PathPerformance, now time.Time, generation uint64,
	path string, epoch, roster uint64, lanes int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.generation != generation {
		return
	}
	var upload, download *AdaptiveDirectionalEvidence
	if lanes > 1 {
		shared := h.shared.evidence(now)
		if shared != nil && shared.revision == roster && shared.Lanes == lanes &&
			shared.anchorPath == path && shared.anchorEpoch == epoch {
			upload, download = shared.Upload, shared.Download
		}
	} else if h.size >= 2 {
		latest := h.windows[(h.next-1+len(h.windows))%len(h.windows)]
		previous := h.windows[(h.next-2+len(h.windows))%len(h.windows)]
		age := now.Sub(latest.End)
		if latest.Path == path && latest.PathEpoch == epoch && latest.generation == generation &&
			age >= 0 && age <= 2*adaptiveFeedbackInterval {
			out.QueueDelay = latest.WSSQueueP95
			if evidence := adaptiveCapacityEvidence(now, []AdaptivePerformanceWindow{previous, latest}); evidence != nil {
				upload, download = evidence.Upload, evidence.Download
			}
		}
	}
	if upload != nil {
		out.Upload = egressrouter.PathDirection{ObservedBPS: upload.ObservedFloorBPS, Pressured: upload.Pressure}
	}
	if download != nil {
		out.Download = egressrouter.PathDirection{ObservedBPS: download.ObservedFloorBPS, Pressured: download.Pressure}
	}
}
