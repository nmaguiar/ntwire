package client

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

var errAdaptiveFeedbackChanged = errors.New("adaptive feedback membership or path changed")

type adaptiveObservation struct {
	local    forwardingCounters
	revision uint64
	children int
	token    string
}

type adaptiveChildFeedback struct {
	lane    *connectionNetwork
	primary string
	epoch   uint64
	peer    protocol.CarrierPerformance
	local   forwardingCounters
	err     error
}

type adaptiveParentSample struct {
	anchor      adaptiveFeedbackSample
	anchorLocal forwardingCounters
	revision    uint64
	children    []adaptiveChildFeedback
}

func (c *Connection) adaptiveObservation(n *connectionNetwork) (adaptiveObservation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.network != n {
		return adaptiveObservation{}, false
	}
	return adaptiveObservation{local: c.adaptiveTrafficLocked(n), revision: c.laneRosterRevision,
		children: len(c.childLanes), token: c.token}, true
}

// Caller holds c.mu. Recheck after I/O because a child can appear and
// disappear even when the number of attached lanes is unchanged.
func (c *Connection) matchesAdaptiveObservationLocked(n *connectionNetwork, observed adaptiveObservation) bool {
	return !c.closed && c.network == n && c.laneRosterRevision == observed.revision && c.token == observed.token
}

func (c *Connection) pollAdaptiveParent(ctx context.Context, n *connectionNetwork, observed adaptiveObservation,
	anchor adaptiveFeedbackSample, info protocol.AdaptiveSession, primary, bearer string) (adaptiveParentSample, error) {
	parent := adaptiveParentSample{anchor: anchor, revision: observed.revision}
	c.mu.Lock()
	if bearer != observed.token || !c.matchesAdaptiveObservationLocked(n, observed) || len(c.childLanes) >= protocol.MaxAdaptiveLanes {
		c.mu.Unlock()
		return parent, errAdaptiveFeedbackChanged
	}
	for _, child := range c.childLanes {
		parent.children = append(parent.children, adaptiveChildFeedback{lane: child, local: child.adaptive.laneTraffic()})
	}
	parent.anchorLocal = n.adaptive.laneTraffic()
	c.mu.Unlock()
	// Stable ordering makes successive counter pairs match without depending
	// on the map order or on which HTTP response completes first.
	slices.SortFunc(parent.children, func(a, b adaptiveChildFeedback) int {
		return strings.Compare(a.lane.response.Adaptive.LaneID, b.lane.response.Adaptive.LaneID)
	})
	for i := range parent.children {
		child := &parent.children[i]
		carrier := child.lane.adaptive
		child.primary, child.epoch, _ = carrier.bind.LaneState(carrier.lane)
		if child.primary == "" {
			return parent, errAdaptiveFeedbackChanged
		}
	}
	poll, cancel := context.WithTimeout(ctx, adaptiveFeedbackTimeout)
	defer cancel()
	a := n.adaptive
	var workers sync.WaitGroup
	for i := range parent.children {
		child := &parent.children[i]
		workers.Go(func() {
			url := a.base + "/v1/transport/lanes/" + child.lane.response.Adaptive.LaneID + "/performance"
			child.err = a.controlRequest(poll, http.MethodGet, url, bearer, nil, &child.peer)
		})
	}
	path := a.base + "/v1/transport/lanes/" + info.LaneID + "/performance"
	err := a.controlRequest(poll, http.MethodGet, path, bearer, nil, &parent.anchor.peer)
	if err != nil {
		cancel()
	}
	workers.Wait()
	if err != nil {
		return parent, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.matchesAdaptiveObservationLocked(n, observed) ||
		!matchesAdaptivePeer(a, parent.anchor.peer, info.AuthGeneration, primary, anchor.epoch) {
		return parent, errAdaptiveFeedbackChanged
	}
	for _, child := range parent.children {
		if child.err != nil {
			return parent, child.err
		}
		if !matchesAdaptivePeer(child.lane.adaptive, child.peer, info.AuthGeneration, child.primary, child.epoch) {
			return parent, errAdaptiveFeedbackChanged
		}
	}
	return parent, nil
}

func matchesAdaptivePeer(a *adaptiveCarrierClient, observed protocol.CarrierPerformance, generation uint64, primary string, epoch uint64) bool {
	current, rev, _ := a.bind.LaneState(a.lane)
	return observed.AuthGeneration == generation && observed.Primary == primary && current == primary && rev == epoch
}

func adaptiveSharedWindow(before, after adaptiveParentSample) (AdaptivePerformanceWindow, bool) {
	a, b := before.anchor, after.anchor
	if a.at.IsZero() || len(after.children) == 0 || len(before.children) != len(after.children) || before.revision != after.revision ||
		a.epoch != b.epoch || b.local.offered < a.local.offered || b.local.received < a.local.received {
		return AdaptivePerformanceWindow{}, false
	}
	seconds := b.at.Sub(a.at).Seconds()
	rates, ok := adaptivePeerRates(a.peer, b.peer, seconds)
	if !ok {
		return AdaptivePerformanceWindow{}, false
	}
	for i, next := range after.children {
		previous := before.children[i]
		if previous.lane != next.lane || previous.epoch != next.epoch || next.peer.AuthGeneration != b.peer.AuthGeneration {
			return AdaptivePerformanceWindow{}, false
		}
		lane, ok := adaptivePeerRates(previous.peer, next.peer, seconds)
		if !ok {
			return AdaptivePerformanceWindow{}, false
		}
		rates.offered += lane.offered
		rates.received += lane.received
	}
	// A queue on one carrier can be local to that lane. Infer shared
	// delivery pressure only from the aggregate offered/received rates.
	result := adaptiveDeliveryWindow(a, b, rates, seconds)
	return result, result.Upload != nil || result.Download != nil
}

// AdaptiveSharedCapacityEvidence combines confirmed delivery from all
// managed lanes in one parent session. It does not estimate physical capacity.
type AdaptiveSharedCapacityEvidence struct {
	Lanes       int                          `json:"lanes"`
	Upload      *AdaptiveDirectionalEvidence `json:"upload,omitempty"`
	Download    *AdaptiveDirectionalEvidence `json:"download,omitempty"`
	revision    uint64
	anchorPath  string
	anchorEpoch uint64
}

type adaptiveSharedHistory struct {
	windows  [2]AdaptivePerformanceWindow
	revision uint64
	lanes    int
	children []adaptiveChildFeedback
}

func (h *adaptivePerformanceHistory) recordShared(generation uint64, parent adaptiveParentSample, window AdaptivePerformanceWindow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.accepts(generation) {
		return
	}
	lanes := 1 + len(parent.children)
	if h.shared.revision != parent.revision || h.shared.lanes != lanes {
		h.shared = adaptiveSharedHistory{revision: parent.revision, lanes: lanes}
	}
	window.generation = generation
	h.shared.windows[0], h.shared.windows[1] = h.shared.windows[1], window
	h.shared.children = parent.children
}

func (h *adaptivePerformanceHistory) clearShared(generation uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.accepts(generation) {
		h.shared = adaptiveSharedHistory{}
	}
}

func (h *adaptiveSharedHistory) evidence(now time.Time) *AdaptiveSharedCapacityEvidence {
	if h.lanes < 2 {
		return nil
	}
	observed := adaptiveCapacityEvidence(now, h.windows[:])
	if observed == nil {
		return nil
	}
	for _, child := range h.children {
		carrier := child.lane.adaptive
		primary, epoch, _ := carrier.bind.LaneState(carrier.lane)
		if primary != child.primary || epoch != child.epoch {
			return nil
		}
	}
	return &AdaptiveSharedCapacityEvidence{Lanes: h.lanes, Upload: observed.Upload, Download: observed.Download,
		revision: h.revision, anchorPath: observed.Path, anchorEpoch: observed.PathEpoch}
}
