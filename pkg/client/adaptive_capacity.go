package client

import (
	"errors"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

const adaptiveCapacityMinOfferedBPS = 128 * 1024

// AdaptiveCapacityEvidence describes what two recent observations on the
// same path generation support. It is advisory and never a link-rate cap.
type AdaptiveCapacityEvidence struct {
	Path      string                       `json:"path"`
	PathEpoch uint64                       `json:"path_epoch"`
	Upload    *AdaptiveDirectionalEvidence `json:"upload,omitempty"`
	Download  *AdaptiveDirectionalEvidence `json:"download,omitempty"`
}

type AdaptiveDirectionalEvidence struct {
	ObservedFloorBPS float64 `json:"observed_floor_bps"`
	Pressure         bool    `json:"pressure,omitempty"`
}

func adaptiveCapacityEvidence(now time.Time, windows []AdaptivePerformanceWindow) *AdaptiveCapacityEvidence {
	if len(windows) < 2 {
		return nil
	}
	a, b := windows[len(windows)-2], windows[len(windows)-1]
	if b.Path == "" || a.Path != b.Path || a.PathEpoch != b.PathEpoch || a.generation != b.generation ||
		now.Sub(b.End) < 0 || now.Sub(b.End) > 2*adaptiveFeedbackInterval ||
		b.End.Sub(a.End) < 4*time.Second || b.End.Sub(a.End) > 8*time.Second {
		return nil
	}
	evidence := &AdaptiveCapacityEvidence{Path: b.Path, PathEpoch: b.PathEpoch}
	evidence.Upload = adaptiveDirectionalEvidence(a.Upload, b.Upload,
		a.UploadBacklogged || a.WSSQueueP95 > 20*time.Millisecond || quicSendPressure(a),
		b.UploadBacklogged || b.WSSQueueP95 > 20*time.Millisecond || quicSendPressure(b))
	evidence.Download = adaptiveDirectionalEvidence(a.Download, b.Download, a.DownloadBacklogged, b.DownloadBacklogged)
	if evidence.Upload == nil && evidence.Download == nil {
		return nil
	}
	return evidence
}

func adaptiveDirectionalEvidence(a, b *DirectionPerformance, aQueued, bQueued bool) *AdaptiveDirectionalEvidence {
	if a == nil || b == nil {
		return nil
	}
	pressure := func(window *DirectionPerformance, queued bool) bool {
		return queued || (window.OfferedBPS >= adaptiveCapacityMinOfferedBPS && window.DeliveredBPS < window.OfferedBPS*0.8)
	}
	return &AdaptiveDirectionalEvidence{
		ObservedFloorBPS: min(a.DeliveredBPS, b.DeliveredBPS),
		Pressure:         pressure(a, aQueued) && pressure(b, bQueued),
	}
}

func quicSendPressure(w AdaptivePerformanceWindow) bool {
	total := float64(w.QUICSent) + float64(w.QUICDropped)
	return w.QUICDropped >= 8 && float64(w.QUICDropped) >= 0.02*total
}

func (s *AdaptiveCapacityEvidence) blocksTrial(path string, epoch uint64) bool {
	return s != nil && s.Path == path && s.PathEpoch == epoch &&
		((s.Upload != nil && s.Upload.Pressure) || (s.Download != nil && s.Download.Pressure))
}

var errAdaptiveExplorationDeferred = errors.New("standby exploration deferred")

// One speculative operation owns the parent link at a time. Recovery and
// bootstrap have their own deadlines and do not acquire this lease.
func (a *adaptiveCarrierClient) beginExploration(now time.Time) bool {
	if !a.exploration.CompareAndSwap(false, true) {
		return false
	}
	path, epoch, _ := a.bind.LaneState(a.lane)
	info, _, _ := a.credentials()
	if (path == protocol.CarrierWSS && a.ws.PeerBacklogged("remote")) ||
		a.measurements.explorationPressured(now, info.AuthGeneration, path, epoch) {
		a.exploration.Store(false)
		return false
	}
	return true
}

func (a *adaptiveCarrierClient) qualifyStandby(now time.Time, qualify func() error) error {
	if !a.beginExploration(now) {
		return errAdaptiveExplorationDeferred
	}
	defer a.exploration.Store(false)
	return qualify()
}

func (h *adaptivePerformanceHistory) explorationPressured(now time.Time, generation uint64, path string, epoch uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.generation != generation {
		return false
	}
	if shared := h.shared.evidence(now); shared != nil && shared.anchorPath == path && shared.anchorEpoch == epoch &&
		((shared.Upload != nil && shared.Upload.Pressure) || (shared.Download != nil && shared.Download.Pressure)) {
		return true
	}
	if h.size < 2 {
		return false
	}
	last := (h.next - 1 + len(h.windows)) % len(h.windows)
	first := (last - 1 + len(h.windows)) % len(h.windows)
	windows := [2]AdaptivePerformanceWindow{h.windows[first], h.windows[last]}
	return windows[1].generation == generation && adaptiveCapacityEvidence(now, windows[:]).blocksTrial(path, epoch)
}
