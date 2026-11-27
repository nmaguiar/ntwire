package client

import (
	"context"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

const (
	adaptiveTrialDuration    = 30 * time.Second
	adaptiveUDPTrialDuration = 20 * time.Second
	adaptiveTrialCooldown    = 2 * time.Minute
)

func (t *adaptiveTrial) elapsed(now time.Time) bool {
	limit := adaptiveTrialDuration
	if usesTunnelRTT(t.incumbent) {
		// A demoted UDP or relay path is retained for 30 seconds. Leave
		// time for the control round trips that restore it.
		limit = adaptiveUDPTrialDuration
	}
	return now.Sub(t.started) >= limit
}

type AdaptiveTrialStatus struct {
	Incumbent   string  `json:"incumbent"`
	Candidate   string  `json:"candidate"`
	State       string  `json:"state"`
	Reason      string  `json:"reason,omitempty"`
	Windows     int     `json:"comparable_windows,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
	GainPercent float64 `json:"median_gain_percent,omitempty"`
}

// One observer owns the trial for the lifetime of a connection network.
// The trial measures live admitted traffic on the same WireGuard peer.
type adaptiveTrial struct {
	incumbent, candidate string
	baselineSince        time.Time
	started, next        time.Time
	status               AdaptiveTrialStatus
	lastCarrier          string
	parallelRelays       bool
	release              func()
}

func (t *adaptiveTrial) candidateFor(now time.Time, primary string, paths []wstransport.QualifiedCarrier, activeSince time.Time, windows []AdaptivePerformanceWindow) string {
	if now.Before(t.next) || now.Sub(activeSince) < adaptiveDwell || activeSince.IsZero() {
		return ""
	}
	var count, samples, tunnelSamples int
	for i := len(windows) - 1; i >= 0; i-- {
		w := windows[i]
		if w.Path != primary || !w.End.After(activeSince) || !freshWindow(now, w) {
			continue
		}
		if count == 0 {
			if now.Sub(w.End) > 2*adaptiveFeedbackInterval || w.WSSQueueP95 > 20*time.Millisecond || quicSendPressure(w) {
				return ""
			}
		}
		count++
		samples += w.RTTSamples
		tunnelSamples += w.TunnelRTTSamples
	}
	if count < 3 {
		return ""
	}
	var candidates []string
	for _, path := range paths {
		if path.Name == primary {
			continue
		}
		kind := adaptiveTrialCarrier(path.Name)
		switch kind {
		case protocol.CarrierWSS, protocol.CarrierQUIC, protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP:
		case protocol.CarrierRelayUDP:
			if path.Carrier != kind || (protocol.ValidCarrierID(primary) && !t.parallelRelays) {
				continue
			}
		default:
			continue
		}
		observations := samples
		if usesTunnelRTT(primary) || usesTunnelRTT(path.Name) {
			observations = tunnelSamples
		}
		if observations >= 6 {
			candidates = append(candidates, path.Name)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	for i, path := range candidates {
		if adaptiveTrialCarrier(path) == t.lastCarrier {
			return candidates[(i+1)%len(candidates)]
		}
	}
	return candidates[0]
}

func adaptiveTrialCarrier(path string) string {
	// Direct carrier IDs are named constants. A relay allocation uses its
	// server-generated opaque ID for authorization and per-path observations.
	if protocol.ValidCarrierID(path) {
		return protocol.CarrierRelayUDP
	}
	return path
}

func (t *adaptiveTrial) verdict(now time.Time, windows []AdaptivePerformanceWindow, reversal bool) AdaptivePathDecision {
	var matched []AdaptivePerformanceWindow
	for _, w := range windows {
		if (w.Path == t.incumbent && w.End.After(t.baselineSince) && !w.End.After(t.started)) ||
			(w.Path == t.candidate && w.End.After(t.started)) {
			matched = append(matched, w)
		}
	}
	return compareAdaptivePaths(now, t.incumbent, t.candidate, reversal, matched)
}

func (t *adaptiveTrial) finish(now time.Time, state, reason string) {
	if t.release != nil {
		t.release()
		t.release = nil
	}
	t.status = AdaptiveTrialStatus{Incumbent: t.incumbent, Candidate: t.candidate, State: state, Reason: reason}
	t.started = time.Time{}
	t.next = now.Add(adaptiveTrialCooldown + time.Duration(rand.Int64N(int64(5*time.Second))))
}

func (a *adaptiveCarrierClient) advanceTrial(ctx context.Context, t *adaptiveTrial, now time.Time, idle bool) {
	a.advanceTrialOn(ctx, t, now, idle, a)
}

func (a *adaptiveCarrierClient) advanceTrialOn(ctx context.Context, t *adaptiveTrial, now time.Time, idle bool, parent *adaptiveCarrierClient) {
	info, _, _ := a.credentials()
	primary, epoch, paths, events := a.bind.LaneDetails(a.lane)
	var activeSince time.Time
	if len(events) != 0 {
		activeSince = events[len(events)-1].At
	}
	var windows []AdaptivePerformanceWindow
	var pressured bool
	if snapshot := a.measurements.snapshot(now, info.AuthGeneration); snapshot != nil {
		windows = snapshot.Windows
		pressured = snapshot.Capacity.blocksTrial(primary, epoch)
	}
	if t.started.IsZero() {
		if idle || pressured || (primary == protocol.CarrierWSS && a.ws.PeerBacklogged("remote")) {
			return
		}
		paths = slices.DeleteFunc(paths, func(path wstransport.QualifiedCarrier) bool {
			return protocol.IsNativeUDPCarrier(path.Name) && (!info.UDPSelect || !a.nativeUDPUsable(path.Name))
		})
		candidate := t.candidateFor(now, primary, paths, activeSince, windows)
		if candidate == "" || !parent.beginExploration(now) {
			return
		}
		t.release = func() { parent.exploration.Store(false) }
		t.lastCarrier = adaptiveTrialCarrier(candidate)
		t.incumbent, t.candidate = primary, candidate
		if err := a.selectPrimaryFrom(ctx, candidate, primary); err != nil {
			if !carrierControlDenied(err) && ctx.Err() == nil {
				if restoreErr := a.selectPrimaryFrom(ctx, primary, primary); restoreErr != nil {
					t.finish(now, "selection unconfirmed", "control path could not confirm the incumbent")
					a.measurements.setTrial(t.status)
					return
				}
			}
			t.finish(now, "skipped", "candidate selection could not be confirmed")
		} else {
			t.baselineSince, t.started = activeSince, time.Now()
			t.status = AdaptiveTrialStatus{Incumbent: primary, Candidate: candidate, State: "measuring"}
		}
	} else {
		switch {
		case primary != t.candidate || activeSince.After(t.started):
			t.finish(now, "interrupted", "active carrier changed during the trial")
		case !idle && !t.elapsed(now):
			return
		default:
			reversal := slices.ContainsFunc(events, func(event wstransport.SwitchEvent) bool {
				return event.From == t.candidate && event.To == t.incumbent && now.Sub(event.At) < adaptiveReversal
			})
			result := t.verdict(now, windows, reversal)
			if !idle && result.WouldSwitch {
				t.finish(now, "retained candidate", result.Reason)
			} else {
				reason := result.Reason
				if idle {
					reason = "forwarding demand ended"
				}
				if err := a.selectPrimaryFrom(ctx, t.incumbent, t.candidate); err != nil {
					t.finish(now, "incumbent unavailable", reason)
				} else {
					t.finish(now, "restored incumbent", reason)
				}
			}
			t.status.Windows = result.ComparableWindows
			t.status.Confidence = result.Confidence
			t.status.GainPercent = result.MedianGainPercent
		}
	}
	a.measurements.setTrial(t.status)
}
