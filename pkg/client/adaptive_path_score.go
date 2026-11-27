package client

import (
	"math"
	"slices"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

const (
	adaptiveDwell       = 30 * time.Second
	adaptiveReversal    = 2 * time.Minute
	pathReferenceBits   = 8 * 128 * 1024
	pathConfidenceFloor = 0.65
)

// AdaptivePathDecision describes the evidence and verdict of a comparison.
type AdaptivePathDecision struct {
	Candidate         string  `json:"candidate,omitempty"`
	WouldSwitch       bool    `json:"would_switch"`
	Reason            string  `json:"reason"`
	ComparableWindows int     `json:"comparable_windows,omitempty"`
	ImprovedWindows   int     `json:"improved_windows,omitempty"`
	MedianGainPercent float64 `json:"median_gain_percent,omitempty"`
	Confidence        float64 `json:"confidence,omitempty"`
}

// scoreAdaptivePaths compares recent observed delivery under comparable
// demand. It intentionally ignores a reachability-only sample.
func scoreAdaptivePaths(now time.Time, primary string, paths []wstransport.QualifiedCarrier, events []wstransport.SwitchEvent, windows []AdaptivePerformanceWindow) AdaptivePathDecision {
	if primary == "" {
		return AdaptivePathDecision{Reason: "primary unavailable"}
	}
	if len(events) == 0 || now.Sub(events[len(events)-1].At) < adaptiveDwell {
		return AdaptivePathDecision{Reason: "minimum active path dwell"}
	}
	best := AdaptivePathDecision{Reason: "no other qualified path with a live RTT"}
	for _, path := range paths {
		if path.Name == primary || path.RTT <= 0 {
			continue
		}
		reversing := slices.ContainsFunc(events, func(event wstransport.SwitchEvent) bool {
			return event.From == path.Name && event.To == primary && now.Sub(event.At) < adaptiveReversal
		})
		d := compareAdaptivePaths(now, primary, path.Name, reversing, windows)
		if best.Candidate == "" ||
			(d.WouldSwitch && (!best.WouldSwitch || d.MedianGainPercent > best.MedianGainPercent)) ||
			(!best.WouldSwitch && d.ComparableWindows > best.ComparableWindows) {
			best = d
		}
	}
	return best
}

func compareAdaptivePaths(now time.Time, primary, candidate string, reversal bool, windows []AdaptivePerformanceWindow) AdaptivePathDecision {
	out := AdaptivePathDecision{Candidate: candidate, Reason: "fewer than six recent RTT observations on one path"}
	primaryRelay, candidateRelay := protocol.ValidCarrierID(primary), protocol.ValidCarrierID(candidate)
	tunnelRTT := usesTunnelRTT(primary) || usesTunnelRTT(candidate)
	preferDirect := primaryRelay && !candidateRelay
	primaryRTT, primaryCount, primaryFresh := windowRTT(now, primary, windows, tunnelRTT)
	candidateRTT, candidateCount, candidateFresh := windowRTT(now, candidate, windows, tunnelRTT)
	if primaryCount < 6 || candidateCount < 6 {
		if tunnelRTT {
			out.Reason = "fewer than six recent tunnel RTT observations on one path"
		}
		return out
	}

	requiredFraction, requiredSeconds := 0.15, 0.005
	if reversal {
		requiredFraction, requiredSeconds = 0.20, 0.010
	}
	var gain [4]float64
	var used [adaptiveHistoryWindows]bool
	var matchedFresh time.Time
	for i := len(windows) - 1; i >= 0 && out.ComparableWindows < len(gain); i-- {
		reference := windows[i]
		if reference.Path != primary || !freshWindow(now, reference) {
			continue
		}
		for j := len(windows) - 1; j >= 0; j-- {
			trial := windows[j]
			if trial.Path != candidate || used[j] || !freshWindow(now, trial) ||
				!comparableDirection(reference.Upload, trial.Upload) || !comparableDirection(reference.Download, trial.Download) {
				continue
			}
			useQueue := reference.WSSQueueP95 > 0 && trial.WSSQueueP95 > 0
			baseCost := windowCost(reference, primaryRTT, useQueue)
			trialCost := windowCost(trial, candidateRTT, useQueue)
			if math.IsInf(baseCost, 0) || math.IsInf(trialCost, 0) {
				continue
			}
			used[j] = true
			saved := baseCost - trialCost
			gain[out.ComparableWindows] = (saved / baseCost) * 100
			out.ComparableWindows++
			margin := max(baseCost*requiredFraction, requiredSeconds)
			if preferDirect {
				// Prefer the direct path when its measured cost is close enough.
				margin = -max(baseCost*0.05, 0.002)
			}
			if saved >= margin {
				out.ImprovedWindows++
			}
			fresh := reference.End
			if trial.End.Before(fresh) {
				fresh = trial.End
			}
			if fresh.After(matchedFresh) {
				matchedFresh = fresh
			}
			break
		}
	}
	out.Reason = "fewer than three comparable demand windows"
	if out.ComparableWindows < 3 {
		return out
	}
	gains := gain[:out.ComparableWindows]
	slices.Sort(gains)
	out.MedianGainPercent = (gains[(len(gains)-1)/2] + gains[len(gains)/2]) / 2
	// Time and agreement penalize stale or conflicting observations.
	oldest := max(now.Sub(primaryFresh), now.Sub(candidateFresh), now.Sub(matchedFresh))
	agreement := float64(out.ImprovedWindows) / float64(out.ComparableWindows)
	out.Confidence = math.Exp2(-oldest.Seconds()/adaptiveHistoryLifetime.Seconds()) * agreement
	out.Reason = "gain below margin in comparable demand windows"
	if out.ImprovedWindows >= 3 {
		out.Reason = "insufficient confidence"
		if out.Confidence >= pathConfidenceFloor {
			out.WouldSwitch = true
			out.Reason = "sustained improvement under comparable demand"
			if preferDirect && out.MedianGainPercent < requiredFraction*100 {
				out.Reason = "direct path comparable under demand"
			}
		}
	}
	return out
}

func usesTunnelRTT(path string) bool {
	return protocol.IsNativeUDPCarrier(path) || protocol.ValidCarrierID(path)
}

func freshWindow(now time.Time, w AdaptivePerformanceWindow) bool {
	age := now.Sub(w.End)
	return age >= 0 && age < adaptiveHistoryLifetime
}

func windowRTT(now time.Time, path string, windows []AdaptivePerformanceWindow, tunnel bool) (time.Duration, int, time.Time) {
	var weighted time.Duration
	var count int
	var newest time.Time
	for _, w := range windows {
		rtt, samples := w.RTT, w.RTTSamples
		if tunnel {
			rtt, samples = w.TunnelRTT, w.TunnelRTTSamples
		}
		if w.Path == path && freshWindow(now, w) && rtt > 0 && samples > 0 {
			count += samples
			weighted += rtt * time.Duration(samples)
			if w.End.After(newest) {
				newest = w.End
			}
		}
	}
	if count == 0 {
		return 0, 0, time.Time{}
	}
	return weighted / time.Duration(count), count, newest
}

func comparableDirection(a, b *DirectionPerformance) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return min(a.OfferedBPS, b.OfferedBPS)*2 >= max(a.OfferedBPS, b.OfferedBPS)
}

func windowCost(w AdaptivePerformanceWindow, rtt time.Duration, useQueue bool) float64 {
	var seconds float64
	if w.Upload != nil {
		seconds = pathReferenceBits / w.Upload.DeliveredBPS
	}
	if w.Download != nil {
		seconds = max(seconds, pathReferenceBits/w.Download.DeliveredBPS)
	}
	if useQueue {
		seconds += w.WSSQueueP95.Seconds()
	}
	return seconds + rtt.Seconds()
}
