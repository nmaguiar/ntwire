package client

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// A child can fail over independently of the anchor. Control requests are
// bounded and the worker is canceled with the child stack.
func (c *Connection) maintainChildCarrierHealth(ctx context.Context, child *connectionNetwork, parent *adaptiveCarrierClient) {
	a := child.adaptive
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var demand udpProbeDemand
	var current string
	var epoch, generation, sequence uint64
	var nextProbe, nextRecovery, wssLossUntil time.Time
	nextStandby := time.Now().Add(adaptiveUDPRetry + rand.N(time.Second))
	for ctx.Err() == nil {
		var lostUDP nativeUDPLoss
		var now time.Time
		select {
		case <-ctx.Done():
			return
		case lostUDP = <-a.udpLost:
			now = time.Now()
		case lost := <-a.wssLost:
			now = time.Now()
			wssLossUntil = lost.Add(adaptiveWSSHealthWindow)
		case now = <-ticker.C:
		}
		path, rev, _ := a.bind.LaneState(a.lane)
		info, _, _ := a.credentials()
		if current != path || epoch != rev || generation != info.AuthGeneration {
			current, epoch, generation = path, rev, info.AuthGeneration
			demand = udpProbeDemand{}
		}
		if path == protocol.CarrierWSS && now.Before(wssLossUntil) && !now.Before(nextRecovery) {
			if _, err := a.ws.CarrierEndpoint("remote"); err != nil {
				attempted, err := c.recoverAdaptiveWSS(ctx, a)
				if attempted {
					nextRecovery = time.Now().Add(adaptiveRecoveryCooldown)
				}
				if carrierControlDenied(err) {
					wssLossUntil = time.Time{}
				}
				continue
			}
		}
		previous := sequence
		sequence = a.lane.DemandSequence()
		var traffic uint64
		if sequence != previous {
			traffic = 1
		}
		if protocol.IsNativeUDPCarrier(path) {
			if demand.ready(now, traffic, !now.Before(nextProbe) && !now.Before(nextRecovery)) && parent.tunnelProbe.CompareAndSwap(false, true) {
				demand.pending = false
				nextProbe = now.Add(adaptiveTunnelProbeInterval)
				rtt := child.tunnelRTT(ctx)
				parent.tunnelProbe.Store(false)
				sequence = a.lane.DemandSequence() // The echo itself is not new demand.
				if rtt > 0 {
					demand.misses = 0
				} else {
					demand.misses = min(demand.misses+1, adaptiveUDPMissLimit)
				}
			}
			hardLoss := lostUDP.path == path && lostUDP.epoch == rev
			if (hardLoss || demand.misses == adaptiveUDPMissLimit) && !now.Before(nextRecovery) {
				latestPath, latestEpoch, _ := a.bind.LaneState(a.lane)
				latest, _, _ := a.credentials()
				if latestPath == path && latestEpoch == rev && latest.AuthGeneration == generation && ctx.Err() == nil {
					if a.recoverAdaptiveUDP(ctx, path) {
						a.bind.RemovePath(a.lane, path)
					}
					nextRecovery = time.Now().Add(adaptiveRecoveryCooldown)
				}
			}
			continue
		}
		if !info.PathSelect || path != protocol.CarrierWSS || traffic == 0 || now.Before(nextStandby) || !a.laneReady(true) {
			continue
		}
		nextStandby = now.Add(adaptiveUDPRetry + rand.N(time.Second))
		c.mu.Lock()
		draining := c.closed || child.draining
		c.mu.Unlock()
		if !draining {
			_ = parent.qualifyStandby(now, func() error { return a.qualifyChildStandby(ctx) })
		}
	}
}

func (a *adaptiveCarrierClient) qualifyChildStandby(ctx context.Context) error {
	for _, path := range [...]string{protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP} {
		if a.nativeUDPUsable(path) && !a.bind.HasQualifiedPath(a.lane, path) {
			return a.qualifyUDP(ctx, path)
		}
	}
	if a.quic != nil && !a.bind.HasQualifiedPath(a.lane, protocol.CarrierQUIC) {
		return a.qualifyQUIC(ctx, protocol.CarrierWSS)
	}
	return nil
}

type nativeUDPLoss struct {
	path  string
	epoch uint64
}

func (a *adaptiveCarrierClient) nativeUDPSendFailed(candidate string) func(error) {
	return func(err error) {
		if a.udpLost == nil || !errors.Is(err, net.ErrClosed) {
			return
		}
		u := a.nativeUDP(candidate)
		if u == nil || !u.closed.CompareAndSwap(false, true) {
			return
		}
		if current, epoch, _ := a.bind.LaneState(a.lane); current == candidate {
			select {
			case a.udpLost <- nativeUDPLoss{path: candidate, epoch: epoch}:
			default:
			}
		}
	}
}

const (
	adaptiveRecoveryBudget   = 8 * time.Second
	adaptiveRecoveryCooldown = 3 * time.Second
	adaptiveUDPMissLimit     = 3
	adaptiveUDPHealthWindow  = 30 * time.Second
	adaptiveWSSHealthWindow  = 30 * time.Second
)

// udpProbeDemand owns at most one outstanding demand credit. An application
// write during the probe cooldown can be the only activity on a stalled TCP
// stream, so keep its credit until a probe starts or the path changes.
type udpProbeDemand struct {
	pending     bool
	misses      int
	activeUntil time.Time
}

func (d *udpProbeDemand) needsProbe(now time.Time) bool {
	return now.Before(d.activeUntil) && (d.pending || d.misses > 0)
}

func (d *udpProbeDemand) ready(now time.Time, traffic uint64, probeAvailable bool) bool {
	if traffic > 0 {
		if !now.Before(d.activeUntil) {
			d.misses = 0
		}
		d.pending = true
		d.activeUntil = now.Add(adaptiveUDPHealthWindow)
	}
	return probeAvailable && d.needsProbe(now)
}

// A physical WebSocket close is authoritative for recovery. The bind's
// lifecycle callback only hands off an event and never does network I/O.
func (a *adaptiveCarrierClient) signalWSSLoss() {
	if a.wssLost == nil {
		return
	}
	if active, _, _ := a.bind.LaneState(a.lane); active != protocol.CarrierWSS {
		return
	}
	select {
	case a.wssLost <- time.Now():
	default:
	}
}

func (c *Connection) recoverAdaptiveWSS(ctx context.Context, a *adaptiveCarrierClient) (attempted bool, err error) {
	primary, _, _ := a.bind.LaneState(a.lane)
	if primary != protocol.CarrierWSS {
		return false, nil
	}
	candidate := protocol.CarrierQUIC
	info, _, _ := a.credentials()
	if !a.bind.HasQualifiedPath(a.lane, candidate) && info.UDPSelect {
		for _, native := range [...]string{protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP} {
			if a.nativeUDPUsable(native) && a.bind.HasQualifiedPath(a.lane, native) {
				candidate = native
				break
			}
		}
	}
	if !a.bind.HasQualifiedPath(a.lane, candidate) && a.relay != nil {
		candidate = a.qualifiedRelayStandby("")
	}
	if !a.bind.HasQualifiedPath(a.lane, candidate) {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, adaptiveRecoveryBudget)
	defer cancel()
	err = a.selectPrimaryFrom(ctx, candidate, protocol.CarrierWSS)
	// A returning WSS connection may change the local epoch after the
	// server's commit. Read authoritative state again before sending.
	if errors.Is(err, wstransport.ErrStalePathEpoch) && ctx.Err() == nil {
		err = a.selectPrimaryFrom(ctx, candidate, protocol.CarrierWSS)
	}
	if err != nil {
		c.log.Debug("adaptive standby recovery did not complete", "error", err)
	} else {
		c.log.Info("adaptive lane recovered on a qualified carrier after WebSocket disconnect")
	}
	return true, err
}

func (a *adaptiveCarrierClient) recoverAdaptiveUDP(ctx context.Context, source string) bool {
	ctx, cancel := context.WithTimeout(ctx, adaptiveRecoveryBudget)
	defer cancel()
	if _, err := a.ws.CarrierEndpoint("remote"); err == nil && a.bind.HasQualifiedPath(a.lane, protocol.CarrierWSS) {
		if err := a.selectPrimaryFrom(ctx, protocol.CarrierWSS, source); err == nil {
			return true
		} else if carrierControlDenied(err) {
			return false
		}
	}
	if a.bind.HasQualifiedPath(a.lane, protocol.CarrierQUIC) {
		if err := a.selectPrimaryFrom(ctx, protocol.CarrierQUIC, source); err == nil {
			return true
		} else if carrierControlDenied(err) {
			return false
		}
	}
	for _, candidate := range [...]string{protocol.CarrierDirectUDP, protocol.CarrierAlternateUDP} {
		if candidate == source || !a.nativeUDPUsable(candidate) || !a.bind.HasQualifiedPath(a.lane, candidate) {
			continue
		}
		if err := a.selectPrimaryFrom(ctx, candidate, source); err == nil {
			return true
		} else if carrierControlDenied(err) {
			return false
		}
	}
	if candidate := a.qualifiedRelayStandby(source); candidate != "" {
		return a.selectPrimaryFrom(ctx, candidate, source) == nil
	}
	return false
}
