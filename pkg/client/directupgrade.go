package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// directUpgradeTiming bundles the opportunistic direct-UDP upgrade's pacing
// knobs. Each Connection resolves and stores its own immutable copy once, at
// ConnectWithOptions time (see (*Connection).upgradeTiming) -- never a
// package-level var later mutated in place. A test that wants a fast
// upgrade/revert cycle to observe (see pkg/server's
// TestDirectUpgradeEndToEnd) supplies Options.DirectUpgradeTiming instead;
// package vars shared between a Connection's own background goroutine and
// whatever else touched them were tried first and produced exactly the data
// race this design avoids.
type directUpgradeTiming struct {
	// initialDelay is how long a freshly connected WebSocket-mode session
	// waits before its first direct-UDP upgrade attempt, giving the
	// control-plane connection and local tunnel listeners a moment to
	// settle.
	initialDelay time.Duration
	// retryInterval paces retries after a failed (or not offered) upgrade
	// attempt: long enough that a network with no viable NAT-traversal path
	// -- symmetric NAT, or a server that hasn't opted into
	// relay.advertise_direct -- isn't polled aggressively, short enough to
	// notice a network change (moving to a friendlier NAT, the operator
	// enabling the feature) within a reasonable time.
	retryInterval time.Duration
	// healthCheckInterval paces the supervisor's liveness probes once
	// upgraded.
	healthCheckInterval time.Duration
	reflectTimeout      time.Duration
	probeTimeout        time.Duration
}

func defaultDirectUpgradeTiming() directUpgradeTiming {
	return directUpgradeTiming{
		initialDelay:        3 * time.Second,
		retryInterval:       2 * time.Minute,
		healthCheckInterval: 20 * time.Second,
		reflectTimeout:      3 * time.Second,
		probeTimeout:        3 * time.Second,
	}
}

// DirectUpgradeTiming overrides the opportunistic direct-UDP upgrade's
// pacing (see Options.DirectUpgradeTiming). Every field left at its zero
// value keeps that one setting's production default; this exists for tests
// exercising a real upgrade/revert cycle end to end within a few seconds,
// not for production tuning.
type DirectUpgradeTiming struct {
	InitialDelay        time.Duration
	RetryInterval       time.Duration
	HealthCheckInterval time.Duration
	ReflectTimeout      time.Duration
	ProbeTimeout        time.Duration
}

func resolveDirectUpgradeTiming(o *DirectUpgradeTiming) directUpgradeTiming {
	t := defaultDirectUpgradeTiming()
	if o == nil {
		return t
	}
	if o.InitialDelay > 0 {
		t.initialDelay = o.InitialDelay
	}
	if o.RetryInterval > 0 {
		t.retryInterval = o.RetryInterval
	}
	if o.HealthCheckInterval > 0 {
		t.healthCheckInterval = o.HealthCheckInterval
	}
	if o.ReflectTimeout > 0 {
		t.reflectTimeout = o.ReflectTimeout
	}
	if o.ProbeTimeout > 0 {
		t.probeTimeout = o.ProbeTimeout
	}
	return t
}

// directUpgradeLoop is the background goroutine a WebSocket-fallback
// Connection runs (unless Options.NoDirectUpgrade) to opportunistically
// escape the relay's WebSocket data plane for a direct WireGuard UDP path,
// and to revert if that path later stalls. It never tears down the
// WebSocket transport -- Hybrid keeps both alive -- so a revert is just
// re-seeding the peer's endpoint back to wstransport.WSSentinel, not a
// reconnect.
func (c *Connection) directUpgradeLoop() {
	c.mu.Lock()
	hybrid := c.hybrid
	c.mu.Unlock()
	if hybrid == nil {
		return
	}
	bind, ok := hybrid.UDP.(*wstransport.FilterBind)
	if !ok {
		return
	}

	var activeCandidate string // "" means "not currently on the direct path"
	wait := c.upgradeTiming.initialDelay
	for {
		select {
		case <-c.stop:
			return
		case <-time.After(wait):
		}

		if activeCandidate != "" {
			if c.directPathHealthy(activeCandidate) {
				wait = c.upgradeTiming.healthCheckInterval
				continue
			}
			c.log.Info("direct UDP path stalled or was reclaimed by the WebSocket fallback; reverting", "server", c.DisplayName())
			if err := c.revertToWebSocket(); err != nil {
				// activeCandidate deliberately stays set: this branch is the
				// only place anything re-seeds the peer's endpoint away from
				// the now-confirmed-dead direct address, so leaving it blank
				// here would strand the data plane there until a fresh
				// upgrade attempt happened to succeed -- which, if /v1/punch
				// is what's unavailable, might be never. Keeping it set
				// re-enters this same branch next tick and retries the
				// revert instead of wandering off to try a new upgrade.
				c.log.Warn("reverting to WebSocket fallback failed; will retry", "server", c.DisplayName(), "error", err)
				wait = c.upgradeTiming.healthCheckInterval
				continue
			}
			c.transport.Store(uint32(transportWSSRelay))
			activeCandidate = ""
			wait = c.upgradeTiming.retryInterval
			continue
		}

		activeCandidate = c.tryDirectUpgrade(bind)
		if activeCandidate != "" {
			wait = c.upgradeTiming.healthCheckInterval
		} else {
			wait = c.upgradeTiming.retryInterval
		}
	}
}

// stackAndServerKey snapshots the fields directupgrade.go's background
// goroutine needs under c.mu, once per call, rather than reading c.Stack
// (or c.Response) piecemeal across a function body. Close() clears c.Stack
// to nil under the same lock, and this goroutine runs for the Connection's
// whole lifetime independently of whatever the caller of Close() is doing --
// without a single consistent snapshot, a Close() racing an in-flight
// upgrade attempt can observe c.Stack go nil between two unsynchronized
// reads of it and panic. ok is false only when the connection is already
// closed; callers should treat that as "nothing to do", not an error.
func (c *Connection) stackAndServerKey() (stack *wgnet.Stack, serverPub string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Stack == nil {
		return nil, "", false
	}
	return c.Stack, c.Response.ServerPublicKey, true
}

// directPathHealthy reports whether the direct-UDP path is both (a) the
// peer's actual current endpoint and (b) reachable right now. Checking only
// probeDirectPath is not enough: WireGuard's own peer roaming is symmetric,
// so a single authenticated packet arriving over the WebSocket fallback --
// entirely possible while both transports stay live on the same device --
// silently moves the peer's endpoint back to WebSocket, after which
// probeDirectPath would keep reporting success (just routed over WS instead)
// and this connection would never notice it had quietly fallen back.
func (c *Connection) directPathHealthy(candidate string) bool {
	stack, serverPub, ok := c.stackAndServerKey()
	if !ok {
		return false
	}
	ep, found, err := stack.PeerEndpoint(serverPub)
	if err != nil || !found || ep != candidate {
		return false
	}
	return c.probeDirectPath()
}

// tryDirectUpgrade runs one full candidate-exchange-and-punch attempt. It
// returns the confirmed direct candidate address on success, or "" on
// failure -- and confirming success takes two checks, not one:
// probeDirectPath alone cannot tell "the direct path works" apart from "the
// WebSocket fallback still works", because WireGuard's own peer roaming is
// symmetric: if any authenticated packet arrives over WebSocket while the
// probe is in flight (both transports stay live on the same device), the
// peer's endpoint silently moves back to WebSocket and the probe would
// still report success, just routed over the transport this was trying to
// escape. PeerEndpoint is what actually distinguishes the two.
func (c *Connection) tryDirectUpgrade(bind *wstransport.FilterBind) string {
	first, err := c.postPunch("")
	if err != nil {
		c.log.Debug("direct-upgrade candidate exchange failed", "error", err)
		return ""
	}
	if first.RelayReflectAddr == "" {
		return "" // server has no direct-upgrade support, or hasn't opted in
	}

	selfAddr, err := selfReflect(bind, first.RelayReflectAddr, c.upgradeTiming.reflectTimeout)
	if err != nil {
		c.log.Debug("direct-upgrade self-reflection failed", "error", err)
		return ""
	}

	second, err := c.postPunch(selfAddr)
	if err != nil {
		c.log.Debug("direct-upgrade candidate exchange failed", "error", err)
		return ""
	}
	if second.ServerAddr == "" {
		return "" // server has no self-reflected candidate yet
	}

	stack, serverPub, ok := c.stackAndServerKey()
	if !ok {
		return "" // connection closed while this attempt was in flight
	}

	primeAddr(bind, second.ServerAddr)
	if err := stack.UpdateEndpoint(serverPub, second.ServerAddr); err != nil {
		c.log.Debug("direct-upgrade endpoint seed failed", "error", err)
		return ""
	}
	if !c.probeDirectPath() {
		_ = stack.UpdateEndpoint(serverPub, wstransport.WSSentinel)
		return ""
	}
	if ep, found, err := stack.PeerEndpoint(serverPub); err != nil || !found || ep != second.ServerAddr {
		c.log.Debug("direct-upgrade probe succeeded but the peer's endpoint is not the seeded candidate; a WebSocket packet likely roamed it back already", "endpoint", ep, "candidate", second.ServerAddr)
		_ = stack.UpdateEndpoint(serverPub, wstransport.WSSentinel)
		return ""
	}
	c.log.Info("upgraded to direct UDP", "server", c.DisplayName(), "candidate", second.ServerAddr)
	c.transport.Store(uint32(transportUDPRelayReflector))
	return second.ServerAddr
}

// revertToWebSocket re-seeds the peer's endpoint back to the WebSocket
// fallback. The WebSocket connection itself was never closed, so this takes
// effect on the very next packet with no reconnect involved -- except that
// UpdateEndpoint itself can fail if that connection is not currently live
// (Bind.ParseEndpoint errors when its WebSocket peer isn't connected; see
// wstransport/bind.go), in which case the caller must keep retrying rather
// than silently accepting the peer staying pointed at a dead direct address.
// A closed Connection is reported as success, not a failure to retry:
// directUpgradeLoop's own c.stop check will end the loop on its next tick.
func (c *Connection) revertToWebSocket() error {
	stack, serverPub, ok := c.stackAndServerKey()
	if !ok {
		return nil
	}
	return stack.UpdateEndpoint(serverPub, wstransport.WSSentinel)
}

// probeDirectPath actively confirms the current WireGuard peer endpoint is
// reachable by dialing the server's tunnel IP on a port nothing is expected
// to be listening on. Any prompt response -- including a refusal -- proves
// a decrypted packet reached the real server and a reply made it back; only
// the dial's own deadline expiring with no response at all counts as
// failure.
func (c *Connection) probeDirectPath() bool {
	c.mu.Lock()
	stack, serverIP := c.Stack, c.serverTunnelIP
	c.mu.Unlock()
	if stack == nil || !serverIP.IsValid() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.upgradeTiming.probeTimeout)
	defer cancel()
	conn, err := stack.DialContext(ctx, "tcp", net.JoinHostPort(serverIP.String(), "1"))
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		return true
	}
	return !errors.Is(err, context.DeadlineExceeded)
}

// primeAddr sends a short burst of NAT-priming pings directly to addr,
// opening this client's side of the NAT pinhole shortly before WireGuard's
// own handshake attempt arrives at the same address.
func primeAddr(bind *wstransport.FilterBind, addr string) {
	for i := 0; i < wstransport.PrimeBurst; i++ {
		if err := bind.SendControl(wstransport.FramePrime, nil, addr); err != nil {
			return
		}
		if i < wstransport.PrimeBurst-1 {
			time.Sleep(wstransport.PrimeInterval)
		}
	}
}

// selfReflect asks the relay's UDP reflector (at relayReflectAddr) what
// address it observed the request come from, using bind so the request goes
// out from -- and the reply is intercepted on -- the exact same local port
// WireGuard traffic itself uses.
func selfReflect(bind *wstransport.FilterBind, relayReflectAddr string, timeout time.Duration) (string, error) {
	// Control is shared with priming pings and any earlier, already
	// timed-out reflection attempt. Without draining it first, a frame left
	// over from a previous cycle -- most awkwardly a stale
	// FrameReflectResponse -- would be handed back here as if it answered
	// this request, up to a full retry interval late and describing a NAT
	// mapping that has likely already expired.
	drainControl(bind)
	if err := bind.SendControl(wstransport.FrameReflectRequest, nil, relayReflectAddr); err != nil {
		return "", err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case cp := <-bind.Control():
			if cp.Type == wstransport.FrameReflectResponse {
				return string(cp.Payload), nil
			}
		case <-timer.C:
			return "", fmt.Errorf("self-reflection timed out")
		}
	}
}

// drainControl discards whatever is currently queued on bind.Control()
// without blocking.
func drainControl(bind *wstransport.FilterBind) {
	for {
		select {
		case <-bind.Control():
		default:
			return
		}
	}
}

// postPunch exchanges one round of protocol.PunchRequest/PunchResponse with
// the server's /v1/punch endpoint. A 404 (server has no direct-upgrade
// support, or hasn't opted in) is reported as a zero PunchResponse with no
// error -- it's an expected, common steady state, not a failure worth
// logging on every retry.
func (c *Connection) postPunch(clientAddr string) (protocol.PunchResponse, error) {
	c.mu.Lock()
	base, token := c.base, c.token
	c.mu.Unlock()
	b, _ := json.Marshal(protocol.PunchRequest{ClientAddr: clientAddr})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/punch", bytes.NewReader(b))
	if err != nil {
		return protocol.PunchResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return protocol.PunchResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return protocol.PunchResponse{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return protocol.PunchResponse{}, fmt.Errorf("punch request failed: %s", resp.Status)
	}
	var out protocol.PunchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return protocol.PunchResponse{}, err
	}
	return out, nil
}
