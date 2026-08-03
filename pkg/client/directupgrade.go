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
	// relayBindKeepalive paces this client's FrameRelayBind resends while
	// riding the UDP-relay forwarding rung: it both refreshes this leg's own
	// NAT mapping and refreshes the relay's idle timeout for the session,
	// independent of whatever WireGuard's own persistent-keepalive is (or
	// isn't) configured to do.
	relayBindKeepalive time.Duration
}

func defaultDirectUpgradeTiming() directUpgradeTiming {
	return directUpgradeTiming{
		initialDelay:        3 * time.Second,
		retryInterval:       2 * time.Minute,
		healthCheckInterval: 20 * time.Second,
		reflectTimeout:      3 * time.Second,
		probeTimeout:        3 * time.Second,
		relayBindKeepalive:  15 * time.Second,
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
	RelayBindKeepalive  time.Duration
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
	if o.RelayBindKeepalive > 0 {
		t.relayBindKeepalive = o.RelayBindKeepalive
	}
	return t
}

// upgradeRung is directUpgradeLoop's position on the relay upgrade ladder:
// each rung trades more privacy (the server's real address, or at least
// more of the relay's visibility into traffic timing) for less overhead,
// and the loop only ever moves one rung at a time in either direction.
type upgradeRung int

const (
	rungNone     upgradeRung = iota // on the WebSocket fallback
	rungUDPRelay                    // WireGuard riding UDP forwarded through the relay's UDP-relay tier
	rungDirect                      // full escape, bypassing the relay's data plane entirely
)

// directUpgradeLoop is the background goroutine a WebSocket-fallback
// Connection runs (unless Options.NoDirectUpgrade) to opportunistically
// climb the relay upgrade ladder -- WSS, to UDP-relay forwarding, to a full
// direct-UDP escape -- and to revert one rung at a time if the current one
// later stalls. It never tears down the WebSocket transport -- Hybrid keeps
// it alive throughout -- so every rung change is just re-seeding the peer's
// endpoint, never a reconnect.
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

	rung := rungNone
	var relayCandidate, directCandidate string
	var relayStop chan struct{} // non-nil while a UDP-relay bind keepalive goroutine is running
	// nextDirectAttempt paces opportunistic escalation from rungUDPRelay to
	// rungDirect at retryInterval, independent of the faster
	// healthCheckInterval the loop otherwise ticks at once upgraded -- a
	// zero value is always due, so the first health-check tick after
	// reaching rungUDPRelay also tries escalating.
	var nextDirectAttempt time.Time
	// lastReason remembers the most recently logged failure/revert
	// explanation so a steady-state cause (e.g. "server has not enabled
	// direct UDP upgrade support") is announced once at Warn -- visible on
	// the CLI's default log level -- rather than repeated every
	// retryInterval for the life of the connection. A changed reason is
	// worth a fresh Warn; an unchanged one drops to Debug.
	var lastReason string
	stopRelayKeepalive := func() {
		if relayStop != nil {
			close(relayStop)
			relayStop = nil
		}
	}
	wait := c.upgradeTiming.initialDelay
	for {
		select {
		case <-c.stop:
			stopRelayKeepalive()
			return
		case <-time.After(wait):
		}

		switch rung {
		case rungNone:
			var relayReason, relayToken string
			relayCandidate, relayToken, relayReason = c.tryUDPRelayUpgrade(bind)
			if relayCandidate != "" {
				relayStop = make(chan struct{})
				go c.udpRelayKeepaliveLoop(bind, relayToken, relayCandidate, relayStop)
				rung = rungUDPRelay
				nextDirectAttempt = time.Time{}
				wait = c.upgradeTiming.healthCheckInterval
				lastReason = ""
				continue
			}
			if relayReason != udpRelayUnavailableReason {
				wait = c.upgradeTiming.retryInterval
				c.logUpgradeReason(&lastReason, relayReason, "UDP relay path not established; staying on WebSocket relay")
				continue
			}
			// The relay offers no UDP-relay tier at all (not merely a
			// failed attempt at this one) -- fall through to the existing
			// full-escape attempt on this same tick. Without this, a relay
			// that offers listen.reflect but not listen.udp_relay -- every
			// relay running before this tier existed -- would silently
			// lose the full-escape feature, since this rung would never
			// become available for it to wait on.
			var directReason string
			directCandidate, directReason = c.tryDirectUpgrade(bind, wstransport.WSSentinel)
			if directCandidate != "" {
				rung = rungDirect
				wait = c.upgradeTiming.healthCheckInterval
				lastReason = ""
				continue
			}
			wait = c.upgradeTiming.retryInterval
			c.logUpgradeReason(&lastReason, directReason, "direct UDP upgrade not established; staying on WebSocket relay")

		case rungUDPRelay:
			healthy, reason := c.pathHealthy(relayCandidate)
			if !healthy {
				c.logUpgradeReason(&lastReason, reason, "UDP relay path is no longer usable; reverting to WebSocket fallback", "candidate", relayCandidate)
				if err := c.setEndpoint(wstransport.WSSentinel); err != nil {
					c.log.Warn("reverting to WebSocket fallback failed; will retry", "server", c.DisplayName(), "error", err)
					wait = c.upgradeTiming.healthCheckInterval
					continue
				}
				c.transport.Store(uint32(transportWSSRelay))
				stopRelayKeepalive()
				relayCandidate = ""
				rung = rungNone
				wait = c.upgradeTiming.retryInterval
				continue
			}
			if nextDirectAttempt.After(time.Now()) {
				wait = c.upgradeTiming.healthCheckInterval
				lastReason = ""
				continue
			}
			nextDirectAttempt = time.Now().Add(c.upgradeTiming.retryInterval)
			var directReason string
			directCandidate, directReason = c.tryDirectUpgrade(bind, relayCandidate)
			if directCandidate != "" {
				rung = rungDirect
			}
			_ = directReason // staying on the already-healthy relay rung isn't itself news; nothing to log
			wait = c.upgradeTiming.healthCheckInterval
			lastReason = ""

		case rungDirect:
			healthy, reason := c.pathHealthy(directCandidate)
			if healthy {
				wait = c.upgradeTiming.healthCheckInterval
				lastReason = ""
				continue
			}
			// Revert exactly one rung: back to the UDP-relay path if it's
			// still warm (its keepalive kept running underneath the whole
			// time this connection rode the direct path), else all the way
			// to the WebSocket fallback.
			fallback, nextRung, nextTransport := wstransport.WSSentinel, rungNone, transportWSSRelay
			if relayCandidate != "" {
				fallback, nextRung, nextTransport = relayCandidate, rungUDPRelay, transportUDPRelay
			}
			c.logUpgradeReason(&lastReason, reason, "direct UDP path is no longer usable; reverting", "candidate", directCandidate, "fallback", fallback)
			if err := c.setEndpoint(fallback); err != nil {
				// directCandidate deliberately stays set: this branch is the
				// only place anything re-seeds the peer's endpoint away from
				// the now-confirmed-dead direct address, so leaving it blank
				// here would strand the data plane there until a fresh
				// upgrade attempt happened to succeed. Keeping it set
				// re-enters this same branch next tick and retries the
				// revert instead of wandering off to try a new upgrade.
				c.log.Warn("reverting direct UDP path failed; will retry", "server", c.DisplayName(), "error", err)
				wait = c.upgradeTiming.healthCheckInterval
				continue
			}
			c.transport.Store(uint32(nextTransport))
			directCandidate = ""
			rung = nextRung
			nextDirectAttempt = time.Now().Add(c.upgradeTiming.retryInterval)
			wait = c.upgradeTiming.retryInterval
		}
	}
}

// logUpgradeReason reports why the direct-UDP path isn't up. An empty reason
// means the caller has nothing worth reporting (e.g. the connection is
// closing) and logs nothing. A reason identical to *lastReason is a
// steady-state condition already announced, so it repeats only at Debug;
// anything new -- the first occurrence, or a change from one cause to
// another -- gets Warn, the CLI's default level, so it's visible without -v.
// That promotion is skipped when the session started on WebSocket because
// the caller passed --websocket: failing to escape a transport the user
// deliberately chose isn't news, so it stays at Debug regardless.
func (c *Connection) logUpgradeReason(lastReason *string, reason, msg string, extra ...any) {
	if reason == "" {
		return
	}
	args := append([]any{"server", c.DisplayName(), "reason", reason}, extra...)
	if reason != *lastReason && !c.options.UseWebSocket {
		c.log.Warn(msg, args...)
		*lastReason = reason
	} else {
		c.log.Debug(msg, args...)
		*lastReason = reason
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

// pathHealthy reports whether candidate -- either rung's confirmed address --
// is both (a) the peer's actual current endpoint and (b) reachable right
// now. It is reused unmodified for both the UDP-relay rung and the full
// direct-escape rung: checking only probeDirectPath is not enough for
// either, since WireGuard's own peer roaming is symmetric, so a single
// authenticated packet arriving over the WebSocket fallback -- entirely
// possible while every transport stays live on the same device -- silently
// moves the peer's endpoint back to WebSocket, after which probeDirectPath
// would keep reporting success (just routed over WS instead) with nothing
// else noticing the quiet fallback. The active probe additionally catches a
// failure mode unique to the relay rung -- the relay's own session for
// candidate silently expiring (idle timeout, relay restart) -- since the
// shared relay address itself never changes even when the session behind it
// is gone, so PeerEndpoint alone can't detect that.
func (c *Connection) pathHealthy(candidate string) (healthy bool, reason string) {
	stack, serverPub, ok := c.stackAndServerKey()
	if !ok {
		return false, "" // connection is closing; nothing to report
	}
	ep, found, err := stack.PeerEndpoint(serverPub)
	if err != nil || !found {
		return false, "WireGuard peer endpoint is no longer available"
	}
	if ep != candidate {
		return false, fmt.Sprintf("a WebSocket packet roamed the WireGuard peer back to %s", ep)
	}
	if !c.probeDirectPath() {
		return false, fmt.Sprintf("candidate %s stopped responding within %s", candidate, c.upgradeTiming.probeTimeout)
	}
	return true, ""
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
//
// The second return value explains a "" candidate: it's empty only when
// there's genuinely nothing to report (the connection is closing
// mid-attempt), and otherwise names the specific stage that failed so
// directUpgradeLoop can tell the user why the session is staying on
// WebSocket -- distinguishing, in particular, "the server doesn't offer this
// at all" (the common, permanent case for a relay-only deployment) from a
// transient NAT/network condition worth retrying.
//
// fallback is the endpoint a failed attempt re-seeds the peer to, mid-way
// through: wstransport.WSSentinel when called from the WebSocket rung, but
// the still-warm UDP-relay candidate when this is an opportunistic
// escalation attempt from that rung -- a failed escalation must not drop the
// connection all the way back to WebSocket when the relay rung underneath it
// was never unhealthy to begin with.
func (c *Connection) tryDirectUpgrade(bind *wstransport.FilterBind, fallback string) (candidate string, reason string) {
	first, err := c.postPunch("")
	if err != nil {
		return "", fmt.Sprintf("could not reach the relay's punch endpoint: %v", err)
	}
	reflectAddr, _ := directCandidateForReflector(first, "")
	if reflectAddr == "" {
		return "", "server has not enabled direct UDP upgrade support"
	}

	selfAddr, err := selfReflect(bind, reflectAddr, c.upgradeTiming.reflectTimeout)
	if err != nil {
		return "", fmt.Sprintf("NAT self-reflection via the relay failed: %v", err)
	}

	second, err := c.postPunch(selfAddr)
	if err != nil {
		return "", fmt.Sprintf("could not reach the relay's punch endpoint: %v", err)
	}
	_, serverAddr := directCandidateForReflector(second, reflectAddr)
	if serverAddr == "" {
		return "", "server has not published a self-reflected candidate address yet"
	}

	stack, serverPub, ok := c.stackAndServerKey()
	if !ok {
		return "", "" // connection closed while this attempt was in flight
	}

	primeAddr(bind, serverAddr)
	if err := stack.UpdateEndpoint(serverPub, serverAddr); err != nil {
		return "", fmt.Sprintf("failed to seed the local WireGuard endpoint with candidate %s: %v", serverAddr, err)
	}
	if !c.probeDirectPath() {
		_ = stack.UpdateEndpoint(serverPub, fallback)
		return "", fmt.Sprintf("candidate %s did not respond within %s (likely blocked by NAT or a firewall)", serverAddr, c.upgradeTiming.probeTimeout)
	}
	if ep, found, err := stack.PeerEndpoint(serverPub); err != nil || !found || ep != serverAddr {
		_ = stack.UpdateEndpoint(serverPub, fallback)
		return "", fmt.Sprintf("candidate %s answered but a WebSocket packet already roamed the WireGuard peer back", serverAddr)
	}
	c.log.Info("upgraded to direct UDP", "server", c.DisplayName(), "candidate", serverAddr)
	c.transport.Store(uint32(transportUDPRelayReflector))
	return serverAddr, ""
}

// directCandidateForReflector selects a matching active-active candidate,
// falling back to the legacy scalar fields for servers predating the pool
// extension. A supplied reflector is preferred to avoid mixing mappings from
// destination-dependent NATs.
func directCandidateForReflector(resp protocol.PunchResponse, reflector string) (string, string) {
	for _, candidate := range resp.Candidates {
		if reflector == "" || candidate.RelayReflectAddr == reflector {
			return candidate.RelayReflectAddr, candidate.ServerAddr
		}
	}
	return resp.RelayReflectAddr, resp.ServerAddr
}

// setEndpoint re-seeds the peer's endpoint to addr: wstransport.WSSentinel to
// fall back to the WebSocket fallback, or a UDP-relay/direct candidate
// address to (re)ascend to that rung. Whichever transport is already live
// underneath is never closed or redialed -- Hybrid keeps every rung's
// transport alive throughout the connection's life -- so this always takes
// effect on the very next packet with no reconnect involved. Except that
// UpdateEndpoint itself can fail if the target transport is not currently
// live (Bind.ParseEndpoint errors when its WebSocket peer isn't connected;
// see wstransport/bind.go), in which case the caller must keep retrying
// rather than silently accepting the peer staying pointed at a dead address.
// A closed Connection is reported as success, not a failure to retry:
// directUpgradeLoop's own c.stop check will end the loop on its next tick.
func (c *Connection) setEndpoint(addr string) error {
	stack, serverPub, ok := c.stackAndServerKey()
	if !ok {
		return nil
	}
	return stack.UpdateEndpoint(serverPub, addr)
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

// udpRelayUnavailableReason marks tryUDPRelayUpgrade's "the relay does not
// offer this tier at all" outcome, distinct from every other failure reason
// it can return. It is the one reason directUpgradeLoop treats as licensing
// an immediate, same-tick fallthrough to the existing full-escape attempt
// rather than simply retrying this rung next cycle -- without that
// distinction, a relay that offers listen.reflect but not listen.udp_relay
// (every relay running before this tier existed) would silently lose the
// full-escape feature, since the loop would otherwise wait forever on a rung
// that can never become available for it.
const udpRelayUnavailableReason = "relay does not offer a UDP relay tier"

// tryUDPRelayUpgrade runs one attempt to bind onto the relay's UDP-relay
// forwarding tier: request a session, bind this leg, and confirm end to end
// -- the same two-check shape tryDirectUpgrade uses (PeerEndpoint plus an
// active probe), for the same reason: probeDirectPath alone can't tell this
// rung apart from a WebSocket packet having silently roamed the peer back.
// It returns the relay's shared client-facing address as candidate and the
// session token on success; the caller keeps resending FrameRelayBind with
// that token as a keepalive for as long as this rung stays active (see
// udpRelayKeepaliveLoop). reason explains a "" candidate, and is
// udpRelayUnavailableReason specifically when the relay offers no such tier
// at all.
func (c *Connection) tryUDPRelayUpgrade(bind *wstransport.FilterBind) (candidate, token, reason string) {
	resp, err := c.postUDPRelay()
	if err != nil {
		return "", "", fmt.Sprintf("could not reach the relay's UDP-relay endpoint: %v", err)
	}
	if resp.RelayAddr == "" || resp.Token == "" {
		return "", "", udpRelayUnavailableReason
	}

	// Control is shared with priming pings, reflection replies, and any
	// earlier, already timed-out bind attempt -- see selfReflect's identical
	// reasoning for draining first.
	drainControl(bind)
	if err := bind.SendControl(wstransport.FrameRelayBind, []byte(resp.Token), resp.RelayAddr); err != nil {
		return "", "", fmt.Sprintf("failed to send UDP-relay bind to %s: %v", resp.RelayAddr, err)
	}
	// A FrameRelayBindAck only shortens detecting a bad/expired token; a
	// missing ack isn't fatal on its own, since the end-to-end probe below
	// is what actually confirms the path either way, exactly as it does for
	// the full escape.
	waitForBindAck(bind, c.upgradeTiming.reflectTimeout)

	stack, serverPub, ok := c.stackAndServerKey()
	if !ok {
		return "", "", "" // connection closed while this attempt was in flight
	}
	if err := stack.UpdateEndpoint(serverPub, resp.RelayAddr); err != nil {
		return "", "", fmt.Sprintf("failed to seed the local WireGuard endpoint with the relay's UDP-relay address %s: %v", resp.RelayAddr, err)
	}
	if !c.probeDirectPath() {
		_ = stack.UpdateEndpoint(serverPub, wstransport.WSSentinel)
		return "", "", fmt.Sprintf("UDP relay path via %s did not respond within %s", resp.RelayAddr, c.upgradeTiming.probeTimeout)
	}
	if ep, found, err := stack.PeerEndpoint(serverPub); err != nil || !found || ep != resp.RelayAddr {
		_ = stack.UpdateEndpoint(serverPub, wstransport.WSSentinel)
		return "", "", fmt.Sprintf("UDP relay path via %s answered but a WebSocket packet already roamed the WireGuard peer back", resp.RelayAddr)
	}
	c.log.Info("upgraded to UDP via relay", "server", c.DisplayName(), "relay_addr", resp.RelayAddr)
	c.transport.Store(uint32(transportUDPRelay))
	return resp.RelayAddr, resp.Token, ""
}

// udpRelayKeepaliveLoop resends FrameRelayBind to addr with token every
// relayBindKeepalive, until stop is closed. This is the client's half of the
// UDP-relay session's keepalive; it both refreshes this leg's own NAT
// mapping and refreshes the relay's idle timeout for the session, and is
// unrelated to whatever WireGuard's own persistent-keepalive is (or isn't)
// configured to do. A send failure is not itself fatal here -- the next
// health check (pathHealthy, via probeDirectPath) is what actually decides
// whether the rung is still usable.
func (c *Connection) udpRelayKeepaliveLoop(bind *wstransport.FilterBind, token, addr string, stop <-chan struct{}) {
	ticker := time.NewTicker(c.upgradeTiming.relayBindKeepalive)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := bind.SendControl(wstransport.FrameRelayBind, []byte(token), addr); err != nil {
				c.log.Debug("udp relay: bind keepalive send failed", "addr", addr, "error", err)
			}
		case <-stop:
			return
		}
	}
}

// waitForBindAck waits up to timeout for a FrameRelayBindAck on bind's
// control channel, discarding any other control frame it sees in the
// meantime (a priming ping or reflection reply arriving at the same time).
// It never reports an error: a missing ack is not fatal to the caller, which
// falls through to its own end-to-end probe either way.
func waitForBindAck(bind *wstransport.FilterBind, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case cp := <-bind.Control():
			if cp.Type == wstransport.FrameRelayBindAck {
				return
			}
		case <-timer.C:
			return
		}
	}
}

// postUDPRelay requests a UDP-relay forwarding session from the server's
// /v1/udp-relay endpoint. A 404 (this server isn't relaying, or the relay it
// uses has no UDP-relay tier configured) is reported as a zero
// UDPRelayResponse with no error -- an expected, common steady state, not a
// failure worth logging on every retry, exactly like postPunch's treatment
// of its own 404.
func (c *Connection) postUDPRelay() (protocol.UDPRelayResponse, error) {
	c.mu.Lock()
	base, token := c.base, c.token
	c.mu.Unlock()
	b, _ := json.Marshal(protocol.UDPRelayRequest{})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/udp-relay", bytes.NewReader(b))
	if err != nil {
		return protocol.UDPRelayResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return protocol.UDPRelayResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return protocol.UDPRelayResponse{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return protocol.UDPRelayResponse{}, fmt.Errorf("udp-relay request failed: %s", resp.Status)
	}
	var out protocol.UDPRelayResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return protocol.UDPRelayResponse{}, err
	}
	return out, nil
}
