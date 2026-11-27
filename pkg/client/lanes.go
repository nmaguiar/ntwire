package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

const childSetupTimeout = 24 * time.Second

var errLaneDraining = errors.New("child lane is draining active flows")
var errChildUnavailable = errors.New("child lane is unavailable")

// flowLane owns one flow's admission. Its stack stays fixed until release,
// even when the parent gains another lane or a carrier reconnects.
type flowLane struct {
	owner   *Connection
	stack   *wgnet.Stack
	network *connectionNetwork
}

func (c *Connection) acquireFlowLaneLocked() flowLane {
	if c.closed || c.Stack == nil {
		return flowLane{}
	}
	anchor := c.network
	if anchor == nil || anchor.response.Adaptive == nil || anchor.response.Adaptive.MaxLanes < 2 {
		return flowLane{stack: c.Stack, network: anchor}
	}
	best := anchor
	ready := anchor.adaptive.laneReady(true)
	for _, child := range c.childLanes {
		if child.draining || (ready && (child.activeFlows > best.activeFlows ||
			(child.activeFlows == best.activeFlows && (best == anchor ||
				child.response.Adaptive.LaneID >= best.response.Adaptive.LaneID)))) {
			continue
		}
		if child.adaptive.laneReady(true) {
			best, ready = child, true
		}
	}
	best.activeFlows++
	return flowLane{owner: c, stack: best.stack, network: best}
}

func (a *adaptiveCarrierClient) laneReady(forAdmission bool) bool {
	path, _, _ := a.bind.LaneState(a.lane)
	if path == "" || !a.bind.HasQualifiedPath(a.lane, path) {
		return false
	}
	switch {
	case path == protocol.CarrierWSS:
		pressure, connected := a.ws.PeerQueuePressure("remote")
		return connected && (!forAdmission || !pressure)
	case protocol.IsNativeUDPCarrier(path):
		return a.nativeUDPUsable(path)
	case path == protocol.CarrierQUIC:
		return a.quic != nil
	case path == protocol.CarrierHTTP3:
		return a.http3 != nil
	case path == protocol.CarrierHTTP2:
		return a.http2 != nil
	default:
		return a.relay != nil && a.relay.path(path).id == path
	}
}

func (c *Connection) acquireFlowLaneFor(anchor *wgnet.Stack) flowLane {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Stack != anchor {
		return flowLane{}
	}
	return c.acquireFlowLaneLocked()
}

func (l flowLane) release() {
	if l.owner != nil {
		l.owner.mu.Lock()
		l.network.activeFlows--
		l.owner.mu.Unlock()
	}
}

func (l flowLane) traffic() *adaptiveTraffic {
	if l.network != nil && l.network.response.Adaptive != nil && l.network.response.Adaptive.Performance {
		return &l.network.adaptive.traffic
	}
	return nil
}

func (l flowLane) trackLocal(conn net.Conn) net.Conn {
	if l.network != nil && l.network.response.Adaptive != nil && l.network.response.Adaptive.RelayPerformance {
		return trackAdaptiveTraffic(conn, &l.network.adaptive.localTraffic)
	}
	return conn
}

func (l flowLane) dialOwned(ctx context.Context, network, address string) (net.Conn, error) {
	if l.stack == nil {
		return nil, net.ErrClosed
	}
	socket, err := l.stack.DialContext(ctx, network, address)
	if err != nil {
		l.release()
		return nil, err
	}
	if l.owner == nil {
		return socket, nil
	}
	return &laneConn{Conn: socket, lane: l}, nil
}

type laneConn struct {
	net.Conn
	lane flowLane
	once sync.Once
}

func (c *laneConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.lane.release)
	return err
}

func (c *laneConn) CloseWrite() error { return localproxy.CloseWrite(c.Conn) }

type LaneStatus struct {
	Anchor        bool   `json:"anchor,omitempty"`
	Carrier       string `json:"carrier,omitempty"`
	State         string `json:"state"`
	ActiveFlows   int    `json:"active_flows"`
	RelayMember   string `json:"relay_member,omitempty"`
	RelayStandbys int    `json:"relay_standbys,omitempty"`
	RelayDecision string `json:"relay_decision,omitempty"`
}

func (c *Connection) laneDiagnosticsLocked() ([]LaneStatus, *LaneScalingStatus) {
	lanes := c.laneStatusLocked()
	if len(lanes) != 0 && c.network.laneScaling.State != "" {
		scaling := c.network.laneScaling
		return lanes, &scaling
	}
	return lanes, nil
}

func (c *Connection) laneStatusLocked() []LaneStatus {
	n := c.network
	if c.closed || n == nil || n.response.Adaptive == nil ||
		(n.response.Adaptive.MaxLanes < 2 && !n.response.Adaptive.RelayPerformance) {
		return nil
	}
	snapshot := func(lane *connectionNetwork) LaneStatus {
		a := lane.adaptive
		primary, _, _ := a.bind.LaneState(a.lane)
		state := "ready"
		if lane.draining {
			state = "draining"
		} else if !a.laneReady(false) {
			state = "recovering"
		}
		out := LaneStatus{Anchor: lane == n, Carrier: primary, State: state, ActiveFlows: lane.activeFlows}
		if protocol.ValidCarrierID(primary) {
			out.Carrier = protocol.CarrierRelayUDP
		}
		if a.relay != nil {
			for _, path := range a.relay.snapshot() {
				if path.id == "" || !a.bind.HasQualifiedPath(a.lane, path.id) {
					continue
				}
				if path.id == primary {
					out.Carrier, out.RelayMember = protocol.CarrierRelayUDP, path.member
				} else if a.relay.performance {
					out.RelayStandbys++
				}
			}
			if a.relay.performance {
				out.RelayDecision = a.measurements.trialReason()
			}
		}
		return out
	}
	out := make([]LaneStatus, 0, 1+len(c.childLanes))
	out = append(out, snapshot(n))
	for _, id := range slices.Sorted(maps.Keys(c.childLanes)) {
		out = append(out, snapshot(c.childLanes[id]))
	}
	return out
}

func newLaneRequest(generation uint64, key string) ([]byte, error) {
	var requestID protocol.CarrierID
	if _, err := rand.Read(requestID[:]); err != nil {
		return nil, err
	}
	return json.Marshal(protocol.LaneRequest{RequestID: base64.RawURLEncoding.EncodeToString(requestID[:]),
		Generation: generation, WireGuardPublicKey: key})
}

// openAdaptiveLane provisions a standalone stack on the current parent.
// It owns no local listeners. Only qualified lanes join the connection.
func (c *Connection) openAdaptiveLane(ctx context.Context) (*connectionNetwork, error) {
	return c.openAdaptiveLaneFor(ctx, nil, 0, 0)
}

func (c *Connection) openAdaptiveLaneFor(ctx context.Context, expected *connectionNetwork, generation, roster uint64) (*connectionNetwork, error) {
	c.networkMu.Lock()
	defer c.networkMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	n, parent := c.network, c.Response
	if c.closed || n == nil || (expected != nil && n != expected) || n.adaptive == nil ||
		parent.Adaptive == nil || len(c.childLanes)+1 >= parent.Adaptive.MaxLanes ||
		(expected != nil && (parent.Adaptive.AuthGeneration != generation || c.laneRosterRevision != roster)) {
		c.mu.Unlock()
		return nil, errors.New("no child lane capacity for this connection")
	}
	c.mu.Unlock()
	a := n.adaptive
	key, err := wgnet.GenerateKey()
	if err != nil {
		return nil, err
	}
	body, err := newLaneRequest(parent.Adaptive.AuthGeneration, key.Public)
	if err != nil {
		return nil, err
	}
	_, _, expires := a.credentials()
	deadline := time.Now().Add(childSetupTimeout)
	if renewalHeadroom := expires.Add(-2 * time.Second); renewalHeadroom.Before(deadline) {
		deadline = renewalHeadroom
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var descriptor protocol.LaneDescriptor
	origin := a.base + "/v1/session/lanes"
	attempt, cancelAttempt := context.WithTimeout(ctx, 3*time.Second)
	err = a.controlRequest(attempt, http.MethodPost, origin, parent.Token, body, &descriptor)
	cancelAttempt()
	if err != nil {
		// Retry a lost response with the same request ID. An explicit
		// response, including a denial or quota decision, is terminal.
		var status *carrierHTTPError
		if errors.As(err, &status) || ctx.Err() != nil {
			return nil, err
		}
		if err := a.controlRequest(ctx, http.MethodPost, origin, parent.Token, body, &descriptor); err != nil {
			return nil, err
		}
	}
	if !validChildDescriptor(parent, descriptor) {
		return nil, errors.New("invalid child lane descriptor")
	}
	laneID := descriptor.Adaptive.LaneID
	c.mu.Lock()
	_, duplicateID := c.childLanes[laneID]
	c.mu.Unlock()
	if duplicateID {
		return nil, errors.New("server reused a child lane ID")
	}
	published := false
	defer func() {
		if !published {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = deleteAdaptiveLane(cleanup, a, laneID)
		}
	}()
	childAuth := parent
	childAuth.Adaptive = &descriptor.Adaptive
	childAuth.TransportCapabilities = descriptor.Adaptive.Capabilities()
	childAuth.RequiredTransportCapabilities = nil
	childAuth.TunnelIP = descriptor.TunnelIP
	childAuth.TTLSeconds = descriptor.TTLSeconds
	child, err := newConnectionNetwork(ctx, childAuth, key.Private, a.base, a.control, c.options)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !published {
			_ = child.stack.Close()
		}
	}()
	if err := qualifyChildPeer(ctx, child, a, parent); err != nil {
		return nil, err
	}
	if err := c.followParentCarrier(ctx, child.adaptive, a); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.closed || c.network != n || c.token != parent.Token {
		return nil, errors.New("parent connection changed during lane setup")
	}
	if c.childLanes == nil {
		c.childLanes = make(map[string]*connectionNetwork)
	}
	for _, existing := range c.childLanes {
		if existing.clientIP == child.clientIP {
			return nil, errors.New("server reused a child lane address")
		}
	}
	c.childLanes[laneID] = child
	c.laneRosterRevision++
	if child.adaptive.udpLost != nil || child.adaptive.wssLost != nil {
		lifetime, stop := context.WithCancel(context.Background())
		child.stopCarrierHealth = stop
		go c.maintainChildCarrierHealth(lifetime, child, a)
		child.adaptive.ws.RetryDeferredDial()
	}
	published = true
	return child, nil
}

func validChildDescriptor(parent protocol.AuthResponse, child protocol.LaneDescriptor) bool {
	info := child.Adaptive
	ip, err := netip.ParseAddr(child.TunnelIP)
	return parent.Adaptive != nil && err == nil && ip.IsGlobalUnicast() && ip.String() == child.TunnelIP &&
		ip.String() != parent.TunnelIP && ip.String() != parent.ServerTunnelIP &&
		child.ServerTunnelIP == parent.ServerTunnelIP && child.ServerPublicKey == parent.ServerPublicKey && child.TTLSeconds > 0 &&
		info.LaneID != parent.Adaptive.LaneID && protocol.ValidCarrierID(info.LaneID) &&
		info == parent.Adaptive.ChildSession(info.LaneID)
}

// A healthy datagram parent is evidence about reachability, not proof
// for another peer. Give the child its own short qualification attempt.
func (c *Connection) followParentCarrier(ctx context.Context, a, parent *adaptiveCarrierClient) error {
	preferred, _, _ := parent.bind.LaneState(parent.lane)
	active, _, _ := a.bind.LaneState(a.lane)
	if active != protocol.CarrierWSS || !parent.bind.HasQualifiedPath(parent.lane, preferred) {
		return nil
	}
	var err error
	switch {
	case protocol.IsNativeUDPCarrier(preferred) && a.info.UDPSelect && parent.nativeUDPUsable(preferred):
		err = a.qualifyUDP(ctx, preferred)
	case preferred == protocol.CarrierQUIC && a.quic != nil:
		err = a.qualifyQUIC(ctx, active)
	default:
		return nil
	}
	if err != nil {
		if carrierControlDenied(err) {
			return err
		}
		c.log.Debug("child carrier qualification kept WebSocket", "carrier", preferred, "error", err)
		return nil // The child still has its confirmed WSS path.
	}
	// A timed-out commit could have switched the server. Never admit a
	// child whose selected path could not be reconciled.
	return a.selectPrimaryFrom(ctx, preferred, active)
}

func qualifyChildPeer(ctx context.Context, child *connectionNetwork, a *adaptiveCarrierClient, parent protocol.AuthResponse) error {
	if err := child.stack.SetPeerKeepalive(parent.ServerPublicKey, 1); err != nil {
		return err
	}
	defer child.stack.SetPeerKeepalive(parent.ServerPublicKey, 0)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			last, ok, err := child.stack.LastHandshake(parent.ServerPublicKey)
			if err != nil || !ok || last.Unix() <= 0 {
				continue
			}
			var lanes protocol.LaneList
			if err := a.controlRequest(ctx, http.MethodGet, a.base+"/v1/session/lanes", parent.Token, nil, &lanes); err != nil {
				return err
			}
			if lanes.ParentID != parent.Adaptive.ParentID || lanes.Generation != parent.Adaptive.AuthGeneration || len(lanes.Lanes) > parent.Adaptive.MaxLanes {
				return errors.New("parent authorization changed during child qualification")
			}
			for _, lane := range lanes.Lanes {
				if lane.Adaptive.LaneID == child.response.Adaptive.LaneID && lane.State == "ready" {
					return nil
				}
			}
		}
	}
}

// retireAdaptiveLane fences admission before reporting that a lane is busy.
// Retrying after its last lease releases removes the peer.
func (c *Connection) retireAdaptiveLane(ctx context.Context, id string) error {
	return c.retireAdaptiveLaneFor(ctx, nil, id)
}

func (c *Connection) retireAdaptiveLaneFor(ctx context.Context, expected *connectionNetwork, id string) error {
	c.networkMu.Lock()
	defer c.networkMu.Unlock()
	c.mu.Lock()
	child, n := c.childLanes[id], c.network
	if child == nil || n == nil || (expected != nil && n != expected) || n.adaptive == nil || c.closed {
		c.mu.Unlock()
		return errChildUnavailable
	}
	if !child.draining {
		child.draining = true
		c.laneDrainRevision++
	}
	if child.activeFlows != 0 {
		c.mu.Unlock()
		return errLaneDraining
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := deleteAdaptiveLane(ctx, n.adaptive, id); err != nil {
		var status *carrierHTTPError
		if !errors.As(err, &status) || status.status != http.StatusNotFound {
			return err
		}
	}
	c.mu.Lock()
	owned := c.childLanes[id] == child
	if owned {
		delete(c.childLanes, id)
		c.laneRosterRevision++
	}
	c.mu.Unlock()
	if owned {
		return child.closeChild()
	}
	return nil
}

func (n *connectionNetwork) closeChild() error {
	if n.stopCarrierHealth != nil {
		n.stopCarrierHealth()
	}
	return n.stack.Close()
}

func deleteAdaptiveLane(ctx context.Context, a *adaptiveCarrierClient, id string) error {
	info, bearer, _ := a.credentials()
	body, err := newLaneRequest(info.AuthGeneration, "")
	if err != nil {
		return err
	}
	return a.controlRequest(ctx, http.MethodDelete, a.base+"/v1/session/lanes/"+id, bearer, body, nil)
}

func (a *adaptiveCarrierClient) renewChild(parent protocol.AuthResponse) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.info.AuthGeneration = parent.Adaptive.AuthGeneration
	if a.info.RelayPerformance {
		a.measurements.renew(a.info.AuthGeneration, false)
	}
	a.wssAttach = protocol.CarrierAttachRequest{}
	a.token = parent.Token
	a.expires = time.Now().Add(time.Duration(parent.TTLSeconds) * time.Second)
	a.renewActivePathsLocked()
}
