package client

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/ipfamily"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	relayClientKeepalive = 5 * time.Second
	relayClientRetry     = time.Second
)

type adaptiveRelayPath struct {
	id, bindToken string
	member        string
	address       netip.AddrPort
	endpoint      conn.Endpoint
	expires       time.Time
	rtt           time.Duration
}

type adaptiveRelayClient struct {
	socket      *wstransport.FilterBind
	ipVersion   string
	performance bool
	bindMu      sync.Mutex
	qualifyMu   sync.Mutex

	mu           sync.Mutex
	probe        *adaptiveUDPClient
	paths        [2]adaptiveRelayPath
	catalogIndex int
	observation  relayObservation // owned by the parent's worker
}

func newAdaptiveRelay(ipVersion string, performance bool) *adaptiveRelayClient {
	r := &adaptiveRelayClient{ipVersion: ipVersion, performance: performance,
		socket: wstransport.NewFilterBind(ipfamily.New(wstransport.NewProbeUDPBind(), ipVersion))}
	r.socket.SetRawControlHandler(func(frame []byte, ep conn.Endpoint) bool {
		if !protocol.IsCarrierProof(frame) {
			return false
		}
		r.mu.Lock()
		active := r.probe
		r.mu.Unlock()
		if active != nil {
			active.receive(frame, ep)
		}
		return true
	})
	return r
}

func (r *adaptiveRelayClient) current() adaptiveRelayPath {
	for _, path := range r.snapshot() {
		if path.id != "" {
			return path
		}
	}
	return adaptiveRelayPath{}
}

func (r *adaptiveRelayClient) snapshot() [2]adaptiveRelayPath {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.paths
}

func (r *adaptiveRelayClient) path(id string) adaptiveRelayPath {
	for _, path := range r.snapshot() {
		if path.id == id {
			return path
		}
	}
	return adaptiveRelayPath{}
}

func (a *adaptiveCarrierClient) qualifiedRelayStandby(exclude string) string {
	if a.relay != nil {
		for _, path := range a.relay.snapshot() {
			if path.id != "" && path.id != exclude && a.bind.HasQualifiedPath(a.lane, path.id) {
				return path.id
			}
		}
	}
	return ""
}

func (r *adaptiveRelayClient) chooseCandidate(info protocol.AdaptiveSession, catalog protocol.RelayCandidateCatalog) (candidate, member string, err error) {
	count := len(catalog.Candidates)
	if catalog.LaneID != info.LaneID || catalog.AuthGeneration != info.AuthGeneration || catalog.ExpiresInMS <= 0 ||
		catalog.ExpiresInMS > 15000 || count == 0 || count > protocol.MaxRelayCandidates ||
		(r.performance && len(catalog.Members) != count) {
		return "", "", errors.New("no authorized adaptive relay candidates")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for range count {
		index := r.catalogIndex % count
		r.catalogIndex = (index + 1) % count
		if !protocol.ValidCarrierID(catalog.Candidates[index]) {
			return "", "", errors.New("invalid relay candidate identifier")
		}
		if !r.performance {
			return catalog.Candidates[index], "", nil
		}
		member := catalog.Members[index]
		if !protocol.ValidCarrierID(member) {
			return "", "", errors.New("invalid relay member identifier")
		}
		if member != r.paths[0].member && member != r.paths[1].member {
			return catalog.Candidates[index], member, nil
		}
	}
	return "", "", errors.New("authorized relays already have allocations on this lane")
}

func (a *adaptiveCarrierClient) qualifyRelay(ctx context.Context) error {
	r := a.relay
	r.qualifyMu.Lock()
	defer r.qualifyMu.Unlock()
	info, bearer, expires := a.credentials()
	origin := a.base + "/v1/transport/lanes/" + info.LaneID
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	_, localEpoch, _ := a.bind.LaneState(a.lane)
	state, err := a.readSelection(ctx, origin, info, bearer)
	if err != nil {
		return err
	}
	var catalog protocol.RelayCandidateCatalog
	if err := a.controlRequest(ctx, http.MethodGet, origin+"/relay-candidates", bearer, nil, &catalog); err != nil {
		return err
	}
	candidate, member, err := r.chooseCandidate(info, catalog)
	if err != nil {
		return err
	}
	id, err := newCarrierRequestID()
	if err != nil {
		return err
	}
	body, err := json.Marshal(protocol.CarrierAttachRequest{RequestID: id, Candidate: candidate,
		Generation: info.AuthGeneration, ExpectedEpoch: state.PathEpoch})
	if err != nil {
		return err
	}
	var offer protocol.CarrierRelayUDPOffer
	if err := a.controlRequest(ctx, http.MethodPost, origin+"/relay/prepare", bearer, body, &offer); err != nil {
		return err
	}
	path, scope, key, err := r.validateOffer(info, state.PathEpoch, offer)
	if err != nil {
		return err
	}
	path.member = member
	port, open := a.bind.CarrierPort(protocol.CarrierRelayUDP)
	if !open || port == 0 {
		return errors.New("adaptive relay UDP socket is unavailable")
	}
	if err := r.bindRelay(ctx, path, time.Second); err != nil {
		return err
	}
	probe := &adaptiveUDPClient{socket: r.socket, remote: path.address, peer: path.endpoint}
	r.mu.Lock()
	r.probe = probe
	r.mu.Unlock()
	path.rtt, err = probe.exchange(ctx, scope, key, port, uint16(offer.DatagramMax))
	r.mu.Lock()
	r.probe = nil
	r.mu.Unlock()
	if err != nil {
		return err
	}
	status, until, err := a.completeUDP(ctx, origin+"/relay/qualify", bearer, body)
	if err != nil {
		return err
	}
	if status.Candidate != path.id || status.DatagramMax != offer.DatagramMax || status.ExpiresInMS <= 0 || status.ExpiresInMS > 30000 {
		return errors.New("invalid adaptive relay qualification")
	}
	path.expires = until
	if expires.Before(path.expires) {
		path.expires = expires
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != bearer || a.info.AuthGeneration != info.AuthGeneration {
		return errors.New("adaptive session changed during relay proof")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	slot := -1
	for i, existing := range r.paths {
		if existing.id == "" && (r.performance || i == 0) {
			slot = i
			break
		}
	}
	if slot < 0 {
		return errors.New("adaptive relay path budget exhausted")
	}
	if err := a.bind.InstallQualifiedPath(a.lane, localEpoch, wstransport.QualifiedPath{
		ID: path.id, Carrier: protocol.CarrierRelayUDP, Endpoint: path.endpoint,
		SendMax: status.DatagramMax, ReceiveMax: status.DatagramMax, ValidUntil: path.expires,
	}); err != nil {
		return err
	}
	r.paths[slot] = path
	return nil
}

func (r *adaptiveRelayClient) validateOffer(info protocol.AdaptiveSession, epoch uint64, offer protocol.CarrierRelayUDPOffer) (adaptiveRelayPath, protocol.CarrierProofScope, [32]byte, error) {
	var path adaptiveRelayPath
	var scope protocol.CarrierProofScope
	candidate, idOK := protocol.ParseCarrierID(offer.ID)
	key, keyOK := protocol.ParseCarrierTicket(offer.ProofKey)
	_, tokenOK := protocol.ParseCarrierTicket(offer.BindToken)
	address, addressOK := adaptiveUDPAddress(offer.RelayAddr)
	if !idOK || !keyOK || !tokenOK || !addressOK || !matchesIPVersion(address.String(), r.ipVersion) ||
		offer.DatagramMax != wstransport.MaxWireGuardDatagram(info.TunnelMTU) || offer.ExpiresInMS <= 0 || offer.ExpiresInMS > 15000 {
		return path, scope, key, errors.New("invalid adaptive relay offer")
	}
	ep, err := r.socket.ParseEndpoint(address.String())
	if err != nil {
		return path, scope, key, err
	}
	parent, _ := protocol.ParseCarrierID(info.ParentID)
	lane, _ := protocol.ParseCarrierID(info.LaneID)
	return adaptiveRelayPath{id: offer.ID, bindToken: offer.BindToken, address: address, endpoint: ep},
		protocol.CarrierProofScope{Parent: parent, Lane: lane, Candidate: candidate, AuthGeneration: info.AuthGeneration, PathEpoch: epoch}, key, nil
}

func (r *adaptiveRelayClient) bindRelay(ctx context.Context, path adaptiveRelayPath, timeout time.Duration) error {
	r.bindMu.Lock()
	defer r.bindMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.socket.SendControl(wstransport.FrameRelayBind, []byte(path.bindToken), path.address.String()); err != nil {
		return err
	}
	wait, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case <-wait.Done():
			return wait.Err()
		case packet := <-r.socket.Control():
			if packet.From == path.address && packet.Type == wstransport.FrameRelayBindAck && len(packet.Payload) == 0 {
				return nil
			}
		}
	}
}

// Caller owns a.mu, so renewal and a successful selection cannot republish
// an old allocation while retiring an inactive standby.
func (a *adaptiveCarrierClient) renewRelayPath() {
	if a.relay == nil {
		return
	}
	r := a.relay
	r.mu.Lock()
	defer r.mu.Unlock()
	active, _, _ := a.bind.LaneState(a.lane)
	for i, path := range r.paths {
		if path.id == "" {
			continue
		}
		if active == path.id {
			r.paths[i].expires = a.expires
			a.bind.ExtendPath(a.lane, path.id, a.expires)
		} else {
			a.bind.FailPath(a.lane, path.id, path.endpoint, protocol.CarrierWSS)
			r.paths[i] = adaptiveRelayPath{}
		}
	}
}

func (a *adaptiveCarrierClient) updateRelaySelection(previous, candidate string) {
	if a.relay == nil {
		return
	}
	r := a.relay
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, path := range r.paths {
		switch path.id {
		case "":
			continue
		case candidate:
			r.paths[i].expires = a.expires
		case previous:
			r.paths[i].expires = time.Now().Add(30 * time.Second)
			if a.expires.Before(r.paths[i].expires) {
				r.paths[i].expires = a.expires
			}
		default:
			continue
		}
		a.bind.ExtendPath(a.lane, path.id, r.paths[i].expires)
	}
}

type relayObservation struct {
	nextProbe   time.Time
	nextCheck   time.Time
	missedBinds int
	demand      uint64
	active      string
	failures    int
}

func (o *relayObservation) noteBinding(now time.Time, err error) {
	if err != nil {
		o.missedBinds++
		o.nextCheck = now.Add(relayClientRetry)
		return
	}
	o.missedBinds = 0
	o.nextCheck = now.Add(relayClientKeepalive)
}

// One worker per parent owns relay exploration for the anchor and its
// children, so concurrent lanes share one qualification budget.
func (c *Connection) maintainAdaptiveRelays(anchor *connectionNetwork, stop <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
		case <-c.stop:
		case <-ctx.Done():
		}
		cancel()
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var nextQualification time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			c.mu.Lock()
			if c.closed || c.network != anchor {
				c.mu.Unlock()
				return
			}
			type relayLane struct {
				adaptive *adaptiveCarrierClient
				draining bool
			}
			lanes := make([]relayLane, 0, len(c.childLanes)+1)
			lanes = append(lanes, relayLane{adaptive: anchor.adaptive})
			for _, child := range c.childLanes {
				lanes = append(lanes, relayLane{adaptive: child.adaptive, draining: child.draining})
			}
			c.mu.Unlock()
			for _, n := range lanes {
				a := n.adaptive
				if a.relay == nil {
					continue
				}
				o := &a.relay.observation
				demand := a.lane.DemandSequence()
				busy := demand != o.demand
				o.demand = demand
				if a.maintainRelayPaths(ctx, now, o) || n.draining || !busy || now.Before(o.nextProbe) || now.Before(nextQualification) {
					continue
				}
				err := anchor.adaptive.qualifyStandby(now, func() error { return a.qualifyRelay(ctx) })
				if errors.Is(err, errAdaptiveExplorationDeferred) {
					continue
				}
				if err == nil {
					c.log.Debug("adaptive UDP relay standby qualified")
				}
				nextQualification = time.Now().Add(time.Second)
				if a.relay.performance && err != nil {
					o.failures = min(o.failures+1, 2)
				} else {
					o.failures = 0
				}
				delay := adaptiveUDPRetry
				if a.relay.performance {
					delay = (delay << o.failures) + rand.N(3*time.Second)
				}
				o.nextProbe = time.Now().Add(delay)
			}
		}
	}
}

func (a *adaptiveCarrierClient) maintainRelayPaths(ctx context.Context, now time.Time, o *relayObservation) bool {
	var count int
	a.mu.Lock()
	a.relay.mu.Lock()
	for i, path := range a.relay.paths {
		if path.id == "" {
			continue
		}
		if now.Before(path.expires) {
			count++
		} else {
			a.bind.FailPath(a.lane, path.id, path.endpoint, protocol.CarrierWSS)
			a.relay.paths[i] = adaptiveRelayPath{}
		}
	}
	a.relay.mu.Unlock()
	a.mu.Unlock()
	primary, _, _ := a.bind.LaneState(a.lane)
	path := a.relay.path(primary)
	if o.active != primary || path.id == "" {
		o.active, o.nextCheck, o.missedBinds = primary, time.Time{}, 0
	}
	full := count >= 2 || (count == 1 && !a.relay.performance)
	if path.id == "" || now.Before(o.nextCheck) {
		return full
	}
	o.noteBinding(now, a.relay.bindRelay(ctx, path, 300*time.Millisecond))
	info, bearer, _ := a.credentials()
	check, cancel := context.WithTimeout(ctx, time.Second)
	state, err := a.readSelection(check, a.base+"/v1/transport/lanes/"+info.LaneID, info, bearer)
	cancel()
	if err == nil && state.Selected != path.id && state.Selected != "" &&
		(a.relay.performance || state.Selected == protocol.CarrierWSS) {
		if a.selectPrimaryFrom(ctx, state.Selected, path.id) == nil {
			o.missedBinds = 0
		}
	} else if o.missedBinds >= 3 {
		if !a.relay.performance {
			if a.selectPrimaryFrom(ctx, protocol.CarrierWSS, path.id) == nil {
				o.missedBinds = 0
			}
		} else if a.recoverAdaptiveUDP(ctx, path.id) {
			o.missedBinds = 0
		}
	}
	return full
}
