package wstransport

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

const (
	adaptiveEndpointPrefix = "lane:"
	maxLanePaths           = 8
	pathReceiveOverlap     = 2 * time.Second
)

var (
	ErrStalePathEpoch  = errors.New("stale path epoch")
	ErrPathUnqualified = errors.New("path is not qualified")
	ErrCarrierDatagram = errors.New("datagram exceeds carrier limit")
)

// AdaptiveBind presents stable logical WireGuard endpoints over exclusively
// owned, explicitly qualified carriers. Never share its receive sockets with
// native peers: accepting raw fallback endpoints here would permit roaming
// around the lane's selected path.
type AdaptiveBind struct {
	lifecycle sync.Mutex
	mu        sync.RWMutex
	carriers  []Carrier
	slots     map[string]int
	batch     int
	epoch     *adaptiveOpen
	lanes     map[string]*adaptiveLane
	routes    map[adaptiveSource]*adaptivePath
	maxLanes  int
	now       func() time.Time
}

type adaptiveOpen struct {
	done   chan struct{}
	ports  []uint16
	active []bool
	sends  sync.WaitGroup
}

type adaptiveLane struct {
	endpoint      *LaneEndpoint
	required      int
	revision      uint64
	paths         map[string]*adaptivePath
	primary       *adaptivePath
	previous      *adaptivePath
	overlapEnds   time.Time
	prepared      *receivePreparation
	switches      switchLog
	observeDemand bool
}

type receivePreparation struct {
	path  *adaptivePath
	epoch uint64
	until time.Time
}

// LaneEndpoint is a stable logical WireGuard endpoint and a local lifetime
// handle. A handle becomes invalid when the owning bind removes its lane.
type LaneEndpoint struct {
	id     string
	demand atomic.Uint64
}

// EnableLaneDemand tracks recent nonempty encrypted WireGuard transport
// sends for an explicitly opted-in lane.
func (b *AdaptiveBind) EnableLaneDemand(ep *LaneEndpoint) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if lane := b.laneFor(ep); lane != nil {
		lane.observeDemand = true
	}
}

// DemandSequence lets each observer detect activity since its own last sample.
func (e *LaneEndpoint) DemandSequence() uint64 {
	return e.demand.Load()
}

func (*LaneEndpoint) ClearSrc()           {}
func (*LaneEndpoint) SrcToString() string { return "" }
func (e *LaneEndpoint) DstToString() string {
	return adaptiveEndpointPrefix + e.id
}
func (e *LaneEndpoint) DstToBytes() []byte { return []byte(e.DstToString()) }
func (*LaneEndpoint) SrcIP() netip.Addr    { return netip.Addr{} }
func (*LaneEndpoint) DstIP() netip.Addr    { return netip.Addr{} }

type adaptiveSource struct {
	slot int
	key  carrierSource
}

type adaptivePath struct {
	lane   *adaptiveLane
	source adaptiveSource
	route  QualifiedPath
}

// NewAdaptiveBind takes exclusive ownership of the carrier binds. Every
// carrier must use its own conn.Bind, and the first supplies Open's port.
func NewAdaptiveBind(maxLanes int, carriers ...Carrier) (*AdaptiveBind, error) {
	if maxLanes < 1 || maxLanes > 65536 || len(carriers) == 0 || len(carriers) > maxLanePaths {
		return nil, fmt.Errorf("invalid adaptive bind capacity")
	}
	b := &AdaptiveBind{
		carriers: append([]Carrier(nil), carriers...),
		slots:    make(map[string]int, len(carriers)), lanes: make(map[string]*adaptiveLane),
		routes: make(map[adaptiveSource]*adaptivePath), maxLanes: maxLanes, now: time.Now,
	}
	for slot, c := range b.carriers {
		if !validCarrierID(c.Name) || c.Bind == nil || c.DatagramMax < 1 || c.DatagramMax > 65535 ||
			c.Bind.BatchSize() < 1 || c.Bind.BatchSize() > conn.IdealBatchSize || (slot == 0 && (c.ListenPort != 0 || c.Optional)) {
			return nil, fmt.Errorf("invalid adaptive carrier configuration")
		}
		if _, exists := b.slots[c.Name]; exists {
			return nil, fmt.Errorf("duplicate adaptive carrier name")
		}
		b.slots[c.Name] = slot
		b.batch = max(b.batch, c.Bind.BatchSize())
	}
	return b, nil
}

// RegisterLane creates a logical endpoint and records its fixed ciphertext
// MTU. Register it before configuring the WireGuard peer's endpoint.
func (b *AdaptiveBind) RegisterLane(id string, datagramMax int) (*LaneEndpoint, error) {
	if !validCarrierID(id) || datagramMax < 1 || datagramMax > 65535 {
		return nil, fmt.Errorf("invalid adaptive lane")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lanes[id] != nil || len(b.lanes) == b.maxLanes {
		return nil, fmt.Errorf("adaptive lane unavailable")
	}
	ep := &LaneEndpoint{id: id}
	b.lanes[id] = &adaptiveLane{endpoint: ep, required: datagramMax, paths: make(map[string]*adaptivePath)}
	return ep, nil
}

// laneFor looks up a handle while mu is held. Comparing its identity
// prevents a delayed controller from acting on a reused lane id.
func (b *AdaptiveBind) laneFor(ep *LaneEndpoint) *adaptiveLane {
	if ep == nil {
		return nil
	}
	lane := b.lanes[ep.id]
	if lane == nil || lane.endpoint != ep {
		return nil
	}
	return lane
}

// LaneState reports the active primary and current compare-and-swap epoch.
func (b *AdaptiveBind) LaneState(ep *LaneEndpoint) (primary string, epoch uint64, ok bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	lane := b.laneFor(ep)
	if lane == nil {
		return "", 0, false
	}
	if lane.primary != nil && b.now().Before(lane.primary.route.ValidUntil) {
		primary = lane.primary.route.ID
	}
	return primary, lane.revision, true
}

// HasQualifiedPath checks current lane membership and expiry without
// allocating a diagnostics snapshot.
func (b *AdaptiveBind) HasQualifiedPath(ep *LaneEndpoint, candidate string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	lane := b.laneFor(ep)
	if lane == nil {
		return false
	}
	path := lane.paths[candidate]
	return path != nil && b.now().Before(path.route.ValidUntil)
}

// QualifiedCarrier reports the usable ciphertext size in each direction
// for a currently authorized path.
type QualifiedCarrier struct {
	Name       string        `json:"name"`
	Carrier    string        `json:"carrier"`
	Primary    bool          `json:"primary"`
	SendMax    int           `json:"send_max"`
	ReceiveMax int           `json:"receive_max"`
	RTT        time.Duration `json:"carrier_rtt,omitempty"`
}

// LaneDetails snapshots authorized paths and committed changes together.
func (b *AdaptiveBind) LaneDetails(ep *LaneEndpoint) (primary string, epoch uint64, paths []QualifiedCarrier, events []SwitchEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	lane := b.laneFor(ep)
	if lane == nil {
		return "", 0, nil, nil
	}
	now := b.now()
	paths = make([]QualifiedCarrier, 0, len(lane.paths))
	for _, p := range lane.paths {
		path := p.route
		if !now.Before(path.ValidUntil) {
			continue
		}
		if p == lane.primary {
			primary = path.ID
		}
		paths = append(paths, QualifiedCarrier{
			Name: path.ID, Carrier: path.Carrier, Primary: p == lane.primary,
			SendMax: path.SendMax, ReceiveMax: path.ReceiveMax,
		})
	}
	slices.SortFunc(paths, func(a, b QualifiedCarrier) int { return strings.Compare(a.Name, b.Name) })
	return primary, lane.revision, paths, lane.switches.snapshot()
}

func (l *adaptiveLane) recordSwitch(now time.Time, previous *adaptivePath, reason SwitchReason) {
	event := SwitchEvent{At: now, Reason: reason}
	if previous != nil {
		event.From = previous.route.ID
	}
	if l.primary != nil {
		event.To = l.primary.route.ID
	}
	l.switches.record(event)
}

// RemoveLane removes all of its source bindings and invalidates its endpoint,
// including when a new lane later uses the same id.
func (b *AdaptiveBind) RemoveLane(ep *LaneEndpoint) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if lane := b.laneFor(ep); lane != nil {
		for _, p := range lane.paths {
			delete(b.routes, p.source)
		}
		delete(b.lanes, ep.id)
	}
}

func (b *AdaptiveBind) InstallQualifiedPath(ep *LaneEndpoint, epoch uint64, route QualifiedPath) error {
	return b.installPath(ep, epoch, route, false)
}

// AttachStream installs a proven WSS connection or replaces its old
// incarnation. A different active carrier retains its primary selection.
func (b *AdaptiveBind) AttachStream(ep *LaneEndpoint, epoch uint64, route QualifiedPath) error {
	source, ok := getCarrierSource(route.Endpoint)
	if !ok || source.instance == nil {
		return ErrPathUnqualified
	}
	return b.installPath(ep, epoch, route, true)
}

func (b *AdaptiveBind) installPath(ep *LaneEndpoint, epoch uint64, route QualifiedPath, stream bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.epoch == nil {
		return net.ErrClosed
	}
	lane := b.laneFor(ep)
	if lane == nil || lane.revision != epoch {
		return ErrStalePathEpoch
	}
	slot, found := b.slots[route.Carrier]
	src, valid := getCarrierSource(route.Endpoint)
	now := b.now()
	if !found || !b.epoch.active[slot] || !valid || !validCarrierID(route.ID) || !now.Before(route.ValidUntil) {
		return ErrPathUnqualified
	}
	if ep, ok := route.Endpoint.(endpoint); ok && !ep.pinned {
		return ErrPathUnqualified
	}
	if route.SendMax < lane.required || route.ReceiveMax < lane.required ||
		route.SendMax > b.carriers[slot].DatagramMax || route.ReceiveMax > b.carriers[slot].DatagramMax {
		return ErrCarrierDatagram
	}
	key := adaptiveSource{slot: slot, key: src}
	previous := lane.paths[route.ID]
	replaceStream := previous != nil && stream && previous.source.slot == slot && previous.source.key.instance != nil
	replaceExpired := previous != nil && !stream && previous != lane.primary && previous != lane.previous && !now.Before(previous.route.ValidUntil)
	if existing := b.routes[key]; existing != nil && (existing != previous || !replaceExpired) {
		return fmt.Errorf("adaptive physical source unavailable")
	}
	if (previous == nil && len(lane.paths) == maxLanePaths) || (previous != nil && !replaceStream && !replaceExpired) {
		return fmt.Errorf("adaptive path unavailable")
	}
	if previous != nil {
		delete(b.routes, previous.source)
		if previous == lane.previous {
			lane.previous = nil
		}
	}
	path := &adaptivePath{source: key, lane: lane, route: route}
	lane.paths[route.ID], b.routes[key] = path, path
	if stream && (lane.primary == nil || lane.primary == previous) {
		oldPrimary := lane.primary
		lane.primary = path
		lane.revision++
		reason := SwitchInitial
		if oldPrimary != nil {
			reason = SwitchReconnected
		}
		lane.recordSwitch(now, oldPrimary, reason)
	}
	return nil
}

// ExtendPath extends a live carrier's authorization through session renewal.
func (b *AdaptiveBind) ExtendPath(ep *LaneEndpoint, id string, until time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if lane := b.laneFor(ep); lane != nil {
		if path := lane.paths[id]; path != nil && until.After(b.now()) {
			path.route.ValidUntil = until
		}
	}
}

// PreparePathReceive opens one qualified candidate for bounded receive-only
// overlap while the remote endpoint commits the selection. The sending path
// remains unchanged until the local commit.
func (b *AdaptiveBind) PreparePathReceive(ep *LaneEndpoint, candidate string, epoch uint64) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	lane := b.laneFor(ep)
	if lane == nil || lane.revision != epoch {
		return nil, ErrStalePathEpoch
	}
	now := b.now()
	path := lane.paths[candidate]
	if b.epoch == nil || path == nil || !now.Before(path.route.ValidUntil) || path == lane.primary {
		return nil, ErrPathUnqualified
	}
	if p := lane.prepared; p != nil && p.epoch == epoch && now.Before(p.until) {
		return nil, ErrStalePathEpoch
	}
	p := &receivePreparation{path: path, epoch: epoch, until: now.Add(pathReceiveOverlap)}
	lane.prepared = p
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if lane.prepared == p {
			lane.prepared = nil
		}
	}, nil
}

// CommitPath selects a qualified path using compare-and-swap. A short
// receive-only overlap permits packets in flight on the previous path.
func (b *AdaptiveBind) CommitPath(ep *LaneEndpoint, candidate string, epoch uint64) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	lane := b.laneFor(ep)
	if lane == nil {
		return 0, ErrPathUnqualified
	}
	if b.epoch == nil {
		return lane.revision, net.ErrClosed
	}
	if lane.revision != epoch {
		return lane.revision, ErrStalePathEpoch
	}
	path := lane.paths[candidate]
	now := b.now()
	if path == nil || !now.Before(path.route.ValidUntil) {
		return lane.revision, ErrPathUnqualified
	}
	if path != lane.primary {
		lane.previous, lane.primary = lane.primary, path
		lane.prepared = nil
		lane.overlapEnds = now.Add(pathReceiveOverlap)
		lane.revision++
		reason := SwitchQualified
		if lane.previous == nil {
			reason = SwitchInitial
		}
		lane.recordSwitch(now, lane.previous, reason)
	}
	return lane.revision, nil
}

// RemovePath retires one candidate without falling back to an unqualified
// transport. An operator can commit another qualified path with the new epoch.
func (b *AdaptiveBind) RemovePath(ep *LaneEndpoint, candidate string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if lane := b.laneFor(ep); lane != nil {
		if p := lane.paths[candidate]; p != nil {
			delete(b.routes, p.source)
			delete(lane.paths, candidate)
			if lane.primary == p {
				lane.primary, lane.previous = nil, nil
				lane.recordSwitch(b.now(), p, SwitchRetired)
			} else if lane.previous == p {
				lane.previous = nil
			}
			lane.revision++
		}
	}
}

// FailPath retires exactly one physical incarnation. When that incarnation
// was primary, fallback must already be qualified for the same lane.
func (b *AdaptiveBind) FailPath(ep *LaneEndpoint, candidate string, physical conn.Endpoint, fallback string) {
	source, ok := getCarrierSource(physical)
	if !ok {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	lane := b.laneFor(ep)
	if lane == nil {
		return
	}
	p := lane.paths[candidate]
	if p == nil || p.source.key != source {
		return
	}
	delete(b.routes, p.source)
	delete(lane.paths, candidate)
	if lane.previous == p {
		lane.previous = nil
	}
	if lane.primary != p {
		return
	}
	now := b.now()
	lane.primary, lane.previous = nil, nil
	if standby := lane.paths[fallback]; standby != nil && now.Before(standby.route.ValidUntil) {
		lane.primary = standby
	}
	lane.revision++
	lane.recordSwitch(now, p, SwitchCarrierFailure)
}

func (b *AdaptiveBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	b.mu.RLock()
	open := b.epoch != nil
	b.mu.RUnlock()
	if open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	generation := &adaptiveOpen{done: make(chan struct{}), ports: make([]uint16, len(b.carriers)), active: make([]bool, len(b.carriers))}
	var fns []conn.ReceiveFunc
	for slot, c := range b.carriers {
		requested := c.ListenPort
		if slot == 0 {
			requested = port
		}
		listeners, actual, err := c.Bind.Open(requested)
		if err != nil {
			if c.Optional {
				continue
			}
			for i := slot - 1; i >= 0; i-- {
				if generation.active[i] {
					_ = b.carriers[i].Bind.Close()
				}
			}
			return nil, 0, fmt.Errorf("open carrier %s: %w", c.Name, err)
		}
		generation.ports[slot], generation.active[slot] = actual, true
		for _, fn := range listeners {
			fns = append(fns, b.receive(generation, slot, c.Bind.BatchSize(), fn))
		}
	}
	b.mu.Lock()
	b.epoch = generation
	b.mu.Unlock()
	return fns, generation.ports[0], nil
}

func (b *AdaptiveBind) CarrierPort(name string) (uint16, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	slot, found := b.slots[name]
	if !found || b.epoch == nil || !b.epoch.active[slot] {
		return 0, false
	}
	return b.epoch.ports[slot], true
}

func (b *AdaptiveBind) receive(generation *adaptiveOpen, slot, batch int, fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 || len(sizes) < len(bufs) || len(eps) < len(bufs) {
			return 0, fmt.Errorf("invalid receive buffers")
		}
		limit := min(len(bufs), batch)
		for {
			select {
			case <-generation.done:
				return 0, net.ErrClosed
			default:
			}
			n, err := fn(bufs[:limit], sizes[:limit], eps[:limit])
			b.mu.RLock()
			if b.epoch != generation {
				b.mu.RUnlock()
				return 0, net.ErrClosed
			}
			if err != nil {
				b.mu.RUnlock()
				return 0, err
			}
			if n < 0 || n > limit {
				b.mu.RUnlock()
				return 0, fmt.Errorf("invalid carrier receive count")
			}
			out := 0
			now := b.now()
			for i := 0; i < n; i++ {
				key, ok := getCarrierSource(eps[i])
				if !ok {
					continue
				}
				path := b.routes[adaptiveSource{slot: slot, key: key}]
				if path == nil || !now.Before(path.route.ValidUntil) || sizes[i] < 1 ||
					sizes[i] > path.route.ReceiveMax || sizes[i] > len(bufs[i]) || !path.admitsReceive(now) {
					continue
				}
				if out != i {
					if sizes[i] > len(bufs[out]) {
						continue
					}
					copy(bufs[out], bufs[i][:sizes[i]])
				}
				sizes[out], eps[out] = sizes[i], path.lane.endpoint
				out++
			}
			b.mu.RUnlock()
			if out > 0 {
				return out, nil
			}
		}
	}
}

func (p *adaptivePath) admitsReceive(now time.Time) bool {
	lane := p.lane
	if lane.primary == p || (lane.previous == p && now.Before(lane.overlapEnds)) {
		return true
	}
	prepared := lane.prepared
	return prepared != nil && prepared.path == p && prepared.epoch == lane.revision && now.Before(prepared.until)
}

func (b *AdaptiveBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	endpoint, ok := ep.(*LaneEndpoint)
	if !ok || endpoint == nil {
		return conn.ErrWrongEndpointType
	}
	if len(bufs) == 0 || len(bufs) > b.batch {
		return fmt.Errorf("invalid send batch")
	}
	b.mu.RLock()
	lane := b.laneFor(endpoint)
	generation := b.epoch
	if generation == nil {
		b.mu.RUnlock()
		return net.ErrClosed
	}
	if lane == nil || lane.primary == nil ||
		!b.now().Before(lane.primary.route.ValidUntil) {
		b.mu.RUnlock()
		return ErrPathUnqualified
	}
	p := lane.primary
	carrier := b.carriers[p.source.slot]
	observeDemand := lane.observeDemand
	maxSize, remote := p.route.SendMax, p.route.Endpoint
	generation.sends.Add(1)
	b.mu.RUnlock()
	defer generation.sends.Done()

	var demand bool
	for _, buf := range bufs {
		if len(buf) < 1 || len(buf) > maxSize {
			return ErrCarrierDatagram
		}
		// Empty authenticated WireGuard keepalives are 32 bytes.
		if observeDemand && len(buf) > 32 && isWireGuardTransport(buf) {
			demand = true
		}
	}
	batch := carrier.Bind.BatchSize()
	for len(bufs) > 0 {
		n := min(batch, len(bufs))
		if err := carrier.Bind.Send(bufs[:n], remote); err != nil {
			if carrier.SendFailed != nil {
				select {
				case <-generation.done:
				default:
					carrier.SendFailed(err)
				}
			}
			// conn.Bind cannot report the accepted prefix. Never replay it.
			return err
		}
		bufs = bufs[n:]
	}
	if demand {
		endpoint.demand.Add(1)
	}
	return nil
}

func (b *AdaptiveBind) Close() error {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	b.mu.Lock()
	if b.epoch == nil {
		b.mu.Unlock()
		return nil
	}
	generation := b.epoch
	close(generation.done)
	b.epoch = nil
	clear(b.routes)
	for _, lane := range b.lanes {
		clear(lane.paths)
		lane.primary, lane.previous = nil, nil
		lane.prepared = nil
		lane.revision++
	}
	b.mu.Unlock()

	var err error
	for i := len(b.carriers) - 1; i >= 0; i-- {
		if generation.active[i] {
			err = errors.Join(err, b.carriers[i].Bind.Close())
		}
	}
	// The underlying Close unblocks I/O first. An interrupted Send must
	// retire before Open publishes new sockets for the same carrier.
	generation.sends.Wait()
	return err
}

func (b *AdaptiveBind) SetMark(mark uint32) error {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	var err error
	for i, c := range b.carriers {
		if !c.Optional || (b.epoch != nil && b.epoch.active[i]) {
			err = errors.Join(err, c.Bind.SetMark(mark))
		}
	}
	return err
}

func (b *AdaptiveBind) BatchSize() int { return b.batch }

func (b *AdaptiveBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	id, ok := strings.CutPrefix(s, adaptiveEndpointPrefix)
	if !ok {
		return nil, conn.ErrWrongEndpointType
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	lane := b.lanes[id]
	if lane == nil {
		return nil, ErrPathUnqualified
	}
	return lane.endpoint, nil
}

var _ conn.Bind = (*AdaptiveBind)(nil)
