package wstransport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/coder/websocket"
)

// Opt-in parallel WSS lanes (wss-lanes-v1).
//
// Lane 0 is the ordinary /v1/wg connection and keeps every existing behavior:
// peer lifecycle callbacks, redial, and multipath health all follow lane 0
// alone. Extra lanes (1..n-1) are helper connections for the same peer id.
// They share the receive queue and endpoint identity, so WireGuard and the
// multipath scheduler still see one "wss" carrier. Send stays on one lane
// and spills to a less-loaded lane only when the active lane's queue backs
// up, for example while one TCP connection recovers from loss. That bounds
// the reordering spreading packets across lanes would otherwise cause.
// With one lane (the default) none of this code runs.

// MaxWSSLanes bounds the lanes one peer may open.
const MaxWSSLanes = 4

const (
	// laneSpillDepth is the active lane's queue depth that triggers a spill.
	laneSpillDepth = peerQueueDepth / 2
	// laneReturnAfter is how long lane 0 must stay idle-drained before Send
	// returns to it after a spill.
	laneReturnAfter = time.Second
)

// laneGroup holds one peer id's extra lanes and its sticky send choice.
type laneGroup struct {
	extra       map[int]*peer
	active      int // lane index Send currently uses; 0 is b.peers[id]
	lastSpillAt time.Time
}

// SetLanes sets how many parallel connections a client-side Bind opens, from
// 1 (default, a single connection) to MaxWSSLanes. It must be called before
// Open. A server-side Bind accepts extra lanes through ServeLane instead.
func (b *Bind) SetLanes(n int) {
	if n < 1 {
		n = 1
	}
	if n > MaxWSSLanes {
		n = MaxWSSLanes
	}
	b.mu.Lock()
	b.laneCount = n
	b.mu.Unlock()
}

// LanesUp reports how many connections (lane 0 included) are currently up
// for id. A client-side Bind's single peer id is "remote".
func (b *Bind) LanesUp(id string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	if b.peers[id] != nil {
		n++
	}
	if g := b.lanes[id]; g != nil {
		n += len(g.extra)
	}
	return n
}

// pickLaneLocked returns the peer Send should use for id, given lane 0's
// peer p0. Callers hold b.mu.
func (b *Bind) pickLaneLocked(id string, p0 *peer) *peer {
	g := b.lanes[id]
	if g == nil || len(g.extra) == 0 {
		return p0
	}
	laneAt := func(i int) *peer {
		if i == 0 {
			return p0
		}
		return g.extra[i]
	}
	cur := laneAt(g.active)
	now := time.Now()
	if cur != nil && len(cur.out) < laneSpillDepth {
		if g.active != 0 && p0 != nil && len(p0.out) == 0 && now.Sub(g.lastSpillAt) >= laneReturnAfter {
			g.active = 0
			return p0
		}
		return cur
	}
	// Spill: pick the least-loaded live lane, preferring lower indexes.
	best, bestLane := p0, 0
	for i := 1; i < MaxWSSLanes; i++ {
		lp := g.extra[i]
		if lp == nil {
			continue
		}
		if best == nil || len(lp.out) < len(best.out) {
			best, bestLane = lp, i
		}
	}
	if bestLane != g.active {
		g.active, g.lastSpillAt = bestLane, now
	}
	return best
}

// addLaneLocked registers p as lane for id, replacing an older connection on
// the same lane. Callers hold b.mu.
func (b *Bind) addLaneLocked(id string, lane int, p *peer) *peer {
	if b.lanes == nil {
		b.lanes = map[string]*laneGroup{}
	}
	g := b.lanes[id]
	if g == nil {
		g = &laneGroup{extra: map[int]*peer{}}
		b.lanes[id] = g
	}
	old := g.extra[lane]
	g.extra[lane] = p
	return old
}

func (b *Bind) removeLane(id string, lane int, p *peer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	g := b.lanes[id]
	if g == nil || g.extra[lane] != p {
		return
	}
	delete(g.extra, lane)
	if g.active == lane {
		g.active = 0
	}
	if len(g.extra) == 0 {
		delete(b.lanes, id)
	}
}

// closeLanesLocked detaches every extra lane for id (or all ids when id is
// empty) and returns them for closing outside the lock.
func (b *Bind) closeLanesLocked(id string) []*peer {
	var out []*peer
	for gid, g := range b.lanes {
		if id != "" && gid != id {
			continue
		}
		for _, p := range g.extra {
			out = append(out, p)
		}
		delete(b.lanes, gid)
	}
	return out
}

// ServeLane attaches an extra lane (1..MaxWSSLanes-1) for a peer id that has
// already been authorized by the caller. Lane 0 must use ServeHTTP. Like
// ServeHTTP it blocks for the lane's lifetime.
func (b *Bind) ServeLane(w http.ResponseWriter, r *http.Request, id string, lane int) error {
	if lane < 1 || lane >= MaxWSSLanes {
		return fmt.Errorf("invalid WebSocket lane %d", lane)
	}
	b.mu.Lock()
	ready := b.open
	b.mu.Unlock()
	if !ready {
		return errors.New("WebSocket transport is not ready")
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return err
	}
	p := newPeer(id, ws, endpoint{id: id, address: endpointAddress(r.RemoteAddr)})
	p.lane = lane
	b.mu.Lock()
	if !b.open {
		b.mu.Unlock()
		_ = ws.Close(websocket.StatusServiceRestart, "closing")
		return errors.New("WebSocket transport is not ready")
	}
	old := b.addLaneLocked(id, lane, p)
	b.mu.Unlock()
	if old != nil {
		_ = old.ws.Close(websocket.StatusNormalClosure, "replaced")
	}
	slog.Debug("WireGuard WebSocket lane connected", "peer", id, "lane", lane)
	go b.readLane(p, false)
	<-p.done
	return nil
}

// readLane pumps one extra lane. It never fires peer lifecycle callbacks:
// lane 0 alone defines the carrier's health.
func (b *Bind) readLane(p *peer, client bool) {
	go b.writeLoop(p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if client {
		go b.keepalive(ctx, p)
	}
	defer func() {
		b.removeLane(p.id, p.lane, p)
		close(p.done)
		slog.Debug("WireGuard WebSocket lane disconnected", "peer", p.id, "lane", p.lane)
		if client {
			go b.dialLane(p.lane)
		}
	}()
	b.pump(p)
}

// laneURL adds the lane query parameter to the client's WebSocket URL.
func laneURL(raw string, lane int) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("lane", strconv.Itoa(lane))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// dialLane keeps one client-side extra lane connected until the bind
// closes, with the same jittered backoff as lane 0's redial.
func (b *Bind) dialLane(lane int) {
	b.mu.Lock()
	done := b.done
	backoff := b.redialMin
	b.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			if backoff <= 0 {
				backoff = time.Millisecond
			}
			select {
			case <-done:
				return
			case <-time.After(time.Duration(rand.Int63n(int64(backoff)))):
			}
			b.mu.Lock()
			backoff = min(backoff*2, b.redialMax)
			b.mu.Unlock()
		}
		select {
		case <-done:
			return
		default:
		}
		b.mu.Lock()
		raw, client, header, dialTimeout, noRedial := b.url, b.client, b.header, b.dialTimeout, b.noRedial
		b.mu.Unlock()
		if noRedial && attempt > 0 {
			return
		}
		target, err := laneURL(raw, lane)
		if err != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		ws, _, err := websocket.Dial(dialCtx, target, &websocket.DialOptions{HTTPClient: client, HTTPHeader: header})
		cancel()
		if err != nil {
			slog.Debug("WireGuard WebSocket lane dial failed", "lane", lane, "error", err)
			continue
		}
		p := newPeer("remote", ws, endpoint{id: "remote", address: endpointAddress(raw)})
		p.lane = lane
		b.mu.Lock()
		if !b.open || b.done != done {
			b.mu.Unlock()
			_ = ws.Close(websocket.StatusNormalClosure, "closing")
			return
		}
		old := b.addLaneLocked("remote", lane, p)
		b.mu.Unlock()
		if old != nil {
			_ = old.ws.Close(websocket.StatusNormalClosure, "replaced")
		}
		slog.Debug("WireGuard WebSocket lane connected", "lane", lane)
		go b.readLane(p, true)
		return
	}
}
