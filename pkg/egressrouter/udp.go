package egressrouter

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/socks"
)

// UDPEgress returns a connected transport with one complete SOCKS datagram per
// read or write. Closing the transport also closes its upstream association.
type UDPEgress interface {
	AssociateUDP(context.Context) (net.Conn, error)
}

const maxSOCKSDatagram = 65507

func (r *Router) serveUDP(ctx context.Context, in net.Conn, client netip.AddrPort) {
	tcp, ok := in.RemoteAddr().(*net.TCPAddr)
	if !ok || !tcp.AddrPort().Addr().Unmap().IsLoopback() ||
		(!client.Addr().IsUnspecified() && client.Addr() != tcp.AddrPort().Addr().Unmap()) {
		socks.Reply(in, 2)
		return
	}
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if state == nil || !state.config.Enabled || !state.config.Routing.UDPAssociate {
		socks.Reply(in, 7)
		return
	}
	if state.config.Routing.mayDirect() || state.config.Routing.usesASN() {
		r.serveRoutedUDP(ctx, in, state, client)
		return
	}
	setupLimits := r.acquireSetup()
	if setupLimits == nil {
		socks.Reply(in, 1)
		return
	}
	setup, cancel := context.WithCancel(ctx)
	stopWatch := localproxy.WatchSetupDisconnect(in, cancel)
	started := time.Now()
	out, chosen, h, err := r.openUDP(setup, state, Destination{}, Decision{Action: Proxy})
	setupLimits.observe(started, err)
	stopWatch()
	canceled := setup.Err() != nil
	cancel()
	r.attempts.Add(-1)
	if canceled {
		if out != nil {
			_ = out.Close()
		}
		return
	}
	if err != nil {
		socks.Reply(in, socksCode(err))
		return
	}
	defer out.Close()
	if state.config.Routing.AffinityScope == "group" {
		r.remember(state, Destination{}, chosen.ID())
	}
	h.active.Add(1)
	defer h.active.Add(-1)
	host := in.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		socks.Reply(in, 1)
		return
	}
	defer udp.Close()
	socks.ReplyBound(in, udp.LocalAddr().(*net.UDPAddr).AddrPort())
	h.routed.Add(1)

	idle := state.config.Routing.UDPIdleTimeout
	setIdle := func() {
		deadline := time.Now().Add(idle)
		_ = udp.SetReadDeadline(deadline)
		_ = out.SetReadDeadline(deadline)
	}
	setIdle()
	var mu sync.Mutex
	var source netip.AddrPort
	if client.Port() != 0 {
		source = netip.AddrPortFrom(tcp.AddrPort().Addr().Unmap(), client.Port())
	}
	closeAll := func() { _ = in.Close(); _ = udp.Close(); _ = out.Close() }
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()
	var wg sync.WaitGroup
	wg.Go(func() {
		defer closeAll()
		packet := make([]byte, maxSOCKSDatagram+1)
		for {
			n, from, err := udp.ReadFromUDPAddrPort(packet)
			if err != nil {
				return
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			if n > maxSOCKSDatagram || from.Addr() != tcp.AddrPort().Addr().Unmap() {
				continue
			}
			dst, offset, err := socks.DatagramDestination(packet[:n])
			if err != nil || CheckNumericDomain(dst, chosen.NumericDomain) != nil || !r.udpPermitted(chosen, dst) {
				continue
			}
			mu.Lock()
			if !source.IsValid() {
				source = from
			}
			owned := source == from
			mu.Unlock()
			if !owned {
				continue
			}
			if _, err = out.Write(packet[:n]); err != nil {
				return
			}
			h.sent.Add(uint64(n - offset))
			setIdle()
		}
	})
	wg.Go(func() {
		defer closeAll()
		packet := make([]byte, maxSOCKSDatagram+1)
		for {
			n, err := out.Read(packet)
			if err != nil {
				return
			}
			if n > maxSOCKSDatagram {
				continue
			}
			dst, offset, err := socks.DatagramDestination(packet[:n])
			if err != nil || CheckNumericDomain(dst, chosen.NumericDomain) != nil {
				continue
			}
			mu.Lock()
			client := source
			mu.Unlock()
			if client.IsValid() {
				if _, err = udp.WriteToUDPAddrPort(packet[:n], client); err != nil {
					return
				}
				h.received.Add(uint64(n - offset))
				setIdle()
			}
		}
	})
	_, _ = io.Copy(io.Discard, in)
	closeAll()
	wg.Wait()
}

func (r *Router) udpPermitted(c ranked, dst Destination) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state != nil && r.state.config.Routing.UDPAssociate &&
		!r.excluded[c.ID()] && r.state.config.approves(c.Member) && r.state.decide(dst, dst.IP(), r.now()).permits(c.ID())
}

func (r *Router) openUDP(ctx context.Context, state *routeState, dst Destination, decision Decision) (net.Conn, ranked, *memberHealth, error) {
	ctx, cancel := context.WithTimeout(ctx, state.config.Failover.TotalTimeout)
	defer cancel()
	limit := state.config.Failover.MaxAttempts
	if !*state.config.Failover.Enabled {
		limit = 1
	}
	attempts := 0
	var last error = &Failure{Class: "udp_unavailable", Code: 7}
	// The TCP request names the sender. Actual destinations are authorized
	// separately for each datagram on the pinned association.
	for _, c := range r.rankDecision(state, dst, decision) {
		if attempts >= limit || ctx.Err() != nil {
			break
		}
		backend, ok := c.Dialer.(UDPEgress)
		if !ok || !c.UDP {
			continue
		}
		h, halfOpen := r.admit(state, c, false)
		if h == nil {
			continue
		}
		if err := CheckNumericDomain(dst, c.NumericDomain); err != nil {
			r.mu.Lock()
			if halfOpen {
				h.testing = false
			}
			r.mu.Unlock()
			return nil, ranked{}, nil, err
		}
		if attempts > 0 {
			r.failovers.Add(1)
		}
		attempts++
		attempt, done := context.WithTimeout(ctx, state.config.Failover.AttemptTimeout)
		conn, err := backend.AssociateUDP(attempt)
		if err == nil && (attempt.Err() != nil || conn == nil) {
			err = &Failure{Class: "ambiguous", Stage: "udp_associate"}
		}
		done()
		r.mu.Lock()
		if halfOpen {
			h.testing = false
		}
		if err == nil && r.state == state {
			h.consecutive = 0
			h.openUntil = time.Time{}
			r.lastSelection = c.ID()
			r.lastReason = "udp_association"
			r.mu.Unlock()
			if attempts > 1 {
				r.recovered.Add(1)
			}
			return conn, c, h, nil
		}
		r.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		last = err
		failure, ok := err.(*Failure)
		if !ok || !failure.Retry {
			break
		}
	}
	if last == nil {
		last = &Failure{Class: "udp_unavailable", Code: 7}
	}
	return nil, ranked{}, nil, last
}
