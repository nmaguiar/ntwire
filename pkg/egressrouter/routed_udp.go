package egressrouter

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/socks"
)

type directUDPFlow struct {
	net.Conn
	ip netip.Addr
}

type udpFlowKey struct {
	host string
	port uint16
}

func (r *Router) serveRoutedUDP(parent context.Context, in net.Conn, state *routeState, sourceHint netip.AddrPort) {
	peer := in.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	host := in.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		socks.Reply(in, 1)
		return
	}
	defer udp.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stopReload := context.AfterFunc(state.probeCtx, cancel)
	defer stopReload()
	stop := context.AfterFunc(ctx, func() { _ = in.Close(); _ = udp.Close() })
	defer stop()
	idle := state.config.Routing.UDPIdleTimeout
	touch := func() { _ = udp.SetReadDeadline(time.Now().Add(idle)) }
	touch()
	var readers sync.WaitGroup
	var flowsMu sync.Mutex
	flows := make(map[udpFlowKey]*directUDPFlow)
	var counted atomic.Bool
	defer func() {
		cancel()
		flowsMu.Lock()
		for _, flow := range flows {
			_ = flow.Close()
		}
		flowsMu.Unlock()
		readers.Wait()
		if counted.Load() {
			r.direct.udpActive.Add(-1)
		}
	}()
	var source netip.AddrPort
	if sourceHint.Port() != 0 {
		source = netip.AddrPortFrom(peer, sourceHint.Port())
	}
	var upstream net.Conn
	var upstreamSnapshot *asnData
	var member ranked
	var h *memberHealth
	defer func() {
		if upstream != nil {
			_ = upstream.Close()
			h.active.Add(-1)
		}
	}()
	socks.ReplyBound(in, udp.LocalAddr().(*net.UDPAddr).AddrPort())
	controlDone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, in); cancel(); close(controlDone) }()
	defer func() { _ = in.Close(); <-controlDone }()
	packet := make([]byte, maxSOCKSDatagram+1)
	for {
		n, from, err := udp.ReadFromUDPAddrPort(packet)
		if err != nil || ctx.Err() != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if n > maxSOCKSDatagram || from.Addr() != peer || source.IsValid() && source != from {
			continue
		}
		dst, offset, err := socks.DatagramDestination(packet[:n])
		if err != nil {
			continue
		}
		now := r.now()
		snapshot := state.asnSnapshot(now)
		decision := r.decision(state, dst, snapshot, now)
		if decision.Action == Direct || decision.Action == Indeterminate && decision.reason == "asn_hostname_unresolved" && r.scopedASN(state, dst, "local") {
			key := udpFlowKey{host: hostKey(dst), port: dst.Port}
			flowsMu.Lock()
			flow := flows[key]
			capacity := len(flows) < 64
			flowsMu.Unlock()
			if flow == nil {
				if !capacity || !claim(&r.directUDPFlows, 256) {
					continue
				}
				setup, done := context.WithTimeout(ctx, state.config.Failover.TotalTimeout)
				addresses, err := r.directAddresses(setup, state, dst, decision, nil, snapshot)
				if socksCode(err) == 2 {
					r.denied.Add(1)
				}
				if err == nil && ctx.Err() == nil && snapshot == state.asnSnapshot(r.now()) {
					for _, ip := range addresses {
						if out, e := r.network.dial(setup, "udp", netip.AddrPortFrom(ip, dst.Port).String()); e == nil {
							flow = &directUDPFlow{Conn: out, ip: ip}
							break
						}
					}
				}
				done()
				if flow == nil {
					r.directUDPFlows.Add(-1)
					continue
				}
				flowsMu.Lock()
				flows[key] = flow
				flowsMu.Unlock()
				if counted.CompareAndSwap(false, true) {
					r.direct.udpActive.Add(1)
				}
				readers.Go(func() {
					defer func() {
						_ = flow.Close()
						flowsMu.Lock()
						delete(flows, key)
						flowsMu.Unlock()
						r.directUDPFlows.Add(-1)
					}()
					reply := make([]byte, maxSOCKSDatagram)
					_ = flow.SetReadDeadline(time.Now().Add(idle))
					for {
						n, err := flow.Read(reply)
						if err != nil || ctx.Err() != nil {
							return
						}
						if !r.directUDPAllowed(state, dst, flow.ip) {
							return
						}
						frame := socks.DatagramFrame(netip.AddrPortFrom(flow.ip, dst.Port), reply[:n])
						if len(frame) <= maxSOCKSDatagram {
							if _, err := udp.WriteToUDPAddrPort(frame, from); err != nil {
								return
							}
							r.direct.udpReceived.Add(uint64(n))
							touch()
						}
					}
				})
			}
			if !source.IsValid() {
				source = from
			}
			_ = flow.SetReadDeadline(time.Now().Add(idle))
			if ctx.Err() != nil || !r.directUDPAllowed(state, dst, flow.ip) {
				_ = flow.Close()
				continue
			}
			_ = flow.SetWriteDeadline(time.Now().Add(state.config.Failover.AttemptTimeout))
			n, err = flow.Write(packet[offset:n])
			if err != nil {
				_ = flow.Close()
				continue
			}
			r.direct.udpSent.Add(uint64(n))
			touch()
			continue
		}
		if decision.Action != Proxy {
			_, _ = r.reject(decision)
			continue
		}
		if upstream != nil && upstreamSnapshot != snapshot {
			return
		}
		if upstream == nil {
			setupLimits := r.acquireSetup()
			if setupLimits == nil {
				continue
			}
			started := time.Now()
			out, chosen, health, err := r.openUDP(ctx, state, dst, decision)
			setupLimits.observe(started, err)
			r.attempts.Add(-1)
			if err != nil {
				continue
			}
			if !r.udpPermitted(chosen, dst) || snapshot != state.asnSnapshot(r.now()) || ctx.Err() != nil {
				_ = out.Close()
				continue
			}
			upstream, member, h = out, chosen, health
			upstreamSnapshot = snapshot
			if !source.IsValid() {
				source = from
			}
			h.active.Add(1)
			h.routed.Add(1)
			if state.config.Routing.AffinityScope == "group" {
				r.remember(state, Destination{}, chosen.ID())
			}
			readers.Go(func() {
				defer out.Close()
				packet := make([]byte, maxSOCKSDatagram+1)
				for {
					n, err := out.Read(packet)
					if err != nil || ctx.Err() != nil {
						return
					}
					r.mu.Lock()
					valid := r.state == state && !r.excluded[chosen.ID()]
					r.mu.Unlock()
					if !valid || snapshot != state.asnSnapshot(r.now()) {
						cancel()
						return
					}
					if n > maxSOCKSDatagram {
						continue
					}
					reply, offset, err := socks.DatagramDestination(packet[:n])
					if err != nil || CheckNumericDomain(reply, chosen.NumericDomain) != nil {
						continue
					}
					if _, err := udp.WriteToUDPAddrPort(packet[:n], from); err != nil {
						return
					}
					h.received.Add(uint64(n - offset))
					touch()
				}
			})
		}
		if !decision.permits(member.ID()) || !r.udpPermitted(member, dst) || CheckNumericDomain(dst, member.NumericDomain) != nil {
			continue
		}
		if !source.IsValid() {
			source = from
		}
		_ = upstream.SetWriteDeadline(time.Now().Add(state.config.Failover.AttemptTimeout))
		if _, err := upstream.Write(packet[:n]); err != nil {
			return
		}
		h.sent.Add(uint64(n - offset))
		touch()
	}
}

func (r *Router) directUDPAllowed(state *routeState, dst Destination, ip netip.Addr) bool {
	r.mu.Lock()
	current := r.state == state
	r.mu.Unlock()
	if !current {
		return false
	}
	decision := state.decide(dst, ip, r.now())
	if decision.Action != Direct {
		return false
	}
	local, err := r.network.local()
	return err == nil && directIPAllowed(ip, decision, local)
}
