package egressrouter

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

type directNetwork struct {
	resolve func(context.Context, string, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
	local   func() ([]net.Addr, error)
}

func nativeNetwork() directNetwork {
	dialer := &net.Dialer{}
	return directNetwork{net.DefaultResolver.LookupNetIP, dialer.DialContext, net.InterfaceAddrs}
}

type directTraffic struct {
	active                                                 atomic.Int64
	attempts, successes, failures, latency, sent, received atomic.Uint64
	udpActive                                              atomic.Int64
	udpSent, udpReceived                                   atomic.Uint64
}

var directGlobalIPv6 = netip.MustParsePrefix("2000::/3")

var lanRanges = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7"),
}

var blockedDirectRanges = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func directIPAllowed(ip netip.Addr, decision Decision, local []net.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.Zone() != "" {
		return false
	}
	if ip.Is6() && !directGlobalIPv6.Contains(ip) && !ip.IsPrivate() {
		return false
	}
	for _, prefix := range blockedDirectRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	for _, addr := range local {
		switch a := addr.(type) {
		case *net.IPNet:
			if own, ok := netip.AddrFromSlice(a.IP); ok {
				if own.Unmap() == ip {
					return false
				}
				if ip.Is4() && own.Unmap().Is4() {
					bits, _ := a.Mask.Size()
					if bits > 0 && bits < 31 {
						b := own.Unmap().As4()
						for j := bits; j < 32; j++ {
							b[j/8] |= byte(1 << (7 - j%8))
						}
						if netip.AddrFrom4(b) == ip {
							return false
						}
					}
				}
			}
		case *net.IPAddr:
			if own, ok := netip.AddrFromSlice(a.IP); ok && own.Unmap() == ip {
				return false
			}
		}
	}
	if !ip.IsPrivate() {
		return true
	}
	if decision.rule == nil {
		return false
	}
	for _, prefix := range decision.rule.prefixes {
		for _, lan := range lanRanges {
			if prefix.Bits() >= lan.Bits() && lan.Contains(prefix.Addr()) && prefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func isLocalName(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func (r *Router) scopedASN(state *routeState, dst Destination, mode string) bool {
	p := state.config.Routing.ASN
	return p != nil && p.HostnameResolution == mode && !isLocalName(hostKey(dst)) &&
		(Rule{Hosts: p.Hosts, Suffixes: p.Suffixes}).nameMatches(hostKey(dst))
}

func (r *Router) directAddresses(ctx context.Context, state *routeState, dst Destination, decision Decision, requested []netip.Addr, snapshot *asnData) ([]netip.Addr, error) {
	denied := &Failure{Class: "local_destination_denied", Code: 2}
	ip := dst.IP()
	var addresses []netip.Addr
	if ip.IsValid() {
		addresses = []netip.Addr{ip}
	} else if requested != nil {
		addresses = requested
	} else {
		if isLocalName(hostKey(dst)) {
			return nil, denied
		}
		addrs, err := r.network.resolve(ctx, "ip", dst.Host)
		if err != nil || len(addrs) == 0 || len(addrs) > 32 {
			return nil, &Failure{Class: "direct_resolution_failed", Code: 4}
		}
		addresses = addrs
	}

	local, err := r.network.local()
	if err != nil {
		return nil, &Failure{Class: "direct_interface_check_failed"}
	}
	allowed := make([]netip.Addr, 0, len(addresses))
	var matched *Rule
	for _, addr := range addresses {
		addr = addr.Unmap()
		candidate := decision
		if !ip.IsValid() {
			candidate = state.config.Routing.decide(dst, addr, func(ip netip.Addr) (uint32, string) {
				number, reason := state.lookupASNData(snapshot, ip, r.now())
				if requested == nil {
					if reason == "" {
						r.asnHits.Add(1)
					} else {
						r.asnMisses.Add(1)
					}
				}
				return number, reason
			})
			if candidate.Action == Indeterminate {
				_, err := r.reject(candidate)
				return nil, err
			}
		}
		if candidate.Action != Direct || !directIPAllowed(addr, candidate, local) {
			return nil, denied
		}
		if len(allowed) != 0 && candidate.rule != matched {
			return nil, &Failure{Class: "direct_address_policy_conflict", Code: 2}
		}
		matched = candidate.rule
		if !slices.Contains(allowed, addr) {
			allowed = append(allowed, addr)
		}
	}
	return allowed, nil
}

func (r *Router) dialDirect(ctx context.Context, state *routeState, dst Destination, decision Decision, snapshot *asnData) (net.Conn, error) {
	return r.dialDirectAddresses(ctx, state, dst, decision, snapshot, nil)
}

func (r *Router) dialDirectAddresses(ctx context.Context, state *routeState, dst Destination, decision Decision, snapshot *asnData, requested []netip.Addr) (net.Conn, error) {
	started := r.now()
	r.direct.attempts.Add(1)
	succeeded := false
	defer func() {
		if !succeeded {
			r.direct.failures.Add(1)
		}
	}()
	addresses, err := r.directAddresses(ctx, state, dst, decision, requested, snapshot)
	if err != nil {
		if socksCode(err) == 2 {
			r.denied.Add(1)
		}
		return nil, err
	}
	r.mu.Lock()
	valid := r.state == state && snapshot == state.asnSnapshot(r.now())
	r.mu.Unlock()
	if !valid {
		return nil, &Failure{Class: "routing_changed"}
	}
	conn, err := r.directDialTCP(ctx, addresses, dst.Port)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &Failure{Class: "timeout", Code: 6}
		}
		return nil, &Failure{Class: "direct_connect_failed", Code: 5}
	}
	r.mu.Lock()
	valid = r.state == state && snapshot == state.asnSnapshot(r.now())
	r.mu.Unlock()
	if !valid {
		_ = conn.Close()
		return nil, &Failure{Class: "routing_changed"}
	}
	succeeded = true
	r.direct.successes.Add(1)
	r.direct.latency.Add(uint64(max(0, r.now().Sub(started))))
	r.direct.active.Add(1)
	return &routedConn{Conn: conn, destination: dst, direct: &r.direct, state: state, asn: snapshot}, nil
}

// Race the two address families, with sequential attempts within each family.
func (r *Router) directDialTCP(ctx context.Context, addresses []netip.Addr, port uint16) (net.Conn, error) {
	dial := func(ctx context.Context, addresses []netip.Addr) (net.Conn, error) {
		var err error
		for _, ip := range addresses {
			var conn net.Conn
			conn, err = r.network.dial(ctx, "tcp", netip.AddrPortFrom(ip, port).String())
			if err == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, err
	}
	if !slices.ContainsFunc(addresses[1:], func(ip netip.Addr) bool { return ip.Is4() != addresses[0].Is4() }) {
		return dial(ctx, addresses)
	}
	var primary, fallback []netip.Addr
	for _, ip := range addresses {
		if ip.Is4() == addresses[0].Is4() {
			primary = append(primary, ip)
		} else {
			fallback = append(fallback, ip)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	run := func(addrs []netip.Addr) {
		conn, err := dial(ctx, addrs)
		select {
		case results <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}
	go run(primary)
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	pending := 1
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			if fallback != nil {
				pending++
				go run(fallback)
				fallback = nil
			}
		case result := <-results:
			if result.err == nil {
				return result.conn, nil
			}
			pending--
			if fallback != nil {
				timer.Stop()
				pending++
				go run(fallback)
				fallback = nil
			}
			if pending == 0 {
				return nil, result.err
			}
		}
	}
}
