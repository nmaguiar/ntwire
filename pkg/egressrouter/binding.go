package egressrouter

import (
	"context"
	"net"
	"net/netip"
	"slices"
)

// BindableEgress prepares a one-use connection offer from an authenticated
// native egress. The same member must complete the exact-address connection.
type BindableEgress interface {
	OfferDestination(context.Context, Destination) (DestinationOffer, error)
}

type DestinationOffer interface {
	Addresses() []netip.Addr
	ConnectAddress(context.Context, netip.Addr) (net.Conn, error)
	Close() error
}

func (r *Router) classifyAnswers(state *routeState, snapshot *asnData, dst Destination, answers []netip.Addr) (Decision, error) {
	var route Decision
	if len(answers) == 0 || len(answers) > 32 {
		return route, &Failure{Class: "hostname_resolution_failed", Code: 4}
	}
	for _, ip := range answers {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.Zone() != "" {
			return route, &Failure{Class: "hostname_resolution_failed", Code: 4}
		}
		d := state.config.Routing.decide(dst, ip, func(ip netip.Addr) (uint32, string) {
			number, reason := state.lookupASNData(snapshot, ip, r.now())
			if reason == "" {
				r.asnHits.Add(1)
			} else {
				r.asnMisses.Add(1)
			}
			return number, reason
		})
		if d.Action == Deny || d.Action == Indeterminate {
			_, err := r.reject(d)
			return route, err
		}
		if route.Action != "" && (route.Action != d.Action || !slices.Equal(route.Members, d.Members)) {
			_, err := r.reject(Decision{Action: Indeterminate, reason: "hostname_route_conflict"})
			return route, err
		}
		route = d
	}
	return route, nil
}

func (r *Router) dialClassifiedHostname(ctx context.Context, state *routeState, dst Destination, snapshot *asnData) (net.Conn, error) {
	local := r.scopedASN(state, dst, "local")
	remote := r.scopedASN(state, dst, "remote")
	if !local && !remote {
		return r.reject(Decision{Action: Indeterminate, reason: "asn_hostname_unresolved"})
	}
	if snapshot == nil {
		return r.reject(Decision{Action: Indeterminate, reason: "asn_unavailable_or_stale"})
	}
	var localIPs []netip.Addr
	if local {
		var err error
		localIPs, err = r.network.resolve(ctx, "ip", dst.Host)
		if err != nil {
			return nil, &Failure{Class: "hostname_resolution_failed", Code: 4}
		}
		decision, err := r.classifyAnswers(state, snapshot, dst, localIPs)
		if err != nil {
			return nil, err
		}
		if decision.Action == Direct {
			return r.dialDirectAddresses(ctx, state, dst, decision, snapshot, localIPs)
		}
		if id := state.config.Routing.ASN.ResolverMember; id == nil || !decision.permits(*id) {
			return r.reject(Decision{Action: Indeterminate, reason: "asn_binding_member_ineligible"})
		}
	}

	policy := state.config.Routing.ASN
	if !state.config.Routing.resolverPermitted(dst, *policy.ResolverMember) {
		return r.reject(Decision{Action: Indeterminate, reason: "asn_binding_member_ineligible"})
	}
	for _, member := range r.rankDecision(state, dst, Decision{Action: Proxy, Members: []MemberID{*policy.ResolverMember}}) {
		backend, ok := member.Dialer.(BindableEgress)
		if !ok || !member.DestinationBinding {
			break
		}
		h, halfOpen := r.admit(state, member, false)
		if h == nil {
			break
		}
		defer func() {
			if halfOpen {
				r.mu.Lock()
				h.testing = false
				r.mu.Unlock()
			}
		}()
		if !r.bindingCurrent(state, snapshot, member) {
			return nil, &Failure{Class: "routing_changed"}
		}
		offer, err := backend.OfferDestination(ctx, dst)
		if err != nil {
			if socksCode(err) == 2 {
				r.denied.Add(1)
			}
			return nil, err
		}
		defer offer.Close()
		addresses := offer.Addresses()
		decision, err := r.classifyAnswers(state, snapshot, dst, addresses)
		if err != nil {
			return nil, err
		}
		if !decision.permits(member.ID()) {
			return r.reject(Decision{Action: Indeterminate, reason: "asn_binding_member_ineligible"})
		}
		for _, ip := range addresses {
			if local && !slices.ContainsFunc(localIPs, func(a netip.Addr) bool { return a.Unmap() == ip.Unmap() }) {
				continue
			}
			if !r.bindingCurrent(state, snapshot, member) {
				return nil, &Failure{Class: "routing_changed"}
			}
			out, err := offer.ConnectAddress(ctx, ip)
			if err != nil {
				if socksCode(err) == 2 {
					r.denied.Add(1)
				}
				return nil, err
			}
			if !r.bindingCurrent(state, snapshot, member) {
				_ = out.Close()
				return nil, &Failure{Class: "routing_changed"}
			}
			h.routed.Add(1)
			h.active.Add(1)
			r.mu.Lock()
			if r.state == state {
				r.lastSelection, r.lastReason = member.ID(), "hostname_asn"
			}
			r.mu.Unlock()
			return r.trackRoutedFlow(&routedConn{Conn: out, destination: dst, member: member.Member,
				generation: member.Generation, health: h, state: state, asn: snapshot, bound: true}, ip), nil
		}
		return r.reject(Decision{Action: Indeterminate, reason: "asn_binding_no_common_address"})
	}
	return r.reject(Decision{Action: Indeterminate, reason: "asn_binding_unavailable"})
}

func (r *Router) bindingCurrent(state *routeState, snapshot *asnData, member ranked) bool {
	r.mu.Lock()
	valid := r.state == state && !r.excluded[member.ID()] && snapshot == state.asnSnapshot(r.now())
	r.mu.Unlock()
	if !valid {
		return false
	}
	c := r.candidate(state, member.Member)
	return c.Dialer != nil && c.Generation == member.Generation && c.DestinationBinding
}
