package server

// This file contains the server-wide destination authorization seam.  It is
// deliberately independent of a particular listener: SOCKS, fixed forwards,
// and future UDP/HTTP paths pass the same normalized context here.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/socks"
)

type DestinationPolicy struct {
	Filters        []string `yaml:"filters"`
	DomainFilters  []string `yaml:"domain_filters"`
	ASNFilters     []uint32 `yaml:"asn_filters"`
	OnlyLocal      bool     `yaml:"only_local"`
	ReverseFilters bool     `yaml:"reverse_filters"`
	AllowAll       bool     `yaml:"allow_all"`
	Protocols      []string `yaml:"protocols"`
	Ports          []uint16 `yaml:"ports"`
}

type DataPlanePrincipal struct {
	Method, Identity string
	TunnelIP         netip.Addr
	Tunnels          map[string]bool
	Policy           string
}

type DestinationContext struct {
	Principal                  DataPlanePrincipal
	Tunnel, Hostname, Protocol string
	IP                         netip.Addr
	Port                       uint16
	ASN                        uint32
}

type DestinationDecision struct {
	Allowed bool
	Reason  string
}

type compiledPolicy struct {
	filter    *socks.Filter
	protocols map[string]bool
	ports     map[uint16]bool
}

func compilePolicy(p DestinationPolicy, asn socks.ASNLookup) (*compiledPolicy, error) {
	f, err := socks.NewFilter(socks.FilterConfig{OnlyLocal: p.OnlyLocal, CIDRs: p.Filters, DomainSuffixes: p.DomainFilters, ASNs: p.ASNFilters, Invert: p.ReverseFilters, AllowAll: p.AllowAll}, asn)
	if err != nil {
		return nil, err
	}
	c := &compiledPolicy{filter: f, protocols: map[string]bool{}, ports: map[uint16]bool{}}
	for _, v := range p.Protocols {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "tcp" && v != "udp" {
			return nil, fmt.Errorf("unsupported protocol %q", v)
		}
		c.protocols[v] = true
	}
	for _, v := range p.Ports {
		if v == 0 {
			return nil, fmt.Errorf("port 0 is invalid")
		}
		c.ports[v] = true
	}
	return c, nil
}

func (c *compiledPolicy) decide(ctx DestinationContext) DestinationDecision {
	if len(c.protocols) > 0 && !c.protocols[strings.ToLower(ctx.Protocol)] {
		return DestinationDecision{Reason: "protocol denied"}
	}
	if len(c.ports) > 0 && !c.ports[ctx.Port] {
		return DestinationDecision{Reason: "port denied"}
	}
	if !c.filter.Allowed(ctx.Hostname, ctx.IP) {
		return DestinationDecision{Reason: "destination denied"}
	}
	return DestinationDecision{Allowed: true, Reason: "policy allowed"}
}

func (s *Server) destinationAllowed(ctx context.Context, principal DataPlanePrincipal, tunnel TunnelConfig, hostname string, ip netip.Addr, port uint16, protocol string) bool {
	// Policy composition is restrictive: a peer policy and a tunnel policy
	// must both approve. No policy retains the historical fixed-tunnel allow.
	for _, name := range []string{principal.Policy, tunnel.DestinationPolicy} {
		if name == "" {
			continue
		}
		p, ok := s.policies[name]
		if !ok {
			return false
		}
		d := p.decide(DestinationContext{Principal: principal, Tunnel: tunnel.Name, Hostname: hostname, IP: ip, Port: port, Protocol: protocol})
		if !d.Allowed {
			s.log.Debug("destination policy denied", "policy", name, "tunnel", tunnel.Name, "destination", ip.String(), "port", port, "reason", d.Reason)
			return false
		}
	}
	return true
}
