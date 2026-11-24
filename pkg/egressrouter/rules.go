package egressrouter

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/socks"
)

// Action identifies how a routing decision handles the request.
type Action string

const (
	Proxy         Action = "proxy"
	Direct        Action = "direct"
	Deny          Action = "deny"
	Indeterminate Action = "indeterminate"
)

type Decision struct {
	Action  Action
	Members []MemberID
	rule    *Rule
	reason  string
}

func (d Decision) permits(id MemberID) bool {
	return d.Action == Proxy && (len(d.Members) == 0 || slices.Contains(d.Members, id))
}

// Rule is an ordered address, port, and ASN selector with an explicit action.
type Rule struct {
	Action   Action   `yaml:"action,omitempty" json:"action,omitempty"`
	ASNs     []uint32 `yaml:"asns,omitempty" json:"asns,omitempty"`
	prefixes []netip.Prefix
	Hosts    []string   `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Suffixes []string   `yaml:"suffixes,omitempty" json:"suffixes,omitempty"`
	CIDRs    []string   `yaml:"cidrs,omitempty" json:"cidrs,omitempty"`
	Ports    []uint16   `yaml:"ports,omitempty" json:"ports,omitempty"`
	Members  []MemberID `yaml:"members,omitempty" json:"members,omitempty"`
	Deny     bool       `yaml:"deny,omitempty" json:"deny,omitempty"`
}

func normalizeRules(routing Routing, members map[MemberID]bool) (Routing, error) {
	if routing.Unmatched != "" && routing.Unmatched != "allow" && routing.Unmatched != "deny" && routing.Unmatched != "direct" && routing.Unmatched != "proxy" {
		return routing, errors.New("routing.unmatched must be allow, proxy, direct, or deny")
	}
	if len(routing.Rules) > 64 {
		return routing, errors.New("at most 64 destination rules are supported")
	}
	routing.Rules = slices.Clone(routing.Rules)
	for i := range routing.Rules {
		rule := &routing.Rules[i]
		if len(rule.Hosts)+len(rule.Suffixes)+len(rule.CIDRs)+len(rule.Ports)+len(rule.Members)+len(rule.ASNs) > 256 {
			return routing, fmt.Errorf("destination rule %d has too many entries", i+1)
		}
		switch rule.Action {
		case "", Proxy, Direct, Deny:
		default:
			return routing, fmt.Errorf("invalid action in destination rule %d", i+1)
		}
		if rule.Deny && rule.Action != "" && rule.Action != Deny {
			return routing, fmt.Errorf("conflicting deny and action in destination rule %d", i+1)
		}
		if rule.action() != Proxy && len(rule.Members) != 0 {
			return routing, fmt.Errorf("destination rule %d cannot combine direct or deny with members", i+1)
		}
		if slices.Contains(rule.ASNs, 0) {
			return routing, fmt.Errorf("invalid ASN in destination rule %d", i+1)
		}
		rule.ASNs = slices.Clone(rule.ASNs)
		rule.prefixes = nil
		rule.Hosts = slices.Clone(rule.Hosts)
		rule.Suffixes = slices.Clone(rule.Suffixes)
		rule.CIDRs = slices.Clone(rule.CIDRs)
		rule.Ports = slices.Clone(rule.Ports)
		rule.Members = slices.Clone(rule.Members)
		for _, names := range [][]string{rule.Hosts, rule.Suffixes} {
			for j, name := range names {
				host := hostKey(Destination{Host: strings.TrimPrefix(name, ".")})
				if _, err := socks.Address(host, 1); err != nil {
					return routing, fmt.Errorf("invalid hostname in destination rule %d", i+1)
				}
				if _, err := netip.ParseAddr(host); err == nil {
					return routing, fmt.Errorf("use a CIDR for IP literals in destination rule %d", i+1)
				}
				names[j] = host
			}
		}
		for j, value := range rule.CIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Addr().Is4In6() {
				return routing, fmt.Errorf("invalid CIDR in destination rule %d", i+1)
			}
			rule.CIDRs[j] = prefix.Masked().String()
			rule.prefixes = append(rule.prefixes, prefix.Masked())
		}
		if slices.Contains(rule.Ports, 0) {
			return routing, fmt.Errorf("invalid port in destination rule %d", i+1)
		}
		for _, id := range rule.Members {
			if !members[id] {
				return routing, fmt.Errorf("destination rule %d references an unapproved member", i+1)
			}
		}
	}
	if routing.ASN != nil {
		policy := *routing.ASN
		if policy.Enabled != nil {
			enabled := *policy.Enabled
			policy.Enabled = &enabled
			if !enabled && routing.usesASN() {
				return routing, errors.New("ASN rules require ASN routing")
			}
		}
		if policy.OnUnknown != "" && policy.OnUnknown != "deny" {
			return routing, errors.New("routing.asn.on_unknown must be deny")
		}
		switch policy.HostnameResolution {
		case "", "disabled":
			if len(policy.Hosts)+len(policy.Suffixes) != 0 || policy.ResolverMember != nil {
				return routing, errors.New("ASN hostname scope requires hostname resolution")
			}
		case "local", "remote":
			scope, err := normalizeRules(Routing{Rules: []Rule{{Hosts: policy.Hosts, Suffixes: policy.Suffixes}}}, nil)
			if err != nil || len(policy.Hosts)+len(policy.Suffixes) == 0 || !routing.usesASN() {
				return routing, errors.New("ASN hostname resolution requires ASN rules and an explicit hostname scope")
			}
			policy.Hosts, policy.Suffixes = scope.Rules[0].Hosts, scope.Rules[0].Suffixes
			if policy.ResolverMember != nil {
				id := *policy.ResolverMember
				if !members[id] {
					return routing, errors.New("ASN resolver member must be explicitly approved")
				}
				policy.ResolverMember = &id
			}
			if policy.HostnameResolution == "remote" && policy.ResolverMember == nil {
				return routing, errors.New("remote ASN resolution requires a resolver member")
			}
		default:
			return routing, errors.New("invalid ASN hostname resolution mode")
		}
		routing.ASN = &policy
	}
	return routing, nil
}

func (r Rule) action() Action {
	if r.Deny {
		return Deny
	}
	if r.Action == "" {
		return Proxy
	}
	return r.Action
}

func (r Rule) nameMatches(host string) bool {
	if slices.Contains(r.Hosts, host) {
		return true
	}
	for _, suffix := range r.Suffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func (r Rule) addressMatches(host string, ip netip.Addr) bool {
	if len(r.Hosts)+len(r.Suffixes)+len(r.CIDRs) == 0 || host != "" && r.nameMatches(host) {
		return true
	}
	if ip.IsValid() {
		for _, prefix := range r.prefixes {
			if prefix.Contains(ip) {
				return true
			}
		}
		// Tests and internal callers may construct a Routing directly.
		if r.prefixes == nil {
			for _, value := range r.CIDRs {
				if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

type asnLookup func(netip.Addr) (uint32, string)

func (r Routing) decide(dst Destination, ip netip.Addr, lookup asnLookup) Decision {
	if len(r.Rules) == 0 {
		return r.unmatchedDecision()
	}
	host := ""
	if !dst.IP().IsValid() {
		host = hostKey(dst)
	}
	var number uint32
	var reason string
	lookedUp := false
	for i := range r.Rules {
		rule := &r.Rules[i]
		if len(rule.Ports) != 0 && !slices.Contains(rule.Ports, dst.Port) || !rule.addressMatches(host, ip) {
			continue
		}
		if len(rule.ASNs) != 0 {
			if !ip.IsValid() {
				return Decision{Action: Indeterminate, reason: "asn_hostname_unresolved"}
			}
			if !lookedUp {
				number, reason = lookup(ip)
				lookedUp = true
			}
			if reason != "" {
				return Decision{Action: Indeterminate, reason: reason}
			}
			if !slices.Contains(rule.ASNs, number) {
				continue
			}
		}
		return Decision{Action: rule.action(), Members: rule.Members, rule: rule}
	}
	return r.unmatchedDecision()
}

func (r Routing) unmatchedDecision() Decision {
	switch r.Unmatched {
	case "direct":
		return Decision{Action: Direct}
	case "allow", "proxy":
		return Decision{Action: Proxy}
	case "":
		if len(r.Rules) == 0 {
			return Decision{Action: Proxy}
		}
	}
	return Decision{Action: Deny}
}

func (r Routing) mayDirect() bool {
	return r.Unmatched == "direct" || slices.ContainsFunc(r.Rules, func(rule Rule) bool { return rule.action() == Direct })
}

func (r Routing) proxyPossible() bool {
	return r.Unmatched == "allow" || r.Unmatched == "proxy" || r.Unmatched == "" && len(r.Rules) == 0 ||
		slices.ContainsFunc(r.Rules, func(rule Rule) bool { return rule.action() == Proxy })
}

func (r Routing) usesASN() bool {
	return slices.ContainsFunc(r.Rules, func(rule Rule) bool { return len(rule.ASNs) != 0 })
}

func unavailableASN(netip.Addr) (uint32, string) { return 0, "asn_unavailable" }

// resolverPermitted limits disclosure before the DNS answer is known.
// Every potentially matching restricted proxy route must permit the resolver.
func (r Routing) resolverPermitted(dst Destination, id MemberID) bool {
	host := hostKey(dst)
	for _, rule := range r.Rules {
		if len(rule.Ports) != 0 && !slices.Contains(rule.Ports, dst.Port) {
			continue
		}
		nameMatches := rule.nameMatches(host) || len(rule.Hosts)+len(rule.Suffixes)+len(rule.CIDRs) == 0
		if !nameMatches && len(rule.CIDRs) == 0 {
			continue
		}
		if rule.action() == Proxy && len(rule.Members) != 0 && !slices.Contains(rule.Members, id) {
			return false
		}
		if nameMatches && len(rule.ASNs) == 0 {
			break
		}
	}
	return true
}
