package egressrouter

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Rule limits a destination to approved members. Rules are evaluated in order.
// Alternatives within each dimension are ORed, and dimensions are ANDed.
type Rule struct {
	Hosts    []string   `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Suffixes []string   `yaml:"suffixes,omitempty" json:"suffixes,omitempty"`
	CIDRs    []string   `yaml:"cidrs,omitempty" json:"cidrs,omitempty"`
	Ports    []uint16   `yaml:"ports,omitempty" json:"ports,omitempty"`
	Members  []MemberID `yaml:"members,omitempty" json:"members,omitempty"`
	Deny     bool       `yaml:"deny,omitempty" json:"deny,omitempty"`
}

func normalizeRules(routing Routing, members map[MemberID]bool) (Routing, error) {
	if routing.Unmatched != "" && routing.Unmatched != "allow" && routing.Unmatched != "deny" {
		return routing, errors.New("routing.unmatched must be allow or deny")
	}
	if len(routing.Rules) > 64 {
		return routing, errors.New("at most 64 destination rules are supported")
	}
	routing.Rules = slices.Clone(routing.Rules)
	for i := range routing.Rules {
		rule := &routing.Rules[i]
		if len(rule.Hosts)+len(rule.Suffixes)+len(rule.CIDRs)+len(rule.Ports)+len(rule.Members) > 256 {
			return routing, fmt.Errorf("destination rule %d has too many entries", i+1)
		}
		if rule.Deny && len(rule.Members) > 0 {
			return routing, fmt.Errorf("destination rule %d cannot combine deny with members", i+1)
		}
		rule.Hosts = slices.Clone(rule.Hosts)
		rule.Suffixes = slices.Clone(rule.Suffixes)
		rule.CIDRs = slices.Clone(rule.CIDRs)
		rule.Ports = slices.Clone(rule.Ports)
		rule.Members = slices.Clone(rule.Members)
		for _, names := range [][]string{rule.Hosts, rule.Suffixes} {
			for j, name := range names {
				host := hostKey(Destination{Host: strings.TrimPrefix(name, ".")})
				if _, err := (Destination{Host: host, Port: 1}).Address(); err != nil {
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
	return routing, nil
}

func (r Rule) matches(dst Destination) bool {
	if len(r.Ports) > 0 && !slices.Contains(r.Ports, dst.Port) {
		return false
	}
	if len(r.Hosts)+len(r.Suffixes)+len(r.CIDRs) == 0 {
		return true
	}
	if ip, err := netip.ParseAddr(dst.Host); err == nil {
		for _, value := range r.CIDRs {
			prefix, _ := netip.ParsePrefix(value)
			if prefix.Contains(ip.Unmap()) {
				return true
			}
		}
		return false
	}
	host := hostKey(dst)
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

func (r Routing) destinationMembers(dst Destination) ([]MemberID, bool) {
	for _, rule := range r.Rules {
		if rule.matches(dst) {
			return rule.Members, !rule.Deny
		}
	}
	// An unset policy is automatic. Keep it distinct from an explicit deny
	// so removing the last rule restores the ordinary group routing.
	return nil, r.Unmatched == "allow" || (r.Unmatched == "" && len(r.Rules) == 0)
}

func (r Routing) permits(dst Destination, id MemberID) bool {
	members, allow := r.destinationMembers(dst)
	return allow && (len(members) == 0 || slices.Contains(members, id))
}
