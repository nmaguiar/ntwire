package egressrouter

import (
	"fmt"
	"slices"
	"strings"
)

// Enrollment approves a server's explicitly advertised egress policy class.
type Enrollment struct {
	ProfileID      string `yaml:"profile_id" json:"profile_id"`
	ExpectedServer string `yaml:"expected_server" json:"expected_server"`
	EgressClass    string `yaml:"egress_class" json:"egress_class"`
	Priority       int    `yaml:"priority" json:"priority"`
}

func (e Enrollment) Member(name string) Member {
	return Member{ProfileID: e.ProfileID, ExpectedServer: e.ExpectedServer, EgressClass: e.EgressClass, Tunnel: name, Priority: e.Priority}
}

type Discover func(Enrollment) []string

func (c Config) Enrollments() []Enrollment {
	entries := slices.Clone(c.Egress.Enroll)
	for _, g := range c.Groups {
		for _, e := range g.Egress.Enroll {
			if !slices.Contains(entries, e) {
				entries = append(entries, e)
			}
		}
	}
	return entries
}

func (c Config) approves(m Member) bool {
	if slices.Contains(c.Egress.Members, m) {
		return true
	}
	if m.EgressClass == "" || m.Tunnel == "" || len(m.Tunnel) > 255 {
		return false
	}
	for _, entry := range c.Egress.Enroll {
		if entry.Member(m.Tunnel) == m {
			return true
		}
	}
	return false
}

func (c Config) resolvedMembers(discover Discover) []Member {
	if discover == nil || len(c.Egress.Enroll) == 0 {
		return c.Egress.Members
	}
	members := slices.Clone(c.Egress.Members)
	seen := make(map[MemberID]bool, len(members))
	for _, m := range members {
		seen[m.ID()] = true
	}
	for _, entry := range c.Egress.Enroll {
		names := slices.Clone(discover(entry))
		slices.Sort(names)
		for _, name := range names {
			if len(members) >= 64 {
				return members
			}
			m := entry.Member(name)
			if seen[m.ID()] || name == "" || len(name) > 255 || strings.ContainsAny(name, "\x00\r\n") {
				continue
			}
			seen[m.ID()] = true
			members = append(members, m)
		}
	}
	return members
}

func normalizeEnrollments(entries []Enrollment) ([]Enrollment, error) {
	if len(entries) > 16 {
		return nil, fmt.Errorf("at most 16 enrollment entries are supported per group")
	}
	entries = slices.Clone(entries)
	seen := map[[2]string]bool{}
	for _, entry := range entries {
		k := [2]string{entry.ProfileID, entry.EgressClass}
		if !ValidProfileID(entry.ProfileID) || !ValidProfileID(entry.EgressClass) || seen[k] ||
			!validExpectedServer(entry.ExpectedServer, true) {
			return nil, fmt.Errorf("enrollment requires a unique profile and class with an explicitly trusted HTTPS server")
		}
		seen[k] = true
	}
	return entries, nil
}
