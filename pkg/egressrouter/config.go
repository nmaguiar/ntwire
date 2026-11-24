// Package egressrouter serves one loopback proxy over explicitly approved SOCKS egresses.
package egressrouter

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

type Config struct {
	Groups    map[string]Config `yaml:"groups,omitempty" json:"groups,omitempty"`
	PACListen string            `yaml:"pac_listen,omitempty" json:"pac_listen,omitempty"`
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Listen    string            `yaml:"listen" json:"listen"`
	Protocols []string          `yaml:"protocols" json:"protocols"`
	Egress    Membership        `yaml:"egress" json:"egress"`
	Failover  Failover          `yaml:"failover" json:"failover"`
	Health    Health            `yaml:"health" json:"health"`
	Routing   Routing           `yaml:"routing" json:"routing"`
	Limits    Limits            `yaml:"limits" json:"limits"`

	BrowserBlockLocalDNS bool `yaml:"browser_block_local_dns,omitempty" json:"browser_block_local_dns,omitempty"`
}

type Membership struct {
	Enroll    []Enrollment `yaml:"enroll,omitempty" json:"enroll,omitempty"`
	Selection string       `yaml:"selection" json:"selection"`
	Members   []Member     `yaml:"members" json:"members"`
}
type Member struct {
	EgressClass    string `yaml:"egress_class,omitempty" json:"egress_class,omitempty"`
	ProfileID      string `yaml:"profile_id" json:"profile_id"`
	Tunnel         string `yaml:"tunnel" json:"tunnel"`
	ExpectedServer string `yaml:"expected_server" json:"expected_server"`
	Priority       int    `yaml:"priority" json:"priority"`
}
type MemberID struct {
	ProfileID string `json:"profile_id" yaml:"profile_id"`
	Tunnel    string `json:"tunnel" yaml:"tunnel"`
}

func (m Member) ID() MemberID { return MemberID{m.ProfileID, m.Tunnel} }

type Failover struct {
	Racing         bool          `yaml:"racing,omitempty" json:"racing,omitempty"`
	RaceDelay      time.Duration `yaml:"race_delay,omitempty" json:"race_delay,omitempty"`
	Enabled        *bool         `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MaxAttempts    int           `yaml:"max_attempts" json:"max_attempts"`
	AttemptTimeout time.Duration `yaml:"attempt_timeout" json:"attempt_timeout"`
	TotalTimeout   time.Duration `yaml:"total_timeout" json:"total_timeout"`
}
type Health struct {
	ProbeTargets     []string      `yaml:"probe_targets" json:"probe_targets"`
	Interval         time.Duration `yaml:"interval" json:"interval"`
	FailureThreshold int           `yaml:"failure_threshold" json:"failure_threshold"`
	RecoveryInterval time.Duration `yaml:"recovery_interval" json:"recovery_interval"`
}
type Routing struct {
	UDPAssociate      bool          `yaml:"udp_associate,omitempty" json:"udp_associate,omitempty"`
	UDPIdleTimeout    time.Duration `yaml:"udp_idle_timeout,omitempty" json:"udp_idle_timeout,omitempty"`
	AffinityScope     string        `yaml:"affinity_scope,omitempty" json:"affinity_scope,omitempty"`
	Rules             []Rule        `yaml:"rules,omitempty" json:"rules,omitempty"`
	Unmatched         string        `yaml:"unmatched,omitempty" json:"unmatched,omitempty"`
	AffinityTTL       time.Duration `yaml:"affinity_ttl" json:"affinity_ttl"`
	HysteresisPercent int           `yaml:"hysteresis_percent" json:"hysteresis_percent"`
}
type Limits struct {
	Connections        int `yaml:"connections" json:"connections"`
	ConcurrentAttempts int `yaml:"concurrent_attempts" json:"concurrent_attempts"`
}

var profileID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func ValidProfileID(id string) bool { return profileID.MatchString(id) }

func (c Config) Normalized() (Config, error) {
	cfg, err := c.normalizedGroup()
	if err != nil {
		return cfg, err
	}
	if len(c.Groups) > 16 {
		return cfg, errors.New("at most 16 named smart proxy groups are supported")
	}
	if len(c.Groups) > 0 {
		cfg.Groups = make(map[string]Config, len(c.Groups))
	}
	if cfg.PACListen != "" {
		addr, err := netip.ParseAddrPort(cfg.PACListen)
		if err != nil || !addr.Addr().IsLoopback() || addr.Addr().Zone() != "" || addr.Port() == 0 {
			return cfg, errors.New("smart proxy PAC listen must be a numeric loopback IP and nonzero port")
		}
		cfg.PACListen = addr.String()
	}
	seen := map[string]bool{}
	if cfg.Enabled {
		seen[cfg.Listen] = true
	}
	if cfg.PACListen != "" {
		if seen[cfg.PACListen] {
			return cfg, errors.New("PAC and proxy listeners must use distinct addresses")
		}
		seen[cfg.PACListen] = true
	}
	for name, group := range c.Groups {
		if !ValidProfileID(name) || name == "default" || len(group.Groups) > 0 || group.PACListen != "" {
			return cfg, errors.New("invalid or nested smart proxy group")
		}
		group, err = group.normalizedGroup()
		if err != nil {
			return cfg, fmt.Errorf("smart proxy group %s: %w", name, err)
		}
		if group.Enabled {
			if seen[group.Listen] {
				return cfg, errors.New("enabled smart proxy groups must use distinct listen addresses")
			}
			seen[group.Listen] = true
		}
		cfg.Groups[name] = group
	}
	return cfg, nil
}

func (c Config) AnyEnabled() bool {
	if c.Enabled {
		return true
	}
	for _, g := range c.Groups {
		if g.Enabled {
			return true
		}
	}
	return false
}

func (c Config) Members() []Member {
	members := slices.Clone(c.Egress.Members)
	for _, g := range c.Groups {
		for _, m := range g.Egress.Members {
			if !slices.Contains(members, m) {
				members = append(members, m)
			}
		}
	}
	return members
}

func (c Config) normalizedGroup() (Config, error) {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:1080"
	}
	addr, err := netip.ParseAddrPort(c.Listen)
	if err != nil || !addr.Addr().IsLoopback() || addr.Addr().Zone() != "" || addr.Port() == 0 {
		return c, errors.New("smart proxy listen must be a numeric loopback IP and nonzero port")
	}
	c.Listen = addr.String()
	c.Protocols = slices.Clone(c.Protocols)
	if len(c.Protocols) == 0 {
		c.Protocols = []string{"socks5", "http"}
	}
	for i, p := range c.Protocols {
		if (p != "http" && p != "socks5") || slices.Contains(c.Protocols[:i], p) {
			return c, errors.New("invalid or duplicate proxy protocol")
		}
	}
	if c.Egress.Selection == "" {
		c.Egress.Selection = "sticky-fastest"
	}
	switch c.Egress.Selection {
	case "priority", "round-robin", "fastest-healthy", "sticky-fastest", "destination-aware":
	default:
		return c, errors.New("unknown smart proxy selection strategy")
	}
	c.Egress.Members = slices.Clone(c.Egress.Members)
	c.Health.ProbeTargets = slices.Clone(c.Health.ProbeTargets)
	if len(c.Egress.Members) > 64 || len(c.Health.ProbeTargets) > 8 {
		return c, errors.New("at most 64 members and 8 probe targets are supported")
	}
	seen := map[MemberID]bool{}
	for _, m := range c.Egress.Members {
		if !validExpectedServer(m.ExpectedServer, false) || m.EgressClass != "" && (!ValidProfileID(m.EgressClass) || !validExpectedServer(m.ExpectedServer, true)) {
			return c, errors.New("invalid expected_server or egress_class")
		}
		if !ValidProfileID(m.ProfileID) || m.Tunnel == "" || len(m.Tunnel) > 255 || m.ExpectedServer == "" || seen[m.ID()] {
			return c, fmt.Errorf("invalid or duplicate smart proxy member for profile %q", m.ProfileID)
		}
		seen[m.ID()] = true
	}
	c.Egress.Enroll, err = normalizeEnrollments(c.Egress.Enroll)
	if err != nil {
		return c, err
	}
	c.Routing, err = normalizeRules(c.Routing, seen)
	if err != nil {
		return c, err
	}
	if c.Routing.AffinityScope == "" {
		c.Routing.AffinityScope = "host"
	}
	if c.Routing.AffinityScope != "host" && c.Routing.AffinityScope != "group" {
		return c, errors.New("affinity_scope must be host or group")
	}
	if c.Routing.AffinityScope == "group" && c.Egress.Selection != "sticky-fastest" {
		return c, errors.New("group affinity requires sticky-fastest")
	}
	if c.Routing.UDPAssociate && !slices.Contains(c.Protocols, "socks5") {
		return c, errors.New("UDP ASSOCIATE requires SOCKS5")
	}
	for _, target := range c.Health.ProbeTargets {
		if _, err := parseProbe(target); err != nil {
			return c, err
		}
	}
	enabled := true
	if c.Failover.Enabled != nil {
		enabled = *c.Failover.Enabled
	}
	c.Failover.Enabled = &enabled
	defaults := []struct {
		value         *int
		fallback, max int
	}{
		{&c.Failover.MaxAttempts, 3, 64}, {&c.Health.FailureThreshold, 3, 32},
		{&c.Routing.HysteresisPercent, 20, 99}, {&c.Limits.Connections, 256, 4096}, {&c.Limits.ConcurrentAttempts, 32, 1024},
	}
	for _, d := range defaults {
		if *d.value == 0 {
			*d.value = d.fallback
		}
		if *d.value < 1 || *d.value > d.max {
			return c, errors.New("smart proxy limit out of range")
		}
	}
	durations := []struct {
		value              *time.Duration
		fallback, min, max time.Duration
	}{
		{&c.Failover.AttemptTimeout, 3 * time.Second, time.Millisecond, time.Minute},
		{&c.Failover.TotalTimeout, 10 * time.Second, time.Millisecond, 2 * time.Minute},
		{&c.Failover.RaceDelay, 200 * time.Millisecond, time.Millisecond, 5 * time.Second},
		{&c.Health.Interval, 30 * time.Second, time.Second, time.Hour},
		{&c.Health.RecoveryInterval, 30 * time.Second, time.Second, time.Hour},
		{&c.Routing.AffinityTTL, 5 * time.Minute, time.Second, time.Hour},
		{&c.Routing.UDPIdleTimeout, 2 * time.Minute, time.Second, time.Hour},
	}
	for _, d := range durations {
		if *d.value == 0 {
			*d.value = d.fallback
		}
		if *d.value < d.min || *d.value > d.max {
			return c, errors.New("smart proxy duration out of range")
		}
	}
	return c, nil
}

func validExpectedServer(expected string, requireHTTPS bool) bool {
	if expected == "" {
		return false
	}
	if !strings.Contains(expected, "://") {
		expected = "https://" + expected
	}
	server, err := url.Parse(expected)
	return err == nil && server.Hostname() != "" && server.User == nil && server.RawQuery == "" && server.Fragment == "" &&
		(server.Scheme == "https" || !requireHTTPS && server.Scheme == "http") &&
		(server.Path == "" || server.Path == "/")
}
