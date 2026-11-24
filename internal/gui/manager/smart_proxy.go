package manager

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

type smartEgressHandle interface {
	EgressCandidate(egressrouter.Member) egressrouter.Candidate
}

func (m *Manager) smartCandidate(member egressrouter.Member) egressrouter.Candidate {
	m.mu.Lock()
	s := m.sessions[member.ProfileID]
	if s == nil {
		m.mu.Unlock()
		return egressrouter.Candidate{Reason: "profile_missing"}
	}
	handle := s.handle
	server := s.profile.Server
	m.mu.Unlock()
	want, err := client.NormalizeServerURL(member.ExpectedServer)
	current, currentErr := client.NormalizeServerURL(server)
	if err != nil || currentErr != nil || want != current {
		return egressrouter.Candidate{Reason: "server_identity_changed"}
	}
	source, ok := handle.(smartEgressHandle)
	if !ok {
		return egressrouter.Candidate{Reason: "profile_disconnected"}
	}
	return source.EgressCandidate(member)
}

func (m *Manager) SmartProxyConfig() egressrouter.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, _ := m.smartConfig.Normalized()
	return cfg
}

type SmartProxyStatus struct {
	egressrouter.Status
	MasterEnabled bool `json:"master_enabled"`
}

func (m *Manager) SmartProxyStatus() SmartProxyStatus {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	status := m.smartRouter.Status()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.smartEnabled || m.smartError != "" {
		status.Error = m.smartError
		status.Enabled = m.smartConfig.Enabled
		status.Listen = m.smartConfig.Listen
		if len(m.smartConfig.Groups) != 0 {
			if status.Groups == nil {
				status.Groups = make(map[string]egressrouter.Status, len(m.smartConfig.Groups))
			}
			for name, group := range m.smartConfig.Groups {
				current := status.Groups[name]
				current.Enabled, current.Listen = group.Enabled, group.Listen
				status.Groups[name] = current
			}
		}
	}
	return SmartProxyStatus{Status: status, MasterEnabled: m.smartEnabled}
}

type SmartProxyGroupState struct {
	Name      string
	Enabled   bool
	Listening bool
}

func (m *Manager) SmartProxyGroups() []SmartProxyGroupState {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	m.mu.Lock()
	cfg, enabled := m.smartConfig, m.smartEnabled
	m.mu.Unlock()
	if !enabled {
		return nil
	}
	listening := m.smartRouter.ListeningGroups()
	groups := make([]SmartProxyGroupState, 0, len(cfg.Groups)+1)
	groups = append(groups, SmartProxyGroupState{"default", cfg.Enabled, slices.Contains(listening, "default")})
	for name, group := range cfg.Groups {
		groups = append(groups, SmartProxyGroupState{name, group.Enabled, slices.Contains(listening, name)})
	}
	slices.SortFunc(groups[1:], func(a, b SmartProxyGroupState) int { return strings.Compare(a.Name, b.Name) })
	return groups
}

func (m *Manager) SetSmartProxy(cfg egressrouter.Config) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	return m.applySmartProxy(cfg, m.smartProxyEnabled())
}

func (m *Manager) smartProxyEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.smartEnabled
}

func (m *Manager) SetSmartProxyEnabled(enabled bool) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	return m.applySmartProxy(m.SmartProxyConfig(), enabled)
}

// SetSmartProxyGroupEnabled changes only the group's saved activation flag.
func (m *Manager) SetSmartProxyGroupEnabled(name string, enabled bool) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if !m.smartProxyEnabled() {
		return fmt.Errorf("Smart Proxy is disabled")
	}
	cfg := m.SmartProxyConfig()
	if name == "default" {
		cfg.Enabled = enabled
	} else {
		group, ok := cfg.Groups[name]
		if !ok {
			return fmt.Errorf("unknown Smart Proxy group %q", name)
		}
		group.Enabled = enabled
		cfg.Groups[name] = group
	}
	return m.applySmartProxy(cfg, true)
}

func runningSmartProxyConfig(cfg egressrouter.Config, enabled bool) egressrouter.Config {
	if enabled {
		return cfg
	}
	cfg.Enabled = false
	cfg.PACListen = ""
	cfg.Groups = maps.Clone(cfg.Groups)
	for name, group := range cfg.Groups {
		group.Enabled = false
		cfg.Groups[name] = group
	}
	return cfg
}

func (m *Manager) applySmartProxy(cfg egressrouter.Config, enabled bool) error {
	saved, err := cfg.Normalized()
	if err != nil {
		return err
	}
	return m.smartRouter.Apply(runningSmartProxyConfig(saved, enabled), func(next egressrouter.Config) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, res := range m.reservations {
			for _, addr := range res {
				if smartAddressConflict(next, addr) {
					return fmt.Errorf("smart proxy conflicts with reserved tunnel listener %s", addr)
				}
			}
		}
		persisted := m.configLocked()
		persisted.SmartProxy = &saved
		persisted.SmartProxyEnabled = enabled
		if err := config.Save(m.configPath, persisted); err != nil {
			return err
		}
		m.smartConfig = saved
		m.smartEnabled = enabled
		m.smartConfigured = true
		m.smartError = ""
		return nil
	})
}

func (m *Manager) SetSmartProxyPreference(id egressrouter.MemberID, exclude *bool) error {
	return m.SetSmartProxyGroupPreference("", id, exclude)
}

var openSmartProxyBrowser = browseropen.OpenSmartProxy

func (m *Manager) OpenSmartProxyGroupBrowser(group string) error {
	if group == "" {
		group = "default"
	}
	status, cfg, _ := m.smartRouter.Group(group)
	if status.Listening == "" {
		return fmt.Errorf("smart proxy is not listening")
	}
	settings := m.Settings()
	folder := settings.BrowserProfilesDir
	if folder == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		folder = filepath.Join(home, ".ntwire")
	}
	path, err := filepath.Abs(m.configPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(path))
	key := fmt.Sprintf("aggregate:%x", sum[:16])
	if group != "default" {
		key += ":" + group
	}
	options := browseropen.LaunchOptions{Executable: settings.BrowserExecutable, ExtraArgs: settings.BrowserArgs,
		BlockLocalDNS: cfg.BrowserBlockLocalDNS,
		Profile:       browseropen.SelectProfile(filepath.Join(folder, "smart-proxy-browser"), browseropen.ProfileSettings{Name: "Smart Proxy"})}
	// Chromium sends IP literals in SOCKS5's domain field. Prefer HTTP
	// when available so those requests reach the same destination rules.
	if slices.Contains(cfg.Protocols, "http") {
		return openSmartProxyBrowser(options, key, (&url.URL{Scheme: "http", Host: status.Listening}).String())
	}
	return openSmartProxyBrowser(options, key, "socks5://"+status.Listening)
}

func (m *Manager) SetSmartProxyGroupPreference(group string, id egressrouter.MemberID, exclude *bool) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if !m.smartProxyEnabled() {
		return fmt.Errorf("Smart Proxy is disabled")
	}
	return m.smartRouter.SetPreference(group, id, exclude)
}

func smartAddressConflict(cfg egressrouter.Config, addr string) bool {
	if cfg.Enabled && addressesConflict(cfg.Listen, addr) || cfg.PACListen != "" && addressesConflict(cfg.PACListen, addr) {
		return true
	}
	for _, g := range cfg.Groups {
		if g.Enabled && addressesConflict(g.Listen, addr) {
			return true
		}
	}
	return false
}

func (m *Manager) discoverEgress(enrollment egressrouter.Enrollment) []string {
	m.mu.Lock()
	s := m.sessions[enrollment.ProfileID]
	if s == nil {
		m.mu.Unlock()
		return nil
	}
	owner, ok := s.handle.(interface {
		DiscoverEgress(egressrouter.Enrollment) []string
	})
	server := s.profile.Server
	m.mu.Unlock()
	want, err := client.NormalizeServerURL(enrollment.ExpectedServer)
	actual, serverErr := client.NormalizeServerURL(server)
	if !ok || err != nil || serverErr != nil || want != actual {
		return nil
	}
	return owner.DiscoverEgress(enrollment)
}
