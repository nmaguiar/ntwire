package manager

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

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
func (m *Manager) SmartProxyStatus() egressrouter.Status {
	status := m.smartRouter.Status()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.smartError != "" {
		status.Error = m.smartError
		status.Enabled = m.smartConfig.Enabled
		status.Listen = m.smartConfig.Listen
	}
	return status
}

func (m *Manager) SetSmartProxy(cfg egressrouter.Config) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	return m.smartRouter.Apply(cfg, func(next egressrouter.Config) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, res := range m.reservations {
			for _, addr := range res {
				if smartAddressConflict(next, addr) {
					return fmt.Errorf("smart proxy conflicts with reserved tunnel listener %s", addr)
				}
			}
		}
		persisted := config.Config{Version: config.CurrentVersion, Settings: m.settings, Profiles: m.profilesLocked(), SmartProxy: &next}
		if err := config.Save(m.configPath, persisted); err != nil {
			return err
		}
		m.smartConfig = next
		m.smartConfigured = true
		m.smartError = ""
		return nil
	})
}

func (m *Manager) SetSmartProxyPreference(id egressrouter.MemberID, exclude *bool) error {
	return m.SetSmartProxyGroupPreference("", id, exclude)
}

func (m *Manager) OpenSmartProxyBrowser() error {
	return m.OpenSmartProxyGroupBrowser("")
}

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
		Profile: browseropen.SelectProfile(filepath.Join(folder, "smart-proxy-browser"), browseropen.ProfileSettings{Name: "Smart Egress Proxy"})}
	if len(cfg.Protocols) == 1 && cfg.Protocols[0] == "http" {
		return browseropen.OpenSmartProxy(options, key, (&url.URL{Scheme: "http", Host: status.Listening}).String())
	}
	return browseropen.OpenSmartProxy(options, key, "socks5://"+status.Listening)
}

func (m *Manager) SetSmartProxyGroupPreference(group string, id egressrouter.MemberID, exclude *bool) error {
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
