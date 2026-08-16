package server

import "sort"

// SecurityCapabilities returns the explicitly enabled configuration features
// that widen ntwire's normal trust boundaries. The names are stable,
// machine-readable values intended for operator logs and the authenticated
// dashboard; they contain neither identities nor secrets.
func (s *Server) SecurityCapabilities() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return securityCapabilities(s.Config)
}

func securityCapabilities(c Config) []string {
	set := map[string]bool{}
	if c.Authorizer.WebhookURL != "" || c.Authorizer.Exec != "" {
		set["authorization_hook"] = true
	}
	if c.Relay.Enabled {
		// A relay may offer the UDP forwarding tier at registration time. It
		// keeps the relay in the data path, but still deliberately enables a
		// transport beyond WebSocket.
		set["relay_mediated_udp"] = true
	}
	if c.Relay.Enabled && c.Relay.AdvertiseDirect {
		set["direct_udp_relay_bypass"] = true
	}
	for _, tunnel := range c.Tunnels {
		if tunnel.Socks == nil {
			continue
		}
		if tunnel.Socks.AllowAll {
			set["socks_unrestricted"] = true
		}
		if tunnel.Socks.AllowBind {
			set["socks_bind"] = true
		}
	}
	capabilities := make([]string, 0, len(set))
	for capability := range set {
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	return capabilities
}

func (s *Server) logSecurityCapabilities(c Config) {
	s.log.Info("security capability status", "event", "security_capabilities", "capabilities", securityCapabilities(c))
}
