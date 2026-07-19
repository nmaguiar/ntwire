package server

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"time"
)

type Config struct {
	TLS struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	Listen struct {
		HTTPS     string `yaml:"https"`
		WireGuard string `yaml:"wireguard"`
	} `yaml:"listen"`
	Auth struct {
		AuthorizedKeysDir string        `yaml:"authorized_keys_dir"`
		OIDC              OIDCConfig    `yaml:"oidc"`
		SessionTTL        time.Duration `yaml:"session_ttl"`
		MaxSessionsPerKey int           `yaml:"max_sessions_per_key"`
	} `yaml:"auth"`
	Network struct {
		TunnelCIDR         string `yaml:"tunnel_cidr"`
		AdvertisedEndpoint string `yaml:"advertised_endpoint"`
	} `yaml:"network"`
	Authorizer AuthorizerConfig `yaml:"authorizer"`
	Tunnels    []TunnelConfig   `yaml:"tunnels"`
}
type OIDCConfig struct {
	Issuers []OIDCIssuerConfig `yaml:"issuers"`
}
type OIDCIssuerConfig struct {
	Name                 string   `yaml:"name"`
	Issuer               string   `yaml:"issuer"`
	ClientID             string   `yaml:"client_id"`
	Scopes               []string `yaml:"scopes"`
	GroupsClaim          string   `yaml:"groups_claim"`
	RequireVerifiedEmail *bool    `yaml:"require_verified_email"`
}

func (c OIDCIssuerConfig) RequireVerified() bool {
	return c.RequireVerifiedEmail == nil || *c.RequireVerifiedEmail
}

type AuthorizerConfig struct {
	WebhookURL string        `yaml:"webhook_url"`
	Exec       string        `yaml:"exec"`
	Timeout    time.Duration `yaml:"timeout"`
}
type TunnelConfig struct {
	Name        string   `yaml:"name"`
	Target      string   `yaml:"target"`
	Description string   `yaml:"description"`
	VirtualPort int      `yaml:"virtual_port"`
	Allow       []string `yaml:"allow"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = yaml.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if c.Listen.HTTPS == "" {
		c.Listen.HTTPS = ":8443"
	}
	if c.Listen.WireGuard == "" {
		c.Listen.WireGuard = ":51820"
	}
	if c.Auth.SessionTTL == 0 {
		c.Auth.SessionTTL = 15 * time.Minute
	}
	if c.Authorizer.Timeout == 0 {
		c.Authorizer.Timeout = 5 * time.Second
	}
	if c.Auth.AuthorizedKeysDir == "" && len(c.Auth.OIDC.Issuers) == 0 {
		return c, fmt.Errorf("at least one of auth.authorized_keys_dir or auth.oidc.issuers is required")
	}
	seenIssuers := map[string]bool{}
	for i := range c.Auth.OIDC.Issuers {
		iss := &c.Auth.OIDC.Issuers[i]
		if iss.Name == "" || iss.Issuer == "" || iss.ClientID == "" {
			return c, fmt.Errorf("auth.oidc.issuers require name, issuer, and client_id")
		}
		if seenIssuers[iss.Name] {
			return c, fmt.Errorf("duplicate oidc issuer %q", iss.Name)
		}
		seenIssuers[iss.Name] = true
		if len(iss.Scopes) == 0 {
			iss.Scopes = []string{"openid", "email", "profile"}
		}
	}
	if c.Network.TunnelCIDR == "" {
		c.Network.TunnelCIDR = "100.64.0.0/16"
	}
	if _, _, e = net.ParseCIDR(c.Network.TunnelCIDR); e != nil {
		return c, fmt.Errorf("network.tunnel_cidr: %w", e)
	}
	seen := map[string]bool{}
	for _, t := range c.Tunnels {
		if t.Name == "" || t.Target == "" {
			return c, fmt.Errorf("tunnels require name and target")
		}
		if seen[t.Name] {
			return c, fmt.Errorf("duplicate tunnel %q", t.Name)
		}
		seen[t.Name] = true
		if t.VirtualPort < 1 || t.VirtualPort > 65535 {
			return c, fmt.Errorf("tunnel %q requires virtual_port in 1..65535", t.Name)
		}
	}
	return c, nil
}
