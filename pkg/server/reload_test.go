package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestReloadDropsSSHSessionWhenKeyRevoked(t *testing.T) {
	s, _, authLine := newTestServer(t, []TunnelConfig{
		{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"*"}},
	})
	fp := "SHA256:whatever-does-not-matter-for-this-test"
	session := s.sessions.Create(CreateParams{Method: "ssh", Identity: fp, Fingerprint: fp, Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Minute})

	// Revoke by emptying the authorized_keys_dir, then reload with the same config.
	entries, _ := os.ReadDir(s.Config.Auth.AuthorizedKeysDir)
	for _, e := range entries {
		_ = os.Remove(filepath.Join(s.Config.Auth.AuthorizedKeysDir, e.Name()))
	}
	s.Reload(s.Config)

	if _, ok := s.sessions.Get(session.Token); ok {
		t.Fatal("session for a revoked key should be dropped on reload")
	}
	_ = authLine
}

func TestReloadNarrowsSSHGrantsWhenTunnelAllowChanges(t *testing.T) {
	s, _, _ := newTestServer(t, []TunnelConfig{
		{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"*"}},
	})
	fp := "SHA256:some-fingerprint"
	session := s.sessions.Create(CreateParams{Method: "ssh", Identity: fp, Fingerprint: fp, Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Minute})

	narrowed := s.Config
	narrowed.Tunnels = []TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"someone-else"}}}
	s.Reload(narrowed)

	if _, ok := s.sessions.Get(session.Token); ok {
		t.Fatal("session should be dropped once its only tunnel grant is revoked")
	}
}

func TestReloadDropsOIDCSessionWhenIssuerRemoved(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := Config{Tunnels: []TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"@corp.com"}}}}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := New(cfg, nil)

	session := s.sessions.Create(CreateParams{Method: "oidc", Identity: "alice@corp.com", Issuer: "test", Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Minute})

	withoutIssuer := s.Config
	withoutIssuer.Auth.OIDC.Issuers = nil
	s.Reload(withoutIssuer)

	if _, ok := s.sessions.Get(session.Token); ok {
		t.Fatal("oidc session should be dropped once its issuer is removed from config")
	}
}

func TestReloadNarrowsOIDCGrantsWhenDomainRevoked(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := Config{Tunnels: []TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"@corp.com"}}}}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := New(cfg, nil)

	session := s.sessions.Create(CreateParams{Method: "oidc", Identity: "alice@corp.com", Issuer: "test", Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Minute})

	narrowed := s.Config
	narrowed.Tunnels = []TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"@other.com"}}}
	s.Reload(narrowed)

	if _, ok := s.sessions.Get(session.Token); ok {
		t.Fatal("oidc session should be dropped once its domain grant is revoked")
	}
}

func TestReloadKeepsOIDCSessionWhenStillGranted(t *testing.T) {
	idp := newFakeIdP(t)
	cfg := Config{Tunnels: []TunnelConfig{{Name: "reports", Target: "x:1", VirtualPort: 1, Allow: []string{"@corp.com"}}}}
	cfg.Auth.SessionTTL = time.Minute
	cfg.Auth.OIDC.Issuers = []OIDCIssuerConfig{{Name: "test", Issuer: idp.server.URL, ClientID: "client-1"}}
	s := New(cfg, nil)

	session := s.sessions.Create(CreateParams{Method: "oidc", Identity: "alice@corp.com", Issuer: "test", Tunnels: []protocol.Tunnel{{Name: "reports"}}, TTL: time.Minute})

	s.Reload(s.Config)

	if _, ok := s.sessions.Get(session.Token); !ok {
		t.Fatal("oidc session should survive a reload that keeps its grants")
	}
}
