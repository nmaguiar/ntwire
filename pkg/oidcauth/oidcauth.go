// Package oidcauth verifies OIDC ID tokens against configured issuers.
package oidcauth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// IssuerConfig is the subset of server configuration one issuer needs.
type IssuerConfig struct {
	Name                 string
	Issuer               string
	ClientID             string
	GroupsClaim          string
	RequireVerifiedEmail bool
}

// Identity is a verified OIDC principal.
type Identity struct {
	IssuerName string
	Subject    string
	Email      string
	Domain     string // includes the leading "@", e.g. "@corp.com"
	Groups     []string
}

// Verifiers holds one lazily-built verifier per configured issuer.
type Verifiers struct {
	issuers map[string]*issuerEntry
}

type issuerEntry struct {
	cfg IssuerConfig

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// NewVerifiers registers the given issuers and warms them up in the
// background. It never blocks on network I/O, so a temporarily unreachable
// IdP does not delay server startup; Verify self-heals on first use if the
// warmup has not completed yet.
func NewVerifiers(cfgs []IssuerConfig, log *slog.Logger) *Verifiers {
	v := &Verifiers{issuers: map[string]*issuerEntry{}}
	for _, c := range cfgs {
		e := &issuerEntry{cfg: c}
		v.issuers[c.Name] = e
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := e.ensure(ctx); err != nil && log != nil {
				log.Warn("oidc issuer discovery failed; will retry on first use", "issuer", c.Name, "error", err)
			}
		}()
	}
	return v
}

func (e *issuerEntry) ensure(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.verifier != nil {
		return e.verifier, nil
	}
	provider, err := oidc.NewProvider(ctx, e.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	e.verifier = provider.Verifier(&oidc.Config{ClientID: e.cfg.ClientID})
	return e.verifier, nil
}

// Verify checks the raw ID token's signature, audience, expiry, and
// (when configured) email_verified against the named issuer, then extracts
// the identity used for grant matching.
func (v *Verifiers) Verify(ctx context.Context, issuerName, rawToken string) (Identity, error) {
	e, ok := v.issuers[issuerName]
	if !ok {
		return Identity{}, fmt.Errorf("unknown oidc issuer %q", issuerName)
	}
	verifier, err := e.ensure(ctx)
	if err != nil {
		return Identity{}, fmt.Errorf("issuer %q unavailable: %w", issuerName, err)
	}
	idToken, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return Identity{}, err
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, err
	}
	if claims.Email == "" {
		return Identity{}, fmt.Errorf("id token missing email claim")
	}
	if e.cfg.RequireVerifiedEmail && !claims.EmailVerified {
		return Identity{}, fmt.Errorf("email not verified")
	}
	var groups []string
	if e.cfg.GroupsClaim != "" {
		var raw map[string]any
		if err := idToken.Claims(&raw); err == nil {
			if g, ok := raw[e.cfg.GroupsClaim].([]any); ok {
				for _, x := range g {
					if s, ok := x.(string); ok {
						groups = append(groups, s)
					}
				}
			}
		}
	}
	domain := ""
	if i := strings.LastIndex(claims.Email, "@"); i >= 0 {
		domain = claims.Email[i:]
	}
	return Identity{IssuerName: issuerName, Subject: idToken.Subject, Email: claims.Email, Domain: domain, Groups: groups}, nil
}
