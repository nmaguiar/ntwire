package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/pkg/client"
)

func applyProxyRequest(p *config.Profile, previous config.Profile, body profileRequest) error {
	if body.KeepProxyURL {
		p.HTTPSProxy = previous.HTTPSProxy
	}
	// Never interpret a returned redaction as a replacement password. Older
	// clients may round-trip the display URL; retain it only if unchanged.
	if !body.ReplaceProxyURL {
		if previous.HTTPSProxy != "" && p.HTTPSProxy == client.RedactProxyURL(previous.HTTPSProxy) {
			p.HTTPSProxy = previous.HTTPSProxy
		} else if strings.Contains(p.HTTPSProxy, "********") || strings.Contains(p.HTTPSProxy, ":xxxxx@") {
			return fmt.Errorf("enter a complete proxy URL to replace saved credentials")
		}
	}
	if p.HTTPSProxy != "" {
		return client.ValidateProxyURL(p.HTTPSProxy)
	}
	return nil
}

// Preview accepts an unsaved profile, uses only the core process environment,
// and never makes a network request. The route has the normal loopback token gate.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	body, err := decodeProfileRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid proxy diagnostics request"))
		return
	}
	p := body.Profile
	previous := config.Profile{}
	if p.ID != "" {
		snap, ok := s.mgr.Snapshot(p.ID)
		if !ok {
			http.NotFound(w, r)
			return
		}
		previous = snap.Profile
	}
	if err := applyProxyRequest(&p, previous, body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, client.DiagnoseProxy(p.Server, client.Options{HTTPSProxy: p.HTTPSProxy, NoSystemProxy: p.NoSystemProxy}))
}
