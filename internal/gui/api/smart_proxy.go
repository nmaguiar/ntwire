package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

func decodeSmartProxyConfig(w http.ResponseWriter, r *http.Request) (egressrouter.Config, error) {
	var cfg egressrouter.Config
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("expected a single Smart Proxy configuration")
	}
	return cfg, nil
}

func (s *Server) smartProxyRoutes() {
	s.mux.HandleFunc("GET /api/smart-proxy", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.mgr.SmartProxyConfig())
	}))
	s.mux.HandleFunc("GET /api/smart-proxy/export", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.mgr.SmartProxyConfig()
		referenced := make(map[string]bool)
		groups := []egressrouter.Config{cfg}
		for _, group := range cfg.Groups {
			groups = append(groups, group)
		}
		for _, group := range groups {
			for _, member := range group.Egress.Members {
				referenced[member.ProfileID] = true
			}
			for _, entry := range group.Egress.Enroll {
				referenced[entry.ProfileID] = true
			}
		}
		profiles := make(map[string]string)
		for _, profile := range s.mgr.Profiles() {
			if referenced[profile.ID] {
				profiles[profile.ID] = profile.Name
			}
		}
		w.Header().Set("Content-Disposition", `attachment; filename="ntwire-smart-proxy.json"`)
		writeJSON(w, http.StatusOK, struct {
			Version  int                 `json:"version"`
			Config   egressrouter.Config `json:"smart_proxy"`
			Profiles map[string]string   `json:"profiles,omitempty"`
		}{1, cfg, profiles})
	}))
	s.mux.HandleFunc("PUT /api/smart-proxy", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		cfg, err := decodeSmartProxyConfig(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.mgr.SetSmartProxy(cfg); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, s.mgr.SmartProxyConfig())
	}))
	s.mux.HandleFunc("POST /api/smart-proxy/validate", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		cfg, err := decodeSmartProxyConfig(w, r)
		if err == nil {
			cfg, err = cfg.Normalized()
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}))
	s.mux.HandleFunc("GET /api/smart-proxy/status", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.mgr.SmartProxyStatus())
	}))
	s.mux.HandleFunc("PUT /api/smart-proxy/master", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Enabled == nil {
			http.Error(w, "Expected an enabled flag", http.StatusBadRequest)
			return
		}
		if err := s.mgr.SetSmartProxyEnabled(*body.Enabled); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, s.mgr.SmartProxyStatus())
	}))
	s.mux.HandleFunc("POST /api/smart-proxy/preference", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Group   string                `json:"group,omitempty"`
			Member  egressrouter.MemberID `json:"member"`
			Exclude *bool                 `json:"exclude"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.mgr.SetSmartProxyGroupPreference(body.Group, body.Member, body.Exclude); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	s.mux.HandleFunc("POST /api/smart-proxy/open-browser", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		if err := s.mgr.OpenSmartProxyGroupBrowser(r.URL.Query().Get("group")); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}
