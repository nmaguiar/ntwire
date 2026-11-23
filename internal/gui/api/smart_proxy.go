package api

import (
	"encoding/json"
	"net/http"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

func (s *Server) smartProxyRoutes() {
	s.mux.HandleFunc("GET /api/smart-proxy", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.mgr.SmartProxyConfig())
	}))
	s.mux.HandleFunc("PUT /api/smart-proxy", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
		var cfg egressrouter.Config
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.mgr.SetSmartProxy(cfg); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, s.mgr.SmartProxyConfig())
	}))
	s.mux.HandleFunc("GET /api/smart-proxy/status", s.requireToken(func(w http.ResponseWriter, r *http.Request) {
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
