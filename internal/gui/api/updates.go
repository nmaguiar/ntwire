package api

import (
	"encoding/json"
	"net/http"

	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/internal/gui/updates"
)

// SetUpdater wires the application lifecycle before Serve starts.
func (s *Server) SetUpdater(c *updates.Controller, quit func()) { s.updates = c; s.quit = quit }
func (s *Server) updateRoutes() {
	for _, route := range []string{"GET /api/updates", "POST /api/updates/check", "POST /api/updates/download", "PUT /api/updates/preferences", "POST /api/updates/install"} {
		s.mux.HandleFunc(route, s.requireToken(s.handleUpdates))
	}
}
func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		http.Error(w, "updater unavailable", http.StatusServiceUnavailable)
		return
	}
	var err error
	switch r.Method + " " + r.URL.Path {
	case "POST /api/updates/check":
		err = s.updates.Check()
	case "POST /api/updates/download":
		err = s.updates.Download()
	case "PUT /api/updates/preferences":
		var p updates.Preferences
		if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&p); err == nil {
			err = s.mgr.SetUpdatePreferences(p.Disabled, p.Automatic)
			if err == nil && p.Automatic {
				status := s.updates.Status()
				if status.Available && !status.Ready && status.Busy == "" {
					err = s.updates.Download()
				}
			}
		}
	case "POST /api/updates/install":
		var req struct {
			Elevate   bool `json:"elevate"`
			Confirmed bool `json:"confirmed"`
		}
		if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
			break
		}
		if s.quit == nil {
			http.Error(w, "installation unavailable in this session", http.StatusConflict)
			return
		}
		if !req.Confirmed {
			for _, snap := range s.mgr.Snapshots() {
				if snap.State != manager.StateIdle && snap.State != manager.StateFailed {
					http.Error(w, "quitting disconnects active tunnels; confirmation required", http.StatusConflict)
					return
				}
			}
		}
		err = s.updates.InstallOnExit(req.Elevate)
		if err == nil {
			writeJSON(w, http.StatusAccepted, s.updates.Status())
			go s.quit()
			return
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	p := s.mgr.Settings()
	writeJSON(w, http.StatusOK, struct {
		Status      updates.Status      `json:"status"`
		Preferences updates.Preferences `json:"preferences"`
	}{s.updates.Status(), updates.Preferences{Disabled: p.UpdateChecksDisabled, Automatic: p.AutomaticUpdates}})
}
