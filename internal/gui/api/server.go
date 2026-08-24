// Package api serves ntwire-gui's settings backend: a token-authenticated
// loopback HTTP+SSE API in front of a *manager.Manager, mirroring the
// pattern pkg/client's Connection.startWebUI already uses for its local
// status dashboard (random token in a query parameter, 404 rather than 401
// on rejection so as not to confirm endpoint existence to an unauthenticated
// caller). A settings window -- native webview or plain browser -- is just
// an HTTP client of this server; nothing here depends on how it's rendered.
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/internal/gui/webui"
	"github.com/nmaguiar/ntwire/pkg/browseropen"
)

// Server is the loopback HTTP+SSE API in front of a Manager.
type Server struct {
	mgr   *manager.Manager
	token string
	mux   *http.ServeMux
	srv   *http.Server
	ln    net.Listener
	fsys  fs.FS
}

// New binds a 127.0.0.1 loopback listener on an OS-assigned port and
// generates a fresh random token. The server does not start serving until
// Serve is called.
func New(mgr *manager.Manager) (*Server, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("gui/api: %w", err)
	}
	fsys, err := webui.Files()
	if err != nil {
		return nil, fmt.Errorf("gui/api: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{
		mgr:   mgr,
		token: base64.RawURLEncoding.EncodeToString(b),
		ln:    ln,
		fsys:  fsys,
	}
	s.mux = http.NewServeMux()
	s.routes()
	s.srv = &http.Server{Handler: s.mux, ReadHeaderTimeout: 5 * time.Second}
	return s, nil
}

// Serve blocks, accepting connections until Close is called (which makes it
// return http.ErrServerClosed).
func (s *Server) Serve() error { return s.srv.Serve(s.ln) }

// Close shuts the server down.
func (s *Server) Close() error { return s.srv.Close() }

// Addr is the loopback address the server is listening on, e.g.
// "127.0.0.1:54321".
func (s *Server) Addr() string { return s.ln.Addr().String() }

// URL is the base address a settings window should be pointed at, with the
// access token embedded as a query parameter -- matching
// client.Connection.UIURL's shape.
func (s *Server) URL() string { return fmt.Sprintf("http://%s/?token=%s", s.Addr(), s.token) }

// Token is the raw access token, for callers (the tray process spawning a
// settings window) that need to pass it out-of-band -- via an environment
// variable or stdin, never in argv, where it would be visible to any local
// user via ps or /proc/<pid>/cmdline.
func (s *Server) Token() string { return s.token }

func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != s.token {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

func (s *Server) routes() {
	// The settings UI itself. Token-gated like every other route -- the
	// page's own script reads its token back out of location.search for
	// subsequent /api/* fetches, the same convention pkg/client's status
	// page uses.
	s.mux.Handle("GET /", s.requireToken(http.FileServer(http.FS(s.fsys)).ServeHTTP))
	s.mux.HandleFunc("GET /api/schema", s.requireToken(s.handleSchema))
	s.mux.HandleFunc("GET /api/profiles", s.requireToken(s.handleListProfiles))
	s.mux.HandleFunc("POST /api/profiles", s.requireToken(s.handleCreateProfile))
	s.mux.HandleFunc("PUT /api/profiles/{id}", s.requireToken(s.handleUpdateProfile))
	s.mux.HandleFunc("DELETE /api/profiles/{id}", s.requireToken(s.handleDeleteProfile))
	s.mux.HandleFunc("POST /api/profiles/{id}/connect", s.requireToken(s.handleConnect))
	s.mux.HandleFunc("POST /api/profiles/{id}/disconnect", s.requireToken(s.handleDisconnect))
	s.mux.HandleFunc("POST /api/profiles/{id}/probe", s.requireToken(s.handleProbe))
	s.mux.HandleFunc("POST /api/profiles/{id}/logout", s.requireToken(s.handleLogout))
	s.mux.HandleFunc("PUT /api/profiles/{id}/tunnels/{name}", s.requireToken(s.handleReplacePort))
	s.mux.HandleFunc("POST /api/profiles/{id}/tunnels/{name}/open-browser", s.requireToken(s.handleOpenBrowser))
	s.mux.HandleFunc("POST /api/profiles/{id}/tunnels/{name}/reset-browser-profile", s.requireToken(s.handleResetBrowserProfile))
	s.mux.HandleFunc("GET /api/browser-profiles", s.requireToken(s.handleListBrowserProfiles))
	s.mux.HandleFunc("POST /api/browser-profiles/clean", s.requireToken(s.handleCleanBrowserProfiles))
	s.mux.HandleFunc("POST /api/prompts/{id}/trust", s.requireToken(s.handleAnswerTrust))
	s.mux.HandleFunc("POST /api/prompts/{id}/passphrase", s.requireToken(s.handleAnswerPassphrase))
	s.mux.HandleFunc("POST /api/keygen", s.requireToken(s.handleKeygen))
	s.mux.HandleFunc("GET /api/events", s.requireToken(s.handleEvents))
	s.mux.HandleFunc("GET /api/settings", s.requireToken(s.handleGetSettings))
	s.mux.HandleFunc("PUT /api/settings", s.requireToken(s.handleSetSettings))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Snapshots())
}

func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	body, err := decodeProfileRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	p := body.Profile
	if body.OIDCClientSecret != nil {
		p.OIDCClientSecret = *body.OIDCClientSecret
	}
	p.ID = "" // a client does not choose its own ID; AddProfile assigns one
	added, err := s.mgr.AddProfile(p)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, added)
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body, err := decodeProfileRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	p := body.Profile
	previous, ok := s.mgr.Snapshot(id)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Errorf("gui: no such profile %q", id))
		return
	}
	// Profile reads intentionally omit OIDCClientSecret. A blank value from
	// the write-only form therefore means "keep the saved secret"; an API
	// caller can explicitly clear it with ClearOIDCClientSecret.
	p.OIDCClientSecret = previous.Profile.OIDCClientSecret
	if body.ClearOIDCClientSecret {
		p.OIDCClientSecret = ""
	} else if body.OIDCClientSecret != nil && *body.OIDCClientSecret != "" {
		p.OIDCClientSecret = *body.OIDCClientSecret
	}
	p.ID = id
	if err := s.mgr.UpdateProfile(p); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// profileRequest is the write shape of a GUI profile. OIDCClientSecret is
// deliberately separate from config.Profile: Profile's JSON form is used for
// every API response and must never contain the saved secret.
type profileRequest struct {
	config.Profile
	OIDCClientSecret      *string `json:"OIDCClientSecret"`
	ClearOIDCClientSecret bool    `json:"ClearOIDCClientSecret"`
}

func decodeProfileRequest(r *http.Request) (profileRequest, error) {
	var body profileRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return profileRequest{}, err
	}
	return body, nil
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.RemoveProfile(r.PathValue("id")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Connect(r.PathValue("id")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Disconnect(r.PathValue("id")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReplacePort(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LocalPort int    `json:"local_port"`
		LocalHost string `json:"local_host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	addr, err := s.mgr.ReplaceListener(r.PathValue("id"), r.PathValue("name"), body.LocalHost, body.LocalPort)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"local_address": addr})
}

func (s *Server) handleOpenBrowser(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.OpenBrowser(r.PathValue("id"), r.PathValue("name")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResetBrowserProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.ResetBrowserProfile(r.PathValue("id"), r.PathValue("name")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListBrowserProfiles(w http.ResponseWriter, r *http.Request) {
	entries, err := s.mgr.ListBrowserProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if entries == nil {
		entries = []browseropen.ProfileEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleCleanBrowserProfiles(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	errs := s.mgr.CleanBrowserProfiles(body.Keys)
	writeJSON(w, http.StatusOK, map[string]any{"errors": errs})
}

// handleProbe previews the tunnels a profile is allowed, without
// establishing a tunnel session -- the GUI equivalent of `ntwire list`,
// used to populate a port-mapping form with real tunnel names.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	tunnels, err := s.mgr.Probe(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, tunnels)
}

// handleLogout clears a profile's cached SSO tokens, the GUI equivalent of
// `ntwire logout`.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Logout(r.PathValue("id")); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleKeygen creates a new SSH identity, the GUI equivalent of `ntwire
// keygen`.
func (s *Server) handleKeygen(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	fingerprint, publicKey, err := s.mgr.GenerateIdentity(body.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"fingerprint": fingerprint, "public_key": publicKey})
}

func (s *Server) handleAnswerTrust(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Trust bool `json:"trust"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.AnswerTrust(r.PathValue("id"), body.Trust); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAnswerPassphrase(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
		Cancel     bool   `json:"cancel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.AnswerPassphrase(r.PathValue("id"), body.Passphrase, body.Cancel); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Settings())
}

func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request) {
	var set config.Settings
	if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.mgr.SetSettings(set); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

// handleEvents streams manager.Update as server-sent events: an initial
// snapshot of every profile, then live updates as they happen. A slow or
// disconnected client cannot stall the manager -- Manager.Subscribe's
// channel is a best-effort, non-blocking fan-out target.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	updates, unsubscribe := s.mgr.Subscribe()
	defer unsubscribe()

	for _, snap := range s.mgr.Snapshots() {
		writeSSE(w, manager.Update{ProfileID: snap.Profile.ID, Snapshot: snap})
	}
	flusher.Flush()

	for {
		select {
		case u := <-updates:
			writeSSE(w, u)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func writeSSE(w http.ResponseWriter, u manager.Update) {
	b, err := json.Marshal(u)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
}
