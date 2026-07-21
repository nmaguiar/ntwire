package server

import (
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/server/webui"
	"net/http"
	"strings"
)

// MetricsHandler exposes the Prometheus snapshot and optional operator
// dashboard on the metrics listener, keeping them off the public control API.
func (s *Server) MetricsHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /metrics", s.metrics)
	m.HandleFunc("GET /", s.dashboard)
	m.HandleFunc("GET /v1/dashboard", s.dashboardStatus)
	return m
}

// dashboard serves the optional operator console. It is deliberately opt-in:
// its data includes authenticated identities and tunnel addresses.
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardAllowed(r) {
		http.NotFound(w, r)
		return
	}
	fsys, err := webui.Files()
	if err != nil {
		http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
		return
	}
	http.FileServer(http.FS(fsys)).ServeHTTP(w, r)
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	sessions := s.sessions.All()
	s.mu.Lock()
	tunnelCount := len(s.Config.Tunnels)
	s.mu.Unlock()
	fmt.Fprintln(w, "# HELP ntwire_sessions Active ntwire sessions.")
	fmt.Fprintln(w, "# TYPE ntwire_sessions gauge")
	fmt.Fprintf(w, "ntwire_sessions %d\n", len(sessions))
	fmt.Fprintln(w, "# HELP ntwire_tunnels_configured Configured server tunnels.")
	fmt.Fprintln(w, "# TYPE ntwire_tunnels_configured gauge")
	fmt.Fprintf(w, "ntwire_tunnels_configured %d\n", tunnelCount)
	fmt.Fprintln(w, "# HELP ntwire_session_tunnels Granted tunnels per active session.")
	fmt.Fprintln(w, "# TYPE ntwire_session_tunnels gauge")
	fmt.Fprintln(w, "# HELP ntwire_session_latency_milliseconds Last client-observed control-plane round-trip latency.")
	fmt.Fprintln(w, "# TYPE ntwire_session_latency_milliseconds gauge")
	fmt.Fprintln(w, "# HELP ntwire_session_reconnections Client control-plane reconnections since startup.")
	fmt.Fprintln(w, "# TYPE ntwire_session_reconnections counter")
	for _, session := range sessions {
		fmt.Fprintf(w, "ntwire_session_tunnels{method=\"%s\",identity=\"%s\"} %d\n", promLabel(session.Method), promLabel(session.Identity), len(session.Tunnels))
		fmt.Fprintf(w, "ntwire_session_latency_milliseconds{method=\"%s\",identity=\"%s\"} %d\n", promLabel(session.Method), promLabel(session.Identity), session.LatencyMillis)
		fmt.Fprintf(w, "ntwire_session_reconnections{method=\"%s\",identity=\"%s\"} %d\n", promLabel(session.Method), promLabel(session.Identity), session.Reconnections)
	}
}

func promLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}
