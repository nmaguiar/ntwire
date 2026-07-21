package server

import (
	"fmt"
	"net/http"
	"strings"
)

// MetricsHandler exposes a small Prometheus-compatible plaintext snapshot.
func (s *Server) MetricsHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /metrics", s.metrics)
	return m
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
	for _, session := range sessions {
		fmt.Fprintf(w, "ntwire_session_tunnels{method=\"%s\",identity=\"%s\"} %d\n", promLabel(session.Method), promLabel(session.Identity), len(session.Tunnels))
	}
}

func promLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}
