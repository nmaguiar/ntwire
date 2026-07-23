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
	m.HandleFunc("POST /v1/admin/sessions/{id}/revoke", s.revokeSession)
	return m
}

// revokeSession lets an operator force-end a specific session immediately,
// by the session_id dashboardStatus reports, rather than waiting for the
// session's own TTL or the next config reload to drop it (see "Revocation
// is YAML/groups change + session TTL, not instantaneous" in
// docs/SECURITY.md). It shares dashboardAllowed's gate since it is exposed
// only on the metrics listener alongside the rest of the admin surface, not
// the public control API.
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardAllowed(r) {
		http.NotFound(w, r)
		return
	}
	old, ok := s.sessions.DeleteByID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.dropSession(old)
	s.log.Debug("session revoked", "session", old.ID, "identity", old.Identity)
	s.audit("session_revoked", old, "admin revoke", 0)
	w.WriteHeader(http.StatusNoContent)
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
	fmt.Fprintln(w, "# HELP ntwire_tunnel_bytes_to_target_total Bytes forwarded from a tunnel's client side to its target.")
	fmt.Fprintln(w, "# TYPE ntwire_tunnel_bytes_to_target_total counter")
	fmt.Fprintln(w, "# HELP ntwire_tunnel_bytes_from_target_total Bytes forwarded from a tunnel's target back to the client.")
	fmt.Fprintln(w, "# TYPE ntwire_tunnel_bytes_from_target_total counter")
	fmt.Fprintln(w, "# HELP ntwire_tunnel_connections_active Open forwarded connections for a tunnel.")
	fmt.Fprintln(w, "# TYPE ntwire_tunnel_connections_active gauge")
	for _, session := range sessions {
		for _, tunnel := range session.Tunnels {
			stats := s.statsFor(session.TunnelIP, tunnel.Name).snapshot()
			labels := fmt.Sprintf("tunnel=\"%s\",method=\"%s\",identity=\"%s\"", promLabel(tunnel.Name), promLabel(session.Method), promLabel(session.Identity))
			fmt.Fprintf(w, "ntwire_tunnel_bytes_to_target_total{%s} %d\n", labels, stats.BytesToTarget)
			fmt.Fprintf(w, "ntwire_tunnel_bytes_from_target_total{%s} %d\n", labels, stats.BytesFromTarget)
			fmt.Fprintf(w, "ntwire_tunnel_connections_active{%s} %d\n", labels, stats.Active)
		}
	}
}

func promLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}
