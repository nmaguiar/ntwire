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
	fmt.Fprintln(w, "# HELP ntwire_session_latency_milliseconds Aggregate client-observed control-plane round-trip latency for active sessions.")
	fmt.Fprintln(w, "# TYPE ntwire_session_latency_milliseconds summary")
	fmt.Fprintln(w, "# HELP ntwire_session_reconnections Client control-plane reconnections reported by active sessions.")
	fmt.Fprintln(w, "# TYPE ntwire_session_reconnections gauge")
	// Metrics must not turn an authenticated identity (email, SSH fingerprint,
	// or arbitrary external subject) into a Prometheus label: it is both
	// sensitive and unbounded. Aggregate the session snapshot by the stable,
	// low-cardinality authentication method instead.
	type sessionTotals struct{ count, tunnels, latency, reconnections uint64 }
	byMethod := map[string]sessionTotals{}
	for _, session := range sessions {
		t := byMethod[session.Method]
		t.count++
		t.tunnels += uint64(len(session.Tunnels))
		t.latency += session.LatencyMillis
		t.reconnections += session.Reconnections
		byMethod[session.Method] = t
	}
	for method, totals := range byMethod {
		label := promLabel(method)
		fmt.Fprintf(w, "ntwire_session_tunnels{method=\"%s\"} %d\n", label, totals.tunnels)
		fmt.Fprintf(w, "ntwire_session_latency_milliseconds_sum{method=\"%s\"} %d\n", label, totals.latency)
		fmt.Fprintf(w, "ntwire_session_latency_milliseconds_count{method=\"%s\"} %d\n", label, totals.count)
		fmt.Fprintf(w, "ntwire_session_reconnections{method=\"%s\"} %d\n", label, totals.reconnections)
	}
	fmt.Fprintln(w, "# HELP ntwire_tunnel_bytes_to_target_total Bytes forwarded from a tunnel's client side to its target.")
	fmt.Fprintln(w, "# TYPE ntwire_tunnel_bytes_to_target_total counter")
	fmt.Fprintln(w, "# HELP ntwire_tunnel_bytes_from_target_total Bytes forwarded from a tunnel's target back to the client.")
	fmt.Fprintln(w, "# TYPE ntwire_tunnel_bytes_from_target_total counter")
	fmt.Fprintln(w, "# HELP ntwire_tunnel_connections_active Open forwarded connections for a tunnel.")
	fmt.Fprintln(w, "# TYPE ntwire_tunnel_connections_active gauge")
	type tunnelTotals struct {
		toTarget, fromTarget uint64
		active               int64
	}
	byTunnel := map[string]tunnelTotals{}
	for _, session := range sessions {
		for _, tunnel := range session.Tunnels {
			stats := s.statsFor(session.TunnelIP, tunnel.Name).snapshot()
			key := session.Method + "\x00" + tunnel.Name
			t := byTunnel[key]
			t.toTarget += stats.BytesToTarget
			t.fromTarget += stats.BytesFromTarget
			t.active += stats.Active
			byTunnel[key] = t
		}
	}
	for key, totals := range byTunnel {
		method, tunnel, _ := strings.Cut(key, "\x00")
		labels := fmt.Sprintf("tunnel=\"%s\",method=\"%s\"", promLabel(tunnel), promLabel(method))
		fmt.Fprintf(w, "ntwire_tunnel_bytes_to_target_total{%s} %d\n", labels, totals.toTarget)
		fmt.Fprintf(w, "ntwire_tunnel_bytes_from_target_total{%s} %d\n", labels, totals.fromTarget)
		fmt.Fprintf(w, "ntwire_tunnel_connections_active{%s} %d\n", labels, totals.active)
	}
}

func promLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}
