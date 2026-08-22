package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// MASQUEGateway serves the initial HTTP/2 CONNECT data path. It exposes only
// configured synthetic FQDNs, maps each to an authenticated session grant,
// and never accepts a raw ntwire target from a client.
type MASQUEGateway struct {
	server *Server
	config MASQUEConfig
	http   *http.Server
}

func NewMASQUEGateway(server *Server, baseTLS *tls.Config) (*MASQUEGateway, error) {
	b, err := os.ReadFile(server.Config.MASQUE.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read MASQUE client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("MASQUE client CA contains no certificates")
	}
	tlsConfig := baseTLS.Clone()
	tlsConfig.ClientAuth, tlsConfig.ClientCAs = tls.RequireAndVerifyClientCert, pool
	tlsConfig.NextProtos = []string{"h2"}
	g := &MASQUEGateway{server: server, config: server.Config.MASQUE}
	g.http = &http.Server{Handler: http.HandlerFunc(g.connect), TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	return g, nil
}

func (g *MASQUEGateway) ListenAndServe() error {
	l, err := net.Listen("tcp", g.config.Listen)
	if err != nil {
		return err
	}
	return g.http.ServeTLS(l, "", "")
}

func (g *MASQUEGateway) connect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "relay request rejected", http.StatusBadRequest)
		return
	}
	session, ok := g.server.sessions.FindID(string(r.TLS.PeerCertificates[0].SubjectKeyId))
	if !ok {
		http.Error(w, "relay request rejected", http.StatusForbidden)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "relay request rejected", http.StatusBadRequest)
		return
	}
	tunnelName, ok := g.config.Tunnels[strings.TrimSuffix(strings.ToLower(host), ".")]
	if !ok || !sessionHasTunnel(session, tunnelName) {
		http.Error(w, "relay request rejected", http.StatusForbidden)
		return
	}
	tunnel, ok := g.server.tunnelConfig(tunnelName)
	if !ok || tunnel.IsSocks() || port != fmt.Sprint(tunnel.VirtualPort) {
		http.Error(w, "relay request rejected", http.StatusForbidden)
		return
	}
	g.server.observe("masque_connect", session.Method)
	g.server.audit("masque_connect", session, "allowed", 0)
	out, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), "tcp", tunnel.Target)
	if err != nil {
		http.Error(w, "relay target unavailable", http.StatusBadGateway)
		return
	}
	defer out.Close()
	if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
		http.Error(w, "relay request rejected", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(out, r.Body)
		// A CONNECT stream can be half-closed by the client while the target
		// still has a response to send. Closing the entire TCP connection here
		// would lose that response for request/response protocols.
		if closer, ok := out.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		} else {
			_ = out.Close()
		}
		close(done)
	}()
	_, _ = io.Copy(w, out)
	<-done
}

func sessionHasTunnel(session Session, name string) bool {
	for _, tunnel := range session.Tunnels {
		if tunnel.Name == name {
			return true
		}
	}
	return false
}
