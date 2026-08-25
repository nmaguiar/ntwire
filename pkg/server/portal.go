package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/portal"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func (s *Server) portalHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	session, ok := s.sessions.Get(token)
	if !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "native"
	}

	serverTunnelIP := s.ServerTunnelIP()
	s.mu.Lock()
	portalCfg := s.Config.Portal
	s.mu.Unlock()

	var targetInfos []portal.TargetInfo
	for _, st := range session.Tunnels {
		cfg, ok := s.tunnelConfig(st.Name)
		if !ok {
			continue
		}
		targetInfos = append(targetInfos, portal.TargetInfo{
			Name:         st.Name,
			Target:       cfg.Target,
			Description:  cfg.Description,
			VirtualPort:  st.VirtualPort,
			LocalPort:    st.LocalPort,
			LocalHost:    st.LocalHost,
			Instructions: st.Instructions,
			DocsURL:      st.DocsURL,
			IsSocks:      cfg.IsSocks(),
			Portal:       cfg.Portal,
		})
	}

	user := portal.PortalUser{
		Identity:    session.Identity,
		DisplayName: session.Identity,
		Method:      session.Method,
		Email:       session.Identity,
		Groups:      session.Groups,
	}
	client := portal.PortalClient{}

	portalCtx := portal.BuildContext(
		portalCfg,
		user,
		client,
		targetInfos,
		mode,
		serverTunnelIP,
	)

	tmpl := portalCfg.Template
	if tmpl == "" {
		tmpl = portal.DefaultTemplate
	}

	renderedMD, err := portal.RenderTemplate(tmpl, portalCtx)
	if err != nil {
		s.log.Warn("portal template render error", "identity", session.Identity, "error", err)
		fail(w, http.StatusInternalServerError, "portal_render_error", "failed to render portal template")
		return
	}

	renderedHTML := portal.RenderMarkdown(renderedMD, portalCtx.Capabilities)

	s.observe("portal_rendered", session.Method)
	s.log.Debug("portal rendered", "identity", session.Identity, "mode", mode, "targets", len(targetInfos))

	write(w, http.StatusOK, portal.RenderedPortal{
		Title:    portalCtx.Portal.Title,
		Markdown: renderedMD,
		HTML:     renderedHTML,
		Context:  portalCtx,
	})
}

func (s *Server) portalActionHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	session, ok := s.sessions.Get(token)
	if !ok {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid session")
		return
	}

	var req portal.ActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, protocol.ErrorInvalidRequest, "invalid request body")
		return
	}

	// Revalidate target authorization
	targetAuthorized := false
	var grantedTunnel protocol.Tunnel
	for _, t := range session.Tunnels {
		if strings.EqualFold(t.Name, req.TargetID) {
			targetAuthorized = true
			grantedTunnel = t
			break
		}
	}

	if !targetAuthorized {
		s.observe("portal_action_denied", session.Method)
		s.log.Warn("portal action denied: target not authorized", "identity", session.Identity, "target", req.TargetID, "action", req.Action)
		fail(w, http.StatusForbidden, protocol.ErrorNotAllowed, "target not authorized for this session")
		return
	}

	cfg, ok := s.tunnelConfig(grantedTunnel.Name)
	if !ok {
		fail(w, http.StatusNotFound, protocol.ErrorInvalidRequest, "target configuration not found")
		return
	}

	targetInfo := portal.TargetInfo{
		Name:         grantedTunnel.Name,
		Target:       cfg.Target,
		Description:  cfg.Description,
		VirtualPort:  grantedTunnel.VirtualPort,
		LocalPort:    grantedTunnel.LocalPort,
		LocalHost:    grantedTunnel.LocalHost,
		Instructions: grantedTunnel.Instructions,
		DocsURL:      grantedTunnel.DocsURL,
		IsSocks:      cfg.IsSocks(),
		Portal:       cfg.Portal,
	}

	serverTunnelIP := s.ServerTunnelIP()
	s.mu.Lock()
	portalCfg := s.Config.Portal
	s.mu.Unlock()

	portalCtx := portal.BuildContext(
		portalCfg,
		portal.PortalUser{Identity: session.Identity, DisplayName: session.Identity, Method: session.Method},
		portal.PortalClient{},
		[]portal.TargetInfo{targetInfo},
		"native",
		serverTunnelIP,
	)

	resolution, err := portal.ResolveAction(req.TargetID, portalCtx.Targets)
	if err != nil {
		fail(w, http.StatusForbidden, protocol.ErrorNotAllowed, err.Error())
		return
	}

	s.observe("portal_action_executed", session.Method)
	s.log.Info("portal action executed", "identity", session.Identity, "action", req.Action, "target", req.TargetID)
	write(w, http.StatusOK, resolution)
}

// WireGuardPortalHandler returns an http.Handler that serves the in-tunnel WireGuard web portal.
func (s *Server) WireGuardPortalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range portal.SecurityHeaders() {
			w.Header().Set(k, v)
		}

		clientHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			clientHost = r.RemoteAddr
		}

		principal, ok := s.principalForIP(clientHost)
		if !ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access Denied: WireGuard peer identity could not be verified.\n"))
			return
		}

		s.observe("portal_web_request", principal.Method)
		s.log.Debug("wireguard web portal request", "identity", principal.Identity, "client_ip", clientHost)

		serverTunnelIP := s.ServerTunnelIP()
		s.mu.Lock()
		portalCfg := s.Config.Portal
		s.mu.Unlock()

		allowedTunnels := s.allowedTunnelsForPrincipal(principal)
		var targetInfos []portal.TargetInfo
		for _, t := range allowedTunnels {
			targetInfos = append(targetInfos, portal.TargetInfo{
				Name:         t.Name,
				Target:       t.Target,
				Description:  t.Description,
				VirtualPort:  t.VirtualPort,
				LocalPort:    t.LocalPort,
				LocalHost:    t.LocalHost,
				Instructions: t.Instructions,
				DocsURL:      t.DocsURL,
				IsSocks:      t.IsSocks(),
				Portal:       t.Portal,
			})
		}

		user := portal.PortalUser{
			Identity:    principal.Identity,
			DisplayName: principal.Identity,
			Method:      principal.Method,
		}
		client := portal.PortalClient{}

		portalCtx := portal.BuildContext(
			portalCfg,
			user,
			client,
			targetInfos,
			"wireguard",
			serverTunnelIP,
		)

		tmpl := portalCfg.Template
		if tmpl == "" {
			tmpl = portal.DefaultTemplate
		}

		renderedMD, err := portal.RenderTemplate(tmpl, portalCtx)
		if err != nil {
			s.log.Warn("web portal template render error", "identity", principal.Identity, "error", err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Error rendering portal template.\n"))
			return
		}

		renderedHTML := portal.RenderMarkdown(renderedMD, portalCtx.Capabilities)
		fullHTML := portal.WrapWebPage(portalCtx.Portal.Title, renderedHTML)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fullHTML))
	})
}

func (s *Server) startWebPortal(d *dataPlane) error {
	addr := s.Config.Portal.Web.Listen
	var ln net.Listener
	var err error

	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr == nil {
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil && (ip == d.serverIP || ip.IsUnspecified()) {
			ln, err = d.stack.Listen("tcp", net.JoinHostPort(d.serverIP.String(), portStr(addr)))
		}
	}
	if ln == nil && err == nil {
		ln, err = d.stack.Listen("tcp", addr)
		if err != nil {
			ln, err = net.Listen("tcp", addr)
		}
	}
	if err != nil {
		return fmt.Errorf("web portal listen: %w", err)
	}

	d.portalLn = ln
	srv := &http.Server{
		Handler:           s.WireGuardPortalHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	d.portalSrv = srv

	s.log.Info("in-tunnel web portal listening", "address", addr)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Debug("web portal server stopped", "error", err)
		}
	}()
	return nil
}

func portStr(address string) string {
	_, p, e := net.SplitHostPort(address)
	if e != nil {
		return "8080"
	}
	return p
}
