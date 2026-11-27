package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.zx2c4.com/wireguard/conn"
)

type http3CarrierContextKey struct{}

func (s *Server) startHTTP3Carrier(p *adaptiveServerPlane, bind *wstransport.QUICBind) (*adaptiveQUICServer, error) {
	q, err := s.startAdaptiveQUIC(bind, s.Config.Transport.HTTP3Listen, http3.NextProtoH3)
	if err != nil {
		return nil, err
	}
	server := &http3.Server{
		EnableDatagrams: true, MaxHeaderBytes: 8192, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 8 * time.Second,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			return context.WithValue(ctx, http3CarrierContextKey{}, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.carrierHTTP3(p, q, w, r) }),
	}
	go func() { _ = server.ServeListener(q.listener) }()
	return q, nil
}

func (s *Server) carrierHTTP3(p *adaptiveServerPlane, q *adaptiveQUICServer, w http.ResponseWriter, r *http.Request) {
	c, ok := r.Context().Value(http3CarrierContextKey{}).(*quic.Conn)
	if !ok {
		http.NotFound(w, r)
		return
	}
	state := c.ConnectionState()
	if r.Method != http.MethodConnect || r.Proto != "connect-udp" ||
		r.URL.EscapedPath() != protocol.CarrierHTTP3Path || r.URL.RawQuery != "" ||
		r.Header.Get("Capsule-Protocol") != "?1" || state.Used0RTT ||
		!state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		http.NotFound(w, r)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.NotFound(w, r)
		return
	}
	id := r.Header.Get(protocol.CarrierLaneHeader)
	secret, valid := protocol.ParseCarrierTicket(r.Header.Get(protocol.CarrierTicketHeader))
	if _, ok := protocol.ParseCarrierID(id); !ok || !valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	lane, ticket := s.consumeHTTP3Ticket(p, id, secret)
	if lane == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	stream := streamer.HTTPStream()
	link := wstransport.NewHTTP3Link(c, stream)
	defer link.Close()
	w.Header().Set("Capsule-Protocol", "?1")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	size := wstransport.MaxWireGuardDatagram(p.mtu)
	probe, err := link.ReceiveProbe(ctx)
	if err != nil || !protocol.ValidCarrierQUICProbe(probe, size, sha256.Sum256(secret[:])) {
		s.log.Debug("HTTP/3 carrier did not receive the size proof", "error", err)
		return
	}
	done := s.publishHTTP3(p, q, id, lane, ticket, size, link)
	if done == nil {
		s.log.Debug("HTTP/3 carrier authorization changed before attachment")
		return
	}
	if err := wstransport.SendCarrierSizeProof(ctx, c.Context(), link.SendProbe, probe); err != nil {
		s.log.Debug("HTTP/3 carrier could not return the size proof", "error", err)
		_ = link.Close()
	} else {
		link.Ready()
	}
	<-done
}

func (s *Server) consumeHTTP3Ticket(p *adaptiveServerPlane, id string, secret [32]byte) (*serverCarrierLane, *carrierTicket) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.adaptive != p {
		return nil, nil
	}
	lane := p.lanes[id]
	if lane == nil || lane.httpLink != nil {
		return nil, nil
	}
	ticket := lane.http3Attach
	if ticket == nil || ticket.consumed || ticket.request.Candidate != protocol.CarrierHTTP3 || !time.Now().Before(ticket.expires) {
		return nil, nil
	}
	want, valid := protocol.ParseCarrierTicket(ticket.secret)
	if !valid || subtle.ConstantTimeCompare(want[:], secret[:]) != 1 {
		return nil, nil
	}
	ticket.consumed, ticket.secret = true, ""
	return lane, ticket
}

func (s *Server) publishHTTP3(p *adaptiveServerPlane, q *adaptiveQUICServer, id string, lane *serverCarrierLane, ticket *carrierTicket, size int, link *wstransport.HTTP3Link) <-chan struct{} {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.adaptive != p || p.lanes[id] != lane || lane.httpLink != nil || lane.http3Attach != ticket || !time.Now().Before(ticket.expires) {
		return nil
	}
	parent, valid := s.sessions.Get(ticket.bearer)
	if !valid {
		return nil
	}
	v, valid := parent.carrierView(id)
	if !valid || v.Adaptive.Child || v.Adaptive.HTTP3 == "" || v.Adaptive.AuthGeneration != ticket.request.Generation {
		return nil
	}
	primary, epoch, _ := p.bind.LaneState(lane.endpoint)
	if primary != "" || epoch != ticket.request.ExpectedEpoch {
		return nil
	}
	ep, done, err := q.bind.AdoptLink(id, link, size, func(ep conn.Endpoint) {
		s.detachHTTPCarrier(p, id, lane, protocol.CarrierHTTP3, link, ep)
	})
	if err == nil {
		err = p.bind.AttachStream(lane.endpoint, epoch, wstransport.QualifiedPath{
			ID: protocol.CarrierHTTP3, Carrier: protocol.CarrierHTTP3, Endpoint: ep,
			SendMax: size, ReceiveMax: size, ValidUntil: v.Expires,
		})
	}
	if err != nil {
		return nil
	}
	ticket.bearer = ""
	lane.httpLink = link
	return done
}
