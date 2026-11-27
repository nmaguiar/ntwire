package server

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

func (s *Server) carrierHTTP2(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.TLS.NegotiatedProtocol != "h2" || r.ProtoMajor != 2 ||
		r.Header.Get("Content-Type") != protocol.CarrierHTTP2Media {
		fail(w, http.StatusUnsupportedMediaType, protocol.ErrorInvalidRequest, "HTTP/2 datagram stream required")
		return
	}
	writer := carrierHTTPWriter{response: w, controller: http.NewResponseController(w)}
	link := wstransport.NewFramedLink(r.Context(), r.Body, writer, protocol.CarrierWSSDatagramMax)
	defer link.Close()
	done := s.admitHTTPCarrier(w, r, protocol.CarrierHTTP2, link)
	if done == nil {
		return
	}
	w.Header().Set("Content-Type", protocol.CarrierHTTP2Media)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if err := writer.flush(); err != nil {
		_ = link.Close()
	} else {
		link.Ready()
	}
	<-done // The response writer must outlive the carrier's writer.
}

type carrierHTTPWriter struct {
	response   http.ResponseWriter
	controller *http.ResponseController
}

func (w carrierHTTPWriter) flush() error {
	if err := w.controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer w.controller.SetWriteDeadline(time.Time{})
	return w.controller.Flush()
}

func (w carrierHTTPWriter) Write(data []byte) (int, error) {
	if err := w.controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	defer w.controller.SetWriteDeadline(time.Time{})
	n, err := w.response.Write(data)
	if err == nil {
		err = w.controller.Flush()
	}
	return n, err
}

func (carrierHTTPWriter) Close() error { return nil }

func (s *Server) admitHTTPCarrier(w http.ResponseWriter, r *http.Request, candidate string, link wstransport.DatagramLink) <-chan struct{} {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	v, lane, ok := s.carrierLane(w, r)
	if !ok {
		return nil
	}
	p := s.adaptive
	bind := p.http2
	if bind == nil || !v.Adaptive.HTTP2 || v.Adaptive.Child {
		http.NotFound(w, r)
		return nil
	}
	ticket := lane.httpAttach
	selected, epoch, _ := p.bind.LaneState(lane.endpoint)
	if ticket == nil || ticket.consumed || ticket.request.Candidate != candidate ||
		ticket.request.Generation != v.Adaptive.AuthGeneration || ticket.request.ExpectedEpoch != epoch ||
		!time.Now().Before(ticket.expires) ||
		subtle.ConstantTimeCompare([]byte(ticket.secret), []byte(r.Header.Get(protocol.CarrierTicketHeader))) != 1 {
		fail(w, http.StatusUnauthorized, protocol.ErrorInvalidRequest, "invalid carrier ticket")
		return nil
	}
	if lane.httpLink != nil || (selected != "" && selected != candidate) {
		fail(w, http.StatusConflict, "attach_conflict", "carrier already selected")
		return nil
	}
	ticket.consumed, ticket.secret = true, ""
	endpoint, done, err := bind.AdoptLink(v.Adaptive.LaneID, link, protocol.CarrierWSSDatagramMax, func(ep conn.Endpoint) {
		s.detachHTTPCarrier(p, v.Adaptive.LaneID, lane, candidate, link, ep)
	})
	if err == nil {
		err = p.bind.AttachStream(lane.endpoint, epoch, wstransport.QualifiedPath{
			ID: candidate, Carrier: candidate, Endpoint: endpoint,
			SendMax: protocol.CarrierWSSDatagramMax, ReceiveMax: protocol.CarrierWSSDatagramMax, ValidUntil: v.Expires,
		})
	}
	if err != nil {
		_ = link.Close()
		fail(w, http.StatusConflict, "stale_carrier_state", "carrier state changed")
		return nil
	}
	lane.httpLink = link
	return done
}

func (s *Server) detachHTTPCarrier(p *adaptiveServerPlane, id string, lane *serverCarrierLane, candidate string, link wstransport.DatagramLink, ep conn.Endpoint) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.adaptive == p && p.lanes[id] == lane && lane.httpLink == link {
		p.bind.FailPath(lane.endpoint, candidate, ep, "")
		lane.httpLink = nil
	}
}
