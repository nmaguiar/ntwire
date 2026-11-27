package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

func (a *adaptiveCarrierClient) bootstrapHTTPOrQUIC(ctx context.Context) error {
	var quicErr error
	if a.quic != nil {
		// Reserve part of the setup budget for HTTP/2 when both are available.
		quicCtx := ctx
		if a.http2 != nil || a.http3 != nil {
			var cancel context.CancelFunc
			quicCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
		}
		err := a.qualifyQUIC(quicCtx, "")
		if err == nil {
			return nil
		}
		quicErr = fmt.Errorf("adaptive QUIC startup: %w", err)
		if carrierControlDenied(quicErr) {
			return quicErr
		}
	}
	if a.http3 != nil {
		h3Ctx := ctx
		var cancel context.CancelFunc
		if a.http2 != nil {
			h3Ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
		}
		h3Err := a.bootstrapHTTP3(h3Ctx)
		if h3Err == nil {
			a.ws.DisableRedial()
			a.httpBootstrap = protocol.CarrierHTTP3
			return nil
		}
		if carrierControlDenied(h3Err) {
			return h3Err
		}
		quicErr = errors.Join(quicErr, h3Err)
	}
	if a.http2 != nil {
		if err := a.bootstrapHTTP2(ctx); err != nil {
			return errors.Join(quicErr, err)
		}
		a.ws.DisableRedial()
		a.httpBootstrap = protocol.CarrierHTTP2
		return nil
	}
	return quicErr
}

var errAdaptiveCarrierUnavailable = errors.New("adaptive carrier unavailable")

// A fresh authentication may select the legacy WireGuard plane only after a
// transport failure and only if that plane satisfies all required capabilities.
func (o Options) legacyCarrierRetry(response protocol.AuthResponse, err error) (Options, bool) {
	if !o.AdaptiveFallback || response.Adaptive == nil || !errors.Is(err, errAdaptiveCarrierUnavailable) {
		return o, false
	}
	o.AdaptiveCarrier = false
	o.AdaptiveFallback = false
	return o, protocol.ValidateRequiredCapabilities(transportCapabilitiesFor(o), response.RequiredTransportCapabilities) == nil
}

// Every failure in a multi-carrier attempt must be a reachability failure.
// Denied, malformed and unexpected replies are terminal.
func unavailableCarrierAttempt(err error) bool {
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			if !unavailableCarrierAttempt(cause) {
				return false
			}
		}
		return true
	case *carrierHTTPError:
		switch e.status {
		case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUpgradeRequired, http.StatusNotImplemented,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	case interface{ Unwrap() error }:
		if cause := e.Unwrap(); cause != nil {
			return unavailableCarrierAttempt(cause)
		}
	}
	return unavailableWebSocketUpgrade(0, err)
}

func (a *adaptiveCarrierClient) bootstrapHTTP2(ctx context.Context) error {
	info, bearer, expires := a.credentials()
	candidates, attach, err := a.httpCarrierTicket(ctx, info, bearer, protocol.CarrierHTTP2)
	if err != nil {
		return err
	}
	if _, ok := protocol.ParseCarrierTicket(attach.Ticket); !ok || attach.ExpiresInMS <= 0 || attach.DatagramMax != protocol.CarrierWSSDatagramMax || !candidates.HTTP2 {
		return errors.New("invalid HTTP/2 carrier ticket")
	}
	link, err := a.openHTTP2Link(ctx, a.base+"/v1/transport/lanes/"+info.LaneID+"/http2", bearer, attach)
	if err != nil {
		return err
	}
	if err := a.installHTTPPath(a.http2, link, info, candidates.PathEpoch, protocol.CarrierHTTP2, attach.DatagramMax, expires); err != nil {
		_ = link.Close()
		return err
	}
	link.Ready()
	return nil
}

func (a *adaptiveCarrierClient) httpCarrierTicket(ctx context.Context, info protocol.AdaptiveSession, bearer, carrier string) (protocol.CarrierCandidates, protocol.CarrierAttachResponse, error) {
	origin := a.base + "/v1/transport/lanes/" + info.LaneID
	var candidates protocol.CarrierCandidates
	var attach protocol.CarrierAttachResponse
	if err := a.controlRequest(ctx, http.MethodGet, origin+"/candidates", bearer, nil, &candidates); err != nil {
		return candidates, attach, err
	}
	if candidates.ParentID != info.ParentID || candidates.LaneID != info.LaneID ||
		candidates.AuthGeneration != info.AuthGeneration || candidates.Selected != "" || !slices.Contains(candidates.IDs, carrier) {
		return candidates, attach, errors.New("missing authorized HTTP carrier candidate")
	}
	id, err := newCarrierRequestID()
	if err != nil {
		return candidates, attach, err
	}
	body, err := json.Marshal(protocol.CarrierAttachRequest{
		RequestID: id, Generation: info.AuthGeneration, Candidate: carrier, ExpectedEpoch: candidates.PathEpoch,
	})
	if err != nil {
		return candidates, attach, err
	}
	err = a.controlRequest(ctx, http.MethodPost, origin+"/attach", bearer, body, &attach)
	return candidates, attach, err
}

func (a *adaptiveCarrierClient) installHTTPPath(bind *wstransport.QUICBind, link wstransport.DatagramLink, info protocol.AdaptiveSession, epoch uint64, carrier string, max int, expires time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.info.AuthGeneration != info.AuthGeneration || !time.Now().Before(expires) {
		return errors.New("HTTP carrier authorization changed")
	}
	physical, _, err := bind.AdoptLink(info.LaneID, link, max, func(ep conn.Endpoint) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.bind.FailPath(a.lane, carrier, ep, "")
	})
	if err != nil {
		return err
	}
	return a.bind.AttachStream(a.lane, epoch, wstransport.QualifiedPath{
		ID: carrier, Carrier: carrier, Endpoint: physical, SendMax: max, ReceiveMax: max, ValidUntil: expires,
	})
}

func (a *adaptiveCarrierClient) openHTTP2Link(ctx context.Context, endpoint, bearer string, attach protocol.CarrierAttachResponse) (_ *wstransport.FramedLink, err error) {
	trusted, ok := a.control.Transport.(*secureControlTransport)
	if !ok || trusted.TLSClientConfig == nil {
		return nil, errors.New("HTTP/2 carrier requires the HTTPS trust configuration")
	}
	transport := trusted.Transport.Clone()
	transport.ForceAttemptHTTP2 = true
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP2(true)
	verified := &secureControlTransport{Transport: transport, remoteProxy: trusted.remoteProxy}
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	upload, writer := io.Pipe()
	stream := &http2Upload{PipeWriter: writer, cancel: cancel, transport: transport}
	defer func() {
		if err != nil {
			_ = stream.Close()
			_ = upload.Close()
		}
	}()
	req, err := http.NewRequestWithContext(lifetime, http.MethodPost, endpoint, upload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", protocol.CarrierHTTP2Media)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set(protocol.CarrierTicketHeader, attach.Ticket)
	response, err := verified.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, &carrierHTTPError{status: response.StatusCode}
	}
	if response.ProtoMajor != 2 || response.Header.Get("Content-Type") != protocol.CarrierHTTP2Media {
		_ = response.Body.Close()
		return nil, errors.New("HTTP/2 carrier was not accepted")
	}
	if !stop() {
		_ = response.Body.Close()
		return nil, errors.New("HTTP/2 attach expired")
	}
	return wstransport.NewFramedLink(lifetime, response.Body, stream, attach.DatagramMax), nil
}

type http2Upload struct {
	*io.PipeWriter
	cancel    context.CancelFunc
	transport *http.Transport
}

func (w *http2Upload) Close() error {
	w.cancel()
	err := w.PipeWriter.Close()
	w.transport.CloseIdleConnections()
	return err
}
