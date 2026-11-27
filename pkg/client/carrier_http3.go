package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (a *adaptiveCarrierClient) bootstrapHTTP3(ctx context.Context) error {
	info, bearer, expires := a.credentials()
	candidates, attach, err := a.httpCarrierTicket(ctx, info, bearer, protocol.CarrierHTTP3)
	if err != nil {
		return err
	}
	secret, valid := protocol.ParseCarrierTicket(attach.Ticket)
	size := wstransport.MaxWireGuardDatagram(info.TunnelMTU)
	if !valid || attach.ExpiresInMS <= 0 || attach.DatagramMax != size || candidates.HTTP3 != info.HTTP3 {
		return errors.New("invalid HTTP/3 carrier ticket")
	}
	trusted, ok := a.control.Transport.(*secureControlTransport)
	if !ok || trusted.TLSClientConfig == nil {
		return errors.New("HTTP/3 carrier requires the HTTPS trust configuration")
	}
	tlsConfig := trusted.TLSClientConfig.Clone()
	if tlsConfig.InsecureSkipVerify && tlsConfig.VerifyConnection == nil {
		return errors.New("HTTP/3 carrier requires verified TLS")
	}
	tlsConfig.ServerName = a.http3.origin
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	c, err := quic.DialAddr(ctx, a.http3.remote.String(), tlsConfig, wstransport.HTTP3QUICConfig(false))
	if err != nil {
		return fmt.Errorf("dial HTTP/3 carrier: %w", err)
	}
	attached := false
	defer func() {
		if !attached {
			_ = c.CloseWithError(0, "carrier unavailable")
		}
	}()
	state := c.ConnectionState()
	if state.Used0RTT || !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		return errors.New("HTTP/3 datagrams were not negotiated")
	}
	transport := &http3.Transport{EnableDatagrams: true, MaxResponseHeaderBytes: 8192}
	stream, err := transport.NewClientConn(c).OpenRequestStream(ctx)
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.CloseWithError(0, "attach canceled") })
	defer stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, a.base+protocol.CarrierHTTP3Path, nil)
	if err != nil {
		return err
	}
	req.Proto = "connect-udp"
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set(protocol.CarrierLaneHeader, info.LaneID)
	req.Header.Set(protocol.CarrierTicketHeader, attach.Ticket)
	if err := stream.SendRequestHeader(req); err != nil {
		return err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return &carrierHTTPError{status: response.StatusCode}
	}
	if response.Header.Get("Capsule-Protocol") != "?1" {
		return errors.New("invalid HTTP/3 capsule negotiation")
	}
	link := wstransport.NewHTTP3Link(c, stream)
	nonce := sha256.Sum256(secret[:])
	if err := wstransport.SendCarrierSizeProof(ctx, c.Context(), link.SendProbe, protocol.CarrierQUICProbe(size, nonce)); err != nil {
		return err
	}
	data, err := link.ReceiveProbe(ctx)
	if err != nil {
		return fmt.Errorf("receive HTTP/3 datagram size proof: %w", err)
	}
	if !protocol.ValidCarrierQUICProbe(data, size, nonce) {
		return errors.New("HTTP/3 datagram size proof failed")
	}
	if !stop() {
		return errors.New("HTTP/3 attach expired")
	}
	attached = a.installHTTPPath(a.http3.bind, link, info, candidates.PathEpoch, protocol.CarrierHTTP3, size, expires) == nil
	if !attached {
		return errors.New("HTTP/3 lane changed during attach")
	}
	link.Ready()
	return nil
}
