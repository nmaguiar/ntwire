package egressattach

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/socks"
)

type attachedOffer struct {
	conn      *localproxy.BufferedConn
	addresses []netip.Addr
}

func (a attached) OfferDestination(ctx context.Context, dst egressrouter.Destination) (egressrouter.DestinationOffer, error) {
	if !a.destinationBinding {
		return nil, &egressrouter.Failure{Class: "asn_binding_unavailable", Code: 7}
	}
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	conn, reader, err := a.info.exchange(ctx, request{Operation: "offer_destination", Member: a.member, Generation: a.generation, Destination: dst, Timeout: timeout})
	if err != nil {
		return nil, &egressrouter.Failure{Class: "attachment_binding_failed"}
	}
	cancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer cancel()
	var reply response
	if err = readFrame(reader, &reply); err != nil || ctx.Err() != nil {
		_ = conn.Close()
		return nil, &egressrouter.Failure{Class: "ambiguous", Stage: "destination_binding"}
	}
	if reply.Failure != nil {
		_ = conn.Close()
		return nil, reply.Failure
	}
	if len(reply.Addresses) == 0 || len(reply.Addresses) > socks.MaxDestinationOffers {
		_ = conn.Close()
		return nil, &egressrouter.Failure{Class: "invalid_binding_offer"}
	}
	return &attachedOffer{conn: &localproxy.BufferedConn{Conn: conn, Reader: reader}, addresses: reply.Addresses}, nil
}

func (p *attachedOffer) Addresses() []netip.Addr { return slices.Clone(p.addresses) }
func (p *attachedOffer) Close() error {
	if p.conn == nil {
		return nil
	}
	return p.conn.Close()
}
func (p *attachedOffer) ConnectAddress(ctx context.Context, ip netip.Addr) (net.Conn, error) {
	if p.conn == nil || !slices.Contains(p.addresses, ip) {
		return nil, &egressrouter.Failure{Class: "invalid_binding_selection", Code: 2}
	}
	conn := p.conn
	p.conn = nil
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	var reply response
	if err := writeFrame(conn, ip); err != nil || readFrame(conn.Reader, &reply) != nil || ctx.Err() != nil {
		_ = conn.Close()
		return nil, &egressrouter.Failure{Class: "ambiguous", Stage: "destination_binding"}
	}
	if reply.Failure != nil {
		_ = conn.Close()
		return nil, reply.Failure
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func serveDestinationOffer(ctx, setup context.Context, in *localproxy.BufferedConn, candidate egressrouter.Candidate, dst egressrouter.Destination) {
	backend, ok := candidate.Dialer.(egressrouter.BindableEgress)
	if !ok || !candidate.DestinationBinding {
		writeFailure(in, &egressrouter.Failure{Class: "asn_binding_unavailable", Code: 7})
		return
	}
	offer, err := backend.OfferDestination(setup, dst)
	if err != nil {
		writeFailure(in, err)
		return
	}
	defer offer.Close()
	addresses := offer.Addresses()
	if len(addresses) == 0 || len(addresses) > socks.MaxDestinationOffers {
		return
	}
	if setup.Err() != nil || writeFrame(in, response{Addresses: addresses}) != nil {
		return
	}
	var selected netip.Addr
	if readFrame(in.Reader, &selected) != nil || !slices.Contains(addresses, selected) {
		return
	}
	out, err := offer.ConnectAddress(setup, selected)
	if err != nil {
		writeFailure(in, err)
		return
	}
	defer out.Close()
	stop := context.AfterFunc(ctx, func() { _ = out.Close() })
	defer stop()
	if setup.Err() != nil {
		return
	}
	_ = in.SetDeadline(time.Time{})
	if writeFrame(in, response{}) == nil {
		localproxy.Relay(out, in)
	}
}
