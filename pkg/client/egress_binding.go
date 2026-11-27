package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/socks"
)

type destinationOffer struct {
	grant     *egressGrant
	conn      *grantConn
	addresses []netip.Addr
}

func (g *egressGrant) OfferDestination(ctx context.Context, dst egressrouter.Destination) (egressrouter.DestinationOffer, error) {
	if !g.destinationBinding {
		return nil, &egressrouter.Failure{Class: "asn_binding_unavailable", Code: 7}
	}
	service, err := g.Prepare(ctx)
	if err != nil {
		return nil, err
	}
	p := service.(*preparedGrant)
	defer p.Close()
	addrs, err := socks.OfferDestination(ctx, p.conn, dst)
	if err != nil {
		return nil, bindingFailure(err)
	}
	if err := g.valid(); err != nil {
		return nil, err
	}
	offer := &destinationOffer{grant: g, conn: p.conn, addresses: addrs}
	p.conn = nil
	return offer, nil
}

func (p *destinationOffer) Addresses() []netip.Addr { return slices.Clone(p.addresses) }

func (p *destinationOffer) Close() error {
	if p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

func (p *destinationOffer) ConnectAddress(ctx context.Context, ip netip.Addr) (net.Conn, error) {
	index := slices.Index(p.addresses, ip)
	if p.conn == nil || index < 0 {
		return nil, &egressrouter.Failure{Class: "invalid_binding_selection", Code: 2}
	}
	conn := p.conn
	p.conn = nil
	if err := p.grant.valid(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := socks.SelectDestination(ctx, conn, index); err != nil {
		_ = conn.Close()
		return nil, bindingFailure(err)
	}
	if err := p.grant.valid(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn.Conn = trackAdaptiveTraffic(conn.Conn, conn.traffic)
	return conn, nil
}

func bindingFailure(err error) error {
	var e *socks.ConnectError
	if errors.As(err, &e) && e.Code != 0 {
		class := "destination_binding_failed"
		if e.Code == 2 {
			class = "policy_denied"
		}
		return &egressrouter.Failure{Class: class, Stage: "destination_binding", Code: e.Code}
	}
	return &egressrouter.Failure{Class: "ambiguous", Stage: "destination_binding"}
}
