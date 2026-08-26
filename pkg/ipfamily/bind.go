// Package ipfamily restricts a WireGuard conn.Bind to a single IP family.
package ipfamily

import (
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

// New wraps bind so it only sends, parses, and delivers packets for the
// requested family: "4" for IPv4-only, "6" for IPv6-only. Any other value,
// including "" (the default, meaning either family), returns bind unchanged
// -- callers are expected to validate the option at the system boundary
// (see the client's httpClient), not here.
//
// The wrapped bind's own socket(s) are untouched -- a dual-stack
// conn.NewStdNetBind() still listens on both families -- but nothing of the
// excluded family is ever sent, accepted as a peer endpoint, or handed up
// from a receive, so the excluded family can never carry WireGuard traffic
// through this Bind even if the peer, a relay, or NAT roaming would
// otherwise have offered it.
func New(bind conn.Bind, family string) conn.Bind {
	switch family {
	case "4":
		return &Bind{Bind: bind, is6: false}
	case "6":
		return &Bind{Bind: bind, is6: true}
	default:
		return bind
	}
}

// Bind wraps a conn.Bind and restricts it to one IP family.
type Bind struct {
	conn.Bind
	is6 bool
}

// Unwrap exposes the underlying bind for transport diagnostics.
func (b *Bind) Unwrap() conn.Bind { return b.Bind }

func (b *Bind) match(addr netip.Addr) bool { return addr.Unmap().Is6() == b.is6 }

func (b *Bind) family() string {
	if b.is6 {
		return "6"
	}
	return "4"
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.wrapReceive(fn)
	}
	return wrapped, actual, nil
}

// wrapReceive drops packets from the excluded family, shifting survivors
// down to a dense [0:n) slice, and retries the underlying read if an entire
// batch turns out to be excluded -- ReceiveFunc's contract requires at least
// one packet per successful return.
func (b *Bind) wrapReceive(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(bufs, sizes, eps)
			if err != nil {
				return n, err
			}
			out := 0
			for i := 0; i < n; i++ {
				if !b.match(eps[i].DstIP()) {
					continue
				}
				if out != i {
					bufs[out], sizes[out], eps[out] = bufs[i], sizes[i], eps[i]
				}
				out++
			}
			if out > 0 {
				return out, nil
			}
		}
	}
}

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if !b.match(ep.DstIP()) {
		return fmt.Errorf("ipfamily: endpoint %s is not IPv%s", ep.DstToString(), b.family())
	}
	return b.Bind.Send(bufs, ep)
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ep, err := b.Bind.ParseEndpoint(s)
	if err != nil {
		return nil, err
	}
	if !b.match(ep.DstIP()) {
		return nil, fmt.Errorf("ipfamily: endpoint %s is not IPv%s", s, b.family())
	}
	return ep, nil
}
