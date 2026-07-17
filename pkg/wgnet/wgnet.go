// Package wgnet owns the userspace WireGuard transport boundary.
package wgnet

import "errors"

var ErrUnavailable = errors.New("userspace WireGuard transport is not linked in this build")

type Endpoint struct{ PublicKey, Address string }
type Stack interface {
	AddPeer(Endpoint) error
	RemovePeer(string) error
	Close() error
}
