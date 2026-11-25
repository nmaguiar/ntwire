//go:build !linux

package server

import (
	"errors"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

func (*Server) newKernelStack(wgnet.Config, AccelerationConfig) (serverStack, error) {
	return nil, errors.New("kernel WireGuard acceleration requires Linux")
}
