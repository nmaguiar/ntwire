//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package wstransport

import (
	"fmt"
	"net"
)

func socketBufferBytes(net.PacketConn) (int, int, error) {
	return 0, 0, fmt.Errorf("UDP socket buffer inspection is unsupported on this platform")
}
