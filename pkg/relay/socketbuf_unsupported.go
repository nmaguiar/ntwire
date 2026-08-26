//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package relay

import (
	"fmt"
	"net"
)

func socketBufferBytes(net.PacketConn) (read, write int, err error) {
	return 0, 0, fmt.Errorf("UDP socket buffer inspection is unsupported on this platform")
}
