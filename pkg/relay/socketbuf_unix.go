//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package relay

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func socketBufferBytes(pc net.PacketConn) (read, write int, err error) {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return 0, 0, fmt.Errorf("packet connection does not expose its socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	err = raw.Control(func(fd uintptr) {
		read, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err == nil {
			write, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		}
	})
	return read, write, err
}
