//go:build windows

package wstransport

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
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
		read, err = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF)
		if err == nil {
			write, err = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF)
		}
	})
	return read, write, err
}
