//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows

package wstransport

import (
	"net"
	"syscall"
	"testing"
)

type invalidBufferSocket struct{ net.PacketConn }

func (invalidBufferSocket) SyscallConn() (syscall.RawConn, error) {
	return invalidBufferRawConn{}, nil
}

type invalidBufferRawConn struct{ syscall.RawConn }

func (invalidBufferRawConn) Control(f func(uintptr)) error {
	f(^uintptr(0))
	return nil
}

func TestSocketBufferBytes_ReportsSocketOptionError(t *testing.T) {
	if _, _, err := socketBufferBytes(invalidBufferSocket{}); err == nil {
		t.Fatal("socket buffer inspection hid the invalid descriptor error")
	}
}
