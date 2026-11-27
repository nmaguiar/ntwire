//go:build linux

package tcptune

import (
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestListen_AcceptedSocketInheritsNotSentLowat(t *testing.T) {
	const lowat = 16 << 10
	ln, err := Listen(Options{NotSentLowat: lowat}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	raw, err := accepted.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var readErr error
	if err := raw.Control(func(fd uintptr) {
		got, readErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	}); err != nil {
		t.Fatal(err)
	}
	if readErr != nil || got != lowat {
		t.Fatalf("accepted TCP_NOTSENT_LOWAT = %d, %v, want %d", got, readErr, lowat)
	}
}

func TestListen_AppliesCongestionOnLinux(t *testing.T) {
	ln, err := Listen(Options{Congestion: "cubic", NotSentLowat: 16384}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	raw, err := ln.(interface {
		SyscallConn() (syscall.RawConn, error)
	}).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got string
	var lowat int
	_ = raw.Control(func(fd uintptr) {
		got, _ = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
		lowat, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	})
	if got != "cubic" {
		t.Skipf("kernel did not report cubic (got %q); congestion module unavailable", got)
	}
	if lowat != 16384 {
		t.Fatalf("TCP_NOTSENT_LOWAT = %d, want 16384", lowat)
	}
}

func TestListen_LowatAppliedWhenCongestionRejected(t *testing.T) {
	ln, err := Listen(Options{Congestion: "definitely-not-real", NotSentLowat: 32768}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	raw, err := ln.(interface {
		SyscallConn() (syscall.RawConn, error)
	}).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var lowat int
	_ = raw.Control(func(fd uintptr) {
		lowat, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	})
	if lowat != 32768 {
		t.Fatalf("TCP_NOTSENT_LOWAT = %d, want 32768", lowat)
	}
}
