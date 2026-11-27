package wstransport

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUDPProbeBind_RequiresDontFragmentOnEachOpenSocket(t *testing.T) {
	bind := NewProbeUDPBind()
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	for _, field := range []struct {
		socket                  *net.UDPConn
		level, option, expected int
	}{
		{bind.ipv4, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO},
		{bind.ipv6, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO},
	} {
		if field.socket == nil {
			continue
		}
		raw, err := field.socket.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var actual int
		var getErr error
		if err := raw.Control(func(fd uintptr) {
			actual, getErr = unix.GetsockoptInt(int(fd), field.level, field.option)
		}); err != nil || getErr != nil || actual != field.expected {
			t.Fatalf("fragmentation policy = %d, want %d (control %v, option %v)", actual, field.expected, err, getErr)
		}
	}
}
