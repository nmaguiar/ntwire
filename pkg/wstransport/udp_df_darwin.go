package wstransport

import "golang.org/x/sys/unix"

func setUDPDontFragment(fd uintptr, ipv6 bool) error {
	if ipv6 {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
}
