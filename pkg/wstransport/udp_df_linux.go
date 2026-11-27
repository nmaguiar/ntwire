package wstransport

import "golang.org/x/sys/unix"

func setUDPDontFragment(fd uintptr, ipv6 bool) error {
	if ipv6 {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
}
