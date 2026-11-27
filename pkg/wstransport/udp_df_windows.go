package wstransport

import "golang.org/x/sys/windows"

func setUDPDontFragment(fd uintptr, ipv6 bool) error {
	// IP_PMTUDISC_DO in the Windows SDK PMTUD_STATE enum.
	const dontFragment = 1
	if ipv6 {
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_MTU_DISCOVER, dontFragment)
	}
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_MTU_DISCOVER, dontFragment)
}
