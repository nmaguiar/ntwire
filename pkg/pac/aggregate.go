package pac

import (
	"errors"
	"net/netip"
)

// Aggregate directs every browser request to one local group. Destination
// authorization runs at that group's listener, where TCP ports and SOCKS
// address types are available reliably.
func Aggregate(address string, httpProxy bool) (string, error) {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 {
		return "", errors.New("aggregate PAC requires a numeric loopback proxy endpoint")
	}
	scheme := "SOCKS5 "
	if httpProxy {
		scheme = "PROXY "
	}
	return "function FindProxyForURL(url, host) { return " + jsString(scheme+endpoint.String()) + "; }\n", nil
}
