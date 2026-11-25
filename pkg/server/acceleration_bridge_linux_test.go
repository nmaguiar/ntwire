//go:build linux

package server

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestKernelBridge_PendingSourceLimit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		endpoint  func(int) string
		other     string
		sameGroup string
	}{
		{
			name:      "IPv4 and mapped IPv4",
			endpoint:  func(i int) string { return fmt.Sprintf("192.0.2.10:%d", 6000+i) },
			other:     "192.0.2.11:6000",
			sameGroup: "[::ffff:192.0.2.10]:6100",
		},
		{
			name:      "IPv6 prefix",
			endpoint:  func(i int) string { return fmt.Sprintf("[2001:db8:1::%x]:6000", i+1) },
			other:     "[2001:db8:2::1]:6000",
			sameGroup: "[2001:db8:1::100]:6100",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Use ordinary loopback sockets to test admission without Linux
			// namespace privileges or traffic on the public WireGuard port.
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ns := &kernelNamespace{calls: make(chan namespaceCall), done: make(chan struct{})}
			go func() {
				defer close(ns.done)
				for call := range ns.calls {
					call.done <- call.run()
				}
			}()
			defer ns.close()
			bridge := newKernelBridge(ns, nil)
			bridge.port = listener.LocalAddr().(*net.UDPAddr).Port
			defer func() {
				if err := bridge.close(); err != nil {
					t.Error(err)
				}
				if bridge.pending != 0 || len(bridge.pendingBySource) != 0 {
					t.Error("closing the bridge left pending source counts")
				}
			}()
			udp := wstransport.NewUDPBind(0, nil)
			mapUDP := func(address string, authorized bool) *bridgeEndpoint {
				t.Helper()
				endpoint, err := udp.ParseEndpoint(address)
				if err != nil {
					t.Fatal(err)
				}
				return bridge.mapping(endpoint.DstToString(), endpoint, authorized)
			}

			for i := 0; i < bridgeMaxPendingPerSource; i++ {
				if mapUDP(tc.endpoint(i), false) == nil {
					t.Fatalf("source mapping %d was denied below its limit", i)
				}
			}
			if mapUDP(tc.sameGroup, false) != nil {
				t.Fatal("extra mapping was admitted for the same source")
			}
			if mapUDP(tc.other, false) == nil {
				t.Fatal("another source could not use the free global capacity")
			}
			if mapUDP(tc.endpoint(0), false) == nil {
				t.Fatal("existing mapping was denied")
			}

			wss, err := wstransport.NewServer().ParseEndpoint(tc.sameGroup)
			if err != nil {
				t.Fatal(err)
			}
			wssMapping := bridge.mapping(wss.DstToString(), wss, false)
			if wssMapping == nil {
				t.Fatal("WebSocket endpoint was charged to a raw UDP source")
			}
			bridge.mu.Lock()
			bridge.remove(wss.DstToString(), wssMapping)
			bridge.mu.Unlock()

			if mapUDP(tc.endpoint(0), true) == nil || mapUDP(tc.sameGroup, false) == nil {
				t.Fatal("authorizing an existing endpoint did not free a source slot")
			}
			if mapUDP(tc.endpoint(bridgeMaxPendingPerSource), false) != nil {
				t.Fatal("replacement mapping did not consume the released slot")
			}

			key := tc.endpoint(1)
			bridge.mu.Lock()
			bridge.remove(key, bridge.mappings[key])
			bridge.mu.Unlock()
			if mapUDP(tc.endpoint(bridgeMaxPendingPerSource), false) == nil {
				t.Fatal("removing a pending endpoint did not free its source slot")
			}
		})
	}
}

func TestBridgePendingSource_IgnoresIPv6Zone(t *testing.T) {
	endpoint, err := wstransport.NewUDPBind(0, nil).ParseEndpoint("[fe80::42%fixture]:51820")
	if err != nil {
		t.Fatal(err)
	}
	if source := bridgePendingSource(endpoint); source != netip.MustParsePrefix("fe80::/64") {
		t.Fatalf("source = %s, want fe80::/64", source)
	}
}
