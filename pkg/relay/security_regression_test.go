package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

func TestNativeWGRoutingMapHardCap(t *testing.T) {
	pc := mustListenUDPForTest(t)
	defer pc.Close()
	n := newNativeWGRelay(pc, "")
	n.servers["home"] = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:9")).AddrPort()
	packet := make([]byte, 148)
	binary.LittleEndian.PutUint32(packet, 1)
	for i := uint32(1); i <= 5000; i++ {
		binary.LittleEndian.PutUint32(packet[4:8], i)
		n.handle(packet, netip.MustParseAddrPort("127.0.0.1:12345"))
	}
	if len(n.indices) != 4096 {
		t.Fatalf("map size = %d", len(n.indices))
	}
	if _, ok := n.indices[1]; ok {
		t.Fatal("oldest route not evicted")
	}
	binary.LittleEndian.PutUint32(packet[4:8], 5000)
	n.handle(packet, netip.MustParseAddrPort("127.0.0.1:12346"))
	if len(n.indices) != 4096 || n.indices[5000].client.Port() != 12346 {
		t.Fatal("existing route refresh failed")
	}
}
func TestDiscoveredRoutesRespectConnectionCapAndRelease(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := NewRegistry(nil, Limits{MaxPendingPerServer: 1, MaxConnsPerServer: 1})
	ep := ServerEndpoint{Hostname: "home.example", Address: ln.Addr().String(), Source: SourceKubernetes, ID: "id"}
	if err := r.UpsertKubernetes(ep); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, key, err := r.OpenSNI(ctx, "", ep.Hostname, "", ep.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := r.OpenSNI(ctx, "", ep.Hostname, "", ep.Hostname); !errors.Is(err, ErrTenantAtCapacity) {
		t.Fatalf("cap not applied: %v", err)
	}
	r.RemoveKubernetes(ep.Hostname, ep.ID)
	r.Release(key)
	if len(r.discoveredUsage) != 0 {
		t.Fatal("removed route retained accounting")
	}
	r.UpsertKubernetes(ep)
	next, nextKey, err := r.OpenSNI(ctx, "", ep.Hostname, "", ep.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
	r.Release(nextKey)
}
func TestSharedPACRequiresTenantScope(t *testing.T) {
	a := newAgentServer(NewRegistry(nil, Limits{}), "example", Limits{}, nil)
	a.socksTargets["one"] = []protocol.SocksTarget{{Name: "egress", TunnelIP: "100.64.0.1", LocalPort: 10080, VirtualPort: 1080}}
	a.socksTargets["two"] = []protocol.SocksTarget{{Name: "egress", TunnelIP: "100.65.0.1", LocalPort: 10081, VirtualPort: 1081}}
	for _, path := range []string{"/proxy.pac", "/proxy-ios.pac", "/proxy.ios.pac", "/proxy-egress.pac", "/proxy-ios-egress.pac", "/proxy.ios-egress.pac"} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal("unscoped shared PAC accepted", path, w.Code)
		}
		w = httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("GET", path+"?tenant=one", nil))
		if w.Code != 200 || strings.Contains(w.Body.String(), "100.65.0.1") || strings.Contains(w.Body.String(), "10081") {
			t.Fatal("wrong tenant selected", path, w.Code)
		}
	}
	for _, targets := range [][]protocol.SocksTarget{{{Name: "egress", TunnelIP: `x";return "PROXY evil:80";//`}}, {{Name: "same"}, {Name: "same"}}, {{Name: "bad", LocalPort: 65536}}} {
		if validateSocksTargets(targets) {
			t.Fatal("invalid metadata accepted")
		}
	}
}
