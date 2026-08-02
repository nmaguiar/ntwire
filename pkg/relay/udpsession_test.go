package relay

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// newTestPortAllocator builds a portAllocator over n loopback UDP sockets,
// mirroring how Relay.Start binds listen.udp_relay_ports eagerly at startup.
func newTestPortAllocator(t *testing.T, n int) *portAllocator {
	t.Helper()
	conns := map[uint16]net.PacketConn{}
	for i := 0; i < n; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("loopback UDP unavailable: %v", err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		conns[uint16(pc.LocalAddr().(*net.UDPAddr).Port)] = pc
	}
	return newPortAllocator(conns)
}

func newTestSessionTable(t *testing.T, poolSize, maxPerTenant int) *udpSessionTable {
	t.Helper()
	alloc := newTestPortAllocator(t, poolSize)
	return newUDPSessionTable(alloc, Limits{MaxUDPRelaySessionsPerServer: maxPerTenant})
}

func TestPortAllocatorExhaustionAndRelease(t *testing.T) {
	alloc := newTestPortAllocator(t, 2)
	p1, _, ok := alloc.allocate()
	if !ok {
		t.Fatal("allocate() failed with a free port available")
	}
	p2, _, ok := alloc.allocate()
	if !ok {
		t.Fatal("allocate() failed with a free port available")
	}
	if p1 == p2 {
		t.Fatalf("allocate() returned the same port twice: %d", p1)
	}
	if _, _, ok := alloc.allocate(); ok {
		t.Fatal("allocate() succeeded with the pool exhausted, want ok=false")
	}
	alloc.release(p1)
	p3, _, ok := alloc.allocate()
	if !ok {
		t.Fatal("allocate() failed after release freed a port")
	}
	if p3 != p1 {
		t.Fatalf("allocate() after release = %d, want the just-released port %d", p3, p1)
	}
}

func TestAllocateEnforcesPoolExhaustion(t *testing.T) {
	table := newTestSessionTable(t, 1, 10)
	if _, _, err := table.Allocate("tenant-a"); err != nil {
		t.Fatalf("first Allocate() = %v, want nil", err)
	}
	if _, _, err := table.Allocate("tenant-b"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("second Allocate() = %v, want ErrPoolExhausted", err)
	}
}

func TestAllocateEnforcesPerTenantCapacityIndependentlyOfPool(t *testing.T) {
	table := newTestSessionTable(t, 10, 1)
	if _, _, err := table.Allocate("tenant-a"); err != nil {
		t.Fatalf("first Allocate() for tenant-a = %v, want nil", err)
	}
	if _, _, err := table.Allocate("tenant-a"); !errors.Is(err, ErrUDPRelayTenantAtCapacity) {
		t.Fatalf("second Allocate() for tenant-a = %v, want ErrUDPRelayTenantAtCapacity", err)
	}
	if _, _, err := table.Allocate("tenant-b"); err != nil {
		t.Fatalf("Allocate() for a different tenant = %v, want nil (per-tenant cap must not affect other tenants)", err)
	}
}

func TestBindServerLocksAndRebindsByToken(t *testing.T) {
	table := newTestSessionTable(t, 4, 10)
	token, _, err := table.Allocate("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	addr1 := netip.MustParseAddrPort("127.0.0.1:1111")
	addr2 := netip.MustParseAddrPort("127.0.0.1:2222")

	sess, ok := table.BindServer(token, addr1)
	if !ok {
		t.Fatal("BindServer() failed for a known token")
	}
	if serverAddr, serverBound, _, _ := sess.legs(); !serverBound || serverAddr != addr1 {
		t.Fatalf("after BindServer: serverAddr=%v serverBound=%v, want %v true", serverAddr, serverBound, addr1)
	}

	if _, ok := table.BindServer(token, addr2); !ok {
		t.Fatal("BindServer() rebind failed for a known token")
	}
	if serverAddr, _, _, _ := sess.legs(); serverAddr != addr2 {
		t.Fatalf("after rebind: serverAddr = %v, want %v", serverAddr, addr2)
	}

	if _, ok := table.BindServer("unknown-token", addr1); ok {
		t.Fatal("BindServer() succeeded for an unknown token, want false")
	}
}

func TestBindClientMaintainsByClientIndexAcrossRebind(t *testing.T) {
	table := newTestSessionTable(t, 4, 10)
	token, _, err := table.Allocate("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	addr1 := netip.MustParseAddrPort("127.0.0.1:1111")
	addr2 := netip.MustParseAddrPort("127.0.0.1:2222")

	if _, ok := table.BindClient(token, addr1); !ok {
		t.Fatal("BindClient() failed for a known token")
	}
	if _, ok := table.LookupByClientAddr(addr1); !ok {
		t.Fatal("LookupByClientAddr() failed to find session at bound address")
	}

	if _, ok := table.BindClient(token, addr2); !ok {
		t.Fatal("BindClient() rebind failed")
	}
	if _, ok := table.LookupByClientAddr(addr1); ok {
		t.Fatal("LookupByClientAddr() still finds session at stale pre-rebind address, want it moved")
	}
	if _, ok := table.LookupByClientAddr(addr2); !ok {
		t.Fatal("LookupByClientAddr() failed to find session at new bound address")
	}
}

func TestReleaseRemovesBothIndexesAndFreesPort(t *testing.T) {
	table := newTestSessionTable(t, 1, 10)
	token, _, err := table.Allocate("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := netip.MustParseAddrPort("127.0.0.1:1111")
	if _, ok := table.BindClient(token, clientAddr); !ok {
		t.Fatal("BindClient() failed")
	}

	table.Release(token)

	if _, ok := table.LookupByClientAddr(clientAddr); ok {
		t.Fatal("LookupByClientAddr() still finds a session after Release()")
	}
	// The pool's only port must be reclaimed for a fresh Allocate to succeed.
	if _, _, err := table.Allocate("tenant-b"); err != nil {
		t.Fatalf("Allocate() after Release() = %v, want nil (port should be reclaimed)", err)
	}
}

func TestReleaseUnknownTokenIsNoop(t *testing.T) {
	table := newTestSessionTable(t, 1, 10)
	table.Release("never-allocated") // must not panic
}

func TestSweepReclaimsIdleSessions(t *testing.T) {
	table := newTestSessionTable(t, 1, 10)
	token, _, err := table.Allocate("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := netip.MustParseAddrPort("127.0.0.1:1111")
	if _, ok := table.BindClient(token, clientAddr); !ok {
		t.Fatal("BindClient() failed")
	}

	table.mu.Lock()
	sess := table.byToken[token]
	table.mu.Unlock()
	sess.lastActivity.Store(time.Now().Add(-time.Hour).UnixNano())

	table.sweepOnce(time.Minute)

	if _, ok := table.LookupByClientAddr(clientAddr); ok {
		t.Fatal("session survived sweepOnce() past its idle timeout")
	}
	if _, _, err := table.Allocate("tenant-b"); err != nil {
		t.Fatalf("Allocate() after sweep = %v, want nil (port should be reclaimed)", err)
	}
}

func TestSweepLeavesActiveSessionsAlone(t *testing.T) {
	table := newTestSessionTable(t, 1, 10)
	token, _, err := table.Allocate("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := netip.MustParseAddrPort("127.0.0.1:1111")
	if _, ok := table.BindClient(token, clientAddr); !ok {
		t.Fatal("BindClient() failed")
	}

	table.sweepOnce(time.Minute) // freshly bound, must not be reclaimed

	if _, ok := table.LookupByClientAddr(clientAddr); !ok {
		t.Fatal("sweepOnce() reclaimed a freshly active session")
	}
}
