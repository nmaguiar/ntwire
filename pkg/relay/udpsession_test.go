package relay

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestUDPSessionStatsForTenant_IsolatedAndCumulative(t *testing.T) {
	one := &udpRelaySession{token: "one", tenant: "alpha"}
	two := &udpRelaySession{token: "two", tenant: "beta"}
	one.clientReceived(11)
	one.serverForwarded(11)
	one.serverReceived(17)
	one.clientForwarded(17)
	two.clientReceived(23)
	sessions := &udpSessionTable{byToken: map[string]*udpRelaySession{"one": one, "two": two}, tenantN: map[string]int{"alpha": 1, "beta": 1}}
	got := sessions.StatsForTenant("alpha")
	if len(got) != 1 {
		t.Fatalf("StatsForTenant(alpha) length = %d, want 1", len(got))
	}
	if got[0].Token != "one" || got[0].ClientPacketsReceived != 1 || got[0].ClientBytesReceived != 11 || got[0].ServerPacketsForwarded != 1 || got[0].ServerBytesForwarded != 11 || got[0].ServerPacketsReceived != 1 || got[0].ServerBytesReceived != 17 || got[0].ClientPacketsForwarded != 1 || got[0].ClientBytesForwarded != 17 {
		t.Fatalf("StatsForTenant(alpha) = %+v, want alpha's complete cumulative counters", got[0])
	}
}

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
	sess, ok := table.BindServer(token, netip.MustParseAddrPort("127.0.0.1:2222"))
	if !ok {
		t.Fatal("BindServer() failed")
	}

	table.Release(token)

	if _, serverBound, _, clientBound := sess.legs(); serverBound || clientBound {
		t.Fatal("released session still has bound forwarding legs")
	}
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

// These table tests need socket identities, but no network I/O.
type sessionTestPacketConn struct {
	net.PacketConn
	port int
}

func (c sessionTestPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.port}
}

func newConcurrentSessionTable(poolSize, limit int) *udpSessionTable {
	conns := make(map[uint16]net.PacketConn, poolSize)
	for i := 1; i <= poolSize; i++ {
		conns[uint16(i)] = sessionTestPacketConn{port: i}
	}
	return newUDPSessionTable(newPortAllocator(conns), Limits{MaxUDPRelaySessionsPerServer: limit})
}

func TestAllocate_ConcurrentTenantCapacity(t *testing.T) {
	for round := 0; round < 100; round++ {
		table := newConcurrentSessionTable(32, 1)
		start := make(chan struct{})
		results := make(chan error, 32)
		for i := 0; i < cap(results); i++ {
			go func() {
				<-start
				_, _, err := table.Allocate("tenant")
				results <- err
			}()
		}
		close(start)
		successes := 0
		for i := 0; i < cap(results); i++ {
			if err := <-results; err == nil {
				successes++
			} else if !errors.Is(err, ErrUDPRelayTenantAtCapacity) {
				t.Errorf("Allocate() = %v, want tenant capacity error", err)
			}
		}
		if successes != 1 {
			t.Fatalf("concurrent allocations admitted %d sessions with tenant limit 1", successes)
		}
		// Rejected allocations must leave the remaining pool available.
		if len(table.alloc.free) != 31 {
			t.Fatalf("free ports = %d, want 31", len(table.alloc.free))
		}
	}
}

func TestBindClient_ConcurrentReleaseDoesNotRestoreIndex(t *testing.T) {
	table := newConcurrentSessionTable(1, 1)
	addr := netip.MustParseAddrPort("127.0.0.1:1234")
	for round := 0; round < 3000; round++ {
		token, _, err := table.Allocate("tenant")
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		done := make(chan struct{}, 2)
		go func() {
			<-start
			table.BindClient(token, addr)
			done <- struct{}{}
		}()
		go func() {
			<-start
			table.Release(token)
			done <- struct{}{}
		}()
		close(start)
		<-done
		<-done
		if _, ok := table.LookupByClientAddr(addr); ok {
			t.Fatal("released session restored in client forwarding index")
		}
	}
}

func TestBindClient_ConcurrentRebindKeepsSingleIndex(t *testing.T) {
	for round := 0; round < 100; round++ {
		table := newConcurrentSessionTable(1, 1)
		token, _, err := table.Allocate("tenant")
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		done := make(chan struct{}, 32)
		for i := 0; i < cap(done); i++ {
			addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(1000+i))
			go func() {
				<-start
				table.BindClient(token, addr)
				done <- struct{}{}
			}()
		}
		close(start)
		for i := 0; i < cap(done); i++ {
			<-done
		}
		_, _, addr, _ := table.byToken[token].legs()
		if len(table.byClient) != 1 || table.byClient[addr] != table.byToken[token] {
			t.Fatalf("client forwarding index inconsistent after concurrent rebind: %d entries", len(table.byClient))
		}
	}
}
