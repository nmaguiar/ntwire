package wstransport

import (
	"fmt"
	"testing"
)

func TestServerMultipathReplacedPathsReleaseSources(t *testing.T) {
	m := NewServerMultipathBind(&fakeBind{}, MultipathOptions{})
	defer m.Close()
	for i := range 1000 {
		m.RegisterPath("peer", "wss", PathWSS, fakeEndpoint{id: fmt.Sprint("source-", i)}, false)
	}
	m.mu.RLock()
	n := len(m.bySource)
	m.mu.RUnlock()
	if n != 1 {
		t.Fatalf("retained sources=%d, want 1", n)
	}
	m.RemovePeer("peer")
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.peers) != 0 || len(m.bySource) != 0 {
		t.Fatal("RemovePeer retained state")
	}
}
func TestServerMultipathReplacementPreservesSharedSources(t *testing.T) {
	m := NewServerMultipathBind(&fakeBind{}, MultipathOptions{})
	defer m.Close()
	shared := fakeEndpoint{id: "shared"}
	m.RegisterPath("peer", "one", PathWSS, shared, false)
	m.RegisterPath("peer", "two", PathWSS, shared, false)
	m.RegisterPath("peer", "one", PathWSS, fakeEndpoint{id: "new"}, false)
	m.mu.RLock()
	p := m.bySource["shared"]
	m.mu.RUnlock()
	if p == nil || p.id != "peer" {
		t.Fatal("removed source still used by another path")
	}
	m.RegisterPath("other", "one", PathWSS, shared, false)
	m.RegisterPath("peer", "two", PathWSS, fakeEndpoint{id: "new-two"}, false)
	m.mu.RLock()
	p = m.bySource["shared"]
	m.mu.RUnlock()
	if p == nil || p.id != "other" {
		t.Fatal("removed source owned by another peer")
	}
}
