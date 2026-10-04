package wstransport

import (
	"fmt"
	"sync"
	"testing"
)

func TestServerMultipathReplacesSourceMapping(t *testing.T) {
	m := NewServerMultipathBind(&fakeBind{}, MultipathOptions{})
	defer m.Close()
	for i := 0; i < 1000; i++ {
		m.RegisterPath("peer", "wss", PathWSS, fakeEndpoint{id: fmt.Sprint(i)}, true)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.bySource) != 1 || m.bySource["999"] != m.peers["peer"] {
		t.Fatalf("retained %d mappings after replacement", len(m.bySource))
	}
}

func TestServerMultipathReplacementClearsMTUState(t *testing.T) {
	m := NewServerMultipathBind(&fakeBind{}, MultipathOptions{})
	defer m.Close()
	m.RegisterPath("peer", "wss", PathWSS, fakeEndpoint{id: "old"}, true)
	p := m.peers["peer"]
	p.mu.Lock()
	p.probes["wss"] = outstandingProbe{}
	p.mtuProbes["wss"] = outstandingMTUProbe{}
	p.mtuDone["wss"] = true
	p.mu.Unlock()
	m.RegisterPath("peer", "wss", PathWSS, fakeEndpoint{id: "new"}, true)
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.probes) != 0 || len(p.mtuProbes) != 0 || len(p.mtuDone) != 0 {
		t.Fatal("new endpoint inherited old probe state")
	}
}

func TestServerMultipathConcurrentMTUCapability(t *testing.T) {
	m := NewServerMultipathBind(&fakeBind{}, MultipathOptions{})
	defer m.Close()
	ep := fakeEndpoint{id: "peer"}
	m.RegisterPath("peer", "wss", PathWSS, ep, true)
	p := m.peers["peer"]
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			m.RegisterPath("peer", "wss", PathWSS, ep, i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			m.dispatchControl(p, FramePathMTUAck, nil, ep)
			m.sendMTUProbe(p, "missing", 1200)
		}
	}()
	wg.Wait()
}

func TestServerMultipathReplacementPreservesSharedSource(t *testing.T) {
	m := NewServerMultipathBind(&fakeBind{}, MultipathOptions{})
	defer m.Close()
	ep := fakeEndpoint{id: "shared"}
	m.RegisterPath("peer", "first", PathWSS, ep, false)
	m.RegisterPath("peer", "second", PathWSS, ep, false)
	m.RegisterPath("peer", "first", PathWSS, fakeEndpoint{id: "new"}, false)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.bySource["shared"] != m.peers["peer"] {
		t.Fatal("replacement removed another candidate's source mapping")
	}
}
