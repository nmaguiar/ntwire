package wstransport

import (
	"fmt"
	"testing"
	"time"
)

func TestNewMTUPolicy_Ladders(t *testing.T) {
	tests := []struct {
		name         string
		opts         MultipathOptions
		wantNil      bool
		wantRequired uint16
		wantLadder   string
	}{
		{"default off", MultipathOptions{}, true, 0, ""},
		{"default tunnel", MultipathOptions{MTUAware: true}, false, 1452, "[1200 1400 1452 1500]"},
		{"1280 tunnel", MultipathOptions{MTUAware: true, TunnelMTU: 1280}, false, 1312, "[1200 1312 1500]"},
		{"1380 tunnel", MultipathOptions{MTUAware: true, TunnelMTU: 1380}, false, 1412, "[1200 1400 1412 1500]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newMTUPolicy(tt.opts)
			if (p == nil) != tt.wantNil {
				t.Fatalf("policy nil = %v, want %v", p == nil, tt.wantNil)
			}
			if p == nil {
				return
			}
			if p.required != tt.wantRequired || fmt.Sprint(p.ladder) != tt.wantLadder {
				t.Fatalf("required=%d ladder=%v, want %d %s", p.required, p.ladder, tt.wantRequired, tt.wantLadder)
			}
		})
	}
}

func TestScheduler_LimitedMTURankedAfterOtherReplacements(t *testing.T) {
	s := NewScheduler()
	now := time.Now()
	s.Register("wss", PathWSS)
	s.ActivateCarrier("wss", now)
	s.Register("direct-udp", PathDirect)
	s.Register("udp-relay", PathUDPRelay)
	s.ProbeResult("direct-udp", time.Millisecond, true, now)
	s.ProbeResult("udp-relay", 50*time.Millisecond, true, now)
	s.SetMTUState("direct-udp", MTUStateLimited)
	s.SetMTUState("udp-relay", MTUStateOK)
	s.CarrierFailure("wss")
	if primary, _, _ := s.Select(); primary != "udp-relay" {
		t.Fatalf("replacement = %q, want udp-relay (direct-udp is MTU-limited)", primary)
	}
	s.SetForced("direct-udp")
	if primary, _, _ := s.Select(); primary != "direct-udp" {
		t.Fatalf("forced primary = %q, want limited direct-udp still selectable when forced", primary)
	}
}

// mtuHarness drives one client-side direct-udp candidate's probe exchange
// through a fakeBind, acknowledging MTU probes only up to pathLimit.
type mtuHarness struct {
	t         *testing.T
	base      *fakeBind
	m         *MultipathBind
	ep        fakeEndpoint
	pathLimit uint16
}

func newMTUHarness(t *testing.T, opts MultipathOptions, pathLimit uint16) *mtuHarness {
	h := &mtuHarness{t: t, base: &fakeBind{}, ep: fakeEndpoint{id: "direct"}, pathLimit: pathLimit}
	h.m = NewMultipathBind(h.base, "server", true, opts)
	t.Cleanup(func() { _ = h.m.Close() })
	h.m.RegisterPath("direct-udp", PathDirect, h.ep)
	return h
}

// deliver answers every frame sent since the last call the way a
// path-mtu-v1 peer behind a pathLimit-byte path would.
func (h *mtuHarness) deliver() {
	h.base.mu.Lock()
	sent := h.base.sent
	h.base.sent, h.base.dests = nil, nil
	h.base.mu.Unlock()
	for _, frame := range sent {
		typ, payload, ok := DecodeControlFrame(frame)
		if !ok {
			continue
		}
		switch typ {
		case FramePathProbe:
			h.m.handlePathControl(FramePathAck, payload, h.ep)
		case FramePathMTUProbe:
			if probe, ok := DecodePathMTUProbe(payload); ok && probe.Target <= h.pathLimit {
				h.m.handlePathControl(FramePathMTUAck, EncodePathMTUAck(probe.Nonce, probe.Target), h.ep)
			}
		}
	}
}

func (h *mtuHarness) state() PathStatus {
	for _, p := range h.m.Paths() {
		if p.Name == "direct-udp" {
			return p
		}
	}
	h.t.Fatal("direct-udp not registered")
	return PathStatus{}
}

func TestMultipathBindMTUAware_LimitedAfterRetries(t *testing.T) {
	h := newMTUHarness(t, MultipathOptions{MTUAware: true}, 1400)
	if got := h.state().MTUState; got != MTUStateProbing {
		t.Fatalf("initial mtu_state = %q, want probing", got)
	}
	for i := 0; i < 4; i++ {
		h.deliver() // health ack -> 1200 -> 1400 -> 1452 (dropped)
	}
	now := time.Now()
	for attempt := 1; attempt <= mtuMaxAttempts; attempt++ {
		now = now.Add(mtuProbeTimeout)
		h.m.driveMTU("direct-udp", now)
		h.deliver()
	}
	st := h.state()
	if st.MTUState != MTUStateLimited {
		t.Fatalf("state = %q, want limited (1452 never acknowledged)", st.MTUState)
	}
}

func TestMultipathBindMTUAware_OKWhenRequiredSizePasses(t *testing.T) {
	h := newMTUHarness(t, MultipathOptions{MTUAware: true}, 1500)
	for i := 0; i < 6; i++ {
		h.deliver()
	}
	st := h.state()
	if st.MTUState != MTUStateOK || st.DatagramMTU != 1500 {
		t.Fatalf("state = %q mtu=%d, want ok at 1500", st.MTUState, st.DatagramMTU)
	}
}

func TestMultipathBindMTUAware_RetryRecoversLostProbe(t *testing.T) {
	h := newMTUHarness(t, MultipathOptions{MTUAware: true}, 1500)
	h.deliver() // health ack -> 1200 sent
	h.base.reset()
	// The 1200 probe was lost. A retry after the timeout resends it.
	h.m.driveMTU("direct-udp", time.Now().Add(mtuProbeTimeout))
	for i := 0; i < 6; i++ {
		h.deliver()
	}
	if st := h.state(); st.MTUState != MTUStateOK {
		t.Fatalf("state = %q after a lost probe, want ok", st.MTUState)
	}
}

func TestMultipathBindMTUAware_DefaultUnchanged(t *testing.T) {
	h := newMTUHarness(t, MultipathOptions{}, 1400)
	for i := 0; i < 6; i++ {
		h.deliver()
	}
	st := h.state()
	if st.MTUState != "" {
		t.Fatalf("default mtu_state = %q, want empty", st.MTUState)
	}
	if st.DatagramMTU != 1420 {
		t.Fatalf("default datagram MTU = %d, want the unchanged 1420 floor", st.DatagramMTU)
	}
}

func TestServerMultipathMTUAware_LimitedAfterRetries(t *testing.T) {
	base := &fakeBind{}
	m := NewServerMultipathBind(base, MultipathOptions{MTUAware: true})
	defer m.Close()
	ep := fakeEndpoint{id: "client-direct"}
	m.RegisterPath("peer-1", "direct-udp", PathDirect, ep, true)
	m.mu.RLock()
	p := m.peers["peer-1"]
	m.mu.RUnlock()
	deliver := func() {
		base.mu.Lock()
		sent := base.sent
		base.sent, base.dests = nil, nil
		base.mu.Unlock()
		for _, frame := range sent {
			typ, payload, ok := DecodeControlFrame(frame)
			if !ok {
				continue
			}
			switch typ {
			case FramePathProbe:
				m.dispatchControl(p, FramePathAck, payload, ep)
			case FramePathMTUProbe:
				if probe, ok := DecodePathMTUProbe(payload); ok && probe.Target <= 1200 {
					m.dispatchControl(p, FramePathMTUAck, EncodePathMTUAck(probe.Nonce, probe.Target), ep)
				}
			}
		}
	}
	for i := 0; i < 3; i++ {
		deliver()
	}
	now := time.Now()
	for i := 0; i < mtuMaxAttempts; i++ {
		now = now.Add(mtuProbeTimeout)
		m.driveMTU(p, "direct-udp", now)
		deliver()
	}
	for _, st := range p.scheduler.Status() {
		if st.Name == "direct-udp" && st.MTUState != MTUStateLimited {
			t.Fatalf("server mtu_state = %q, want limited", st.MTUState)
		}
	}
}
