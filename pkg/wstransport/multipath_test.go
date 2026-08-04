package wstransport

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestSchedulerSelectsBestAndDuplicatesOnlyWhenNeeded(t *testing.T) {
	s := NewScheduler()
	s.Register("wss", PathWSS)
	s.Register("relay", PathUDPRelay)
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("wss", 300*time.Millisecond, true, now)
		s.ProbeResult("relay", 20*time.Millisecond, true, now)
	}
	primary, alternate, dup := s.Select()
	if primary != "relay" || alternate != "" || dup {
		t.Fatalf("healthy paths = %q %q %v, want relay only", primary, alternate, dup)
	}
	// One loss in a twenty-result rolling window reaches the 5% threshold.
	for i := 0; i < 16; i++ {
		s.ProbeResult("relay", 20*time.Millisecond, true, now)
	}
	s.ProbeResult("relay", 0, false, now)
	primary, alternate, dup = s.Select()
	if primary != "wss" || alternate != "relay" || !dup {
		t.Fatalf("loss trigger = %q %q %v", primary, alternate, dup)
	}
}

func TestSchedulerRecoversAfterThreeMisses(t *testing.T) {
	s := NewScheduler()
	s.Register("wss", PathWSS)
	now := time.Now()
	s.ProbeResult("wss", time.Millisecond, true, now)
	for i := 0; i < 3; i++ {
		s.ProbeResult("wss", 0, false, now)
	}
	if p, _, _ := s.Select(); p != "" {
		t.Fatalf("unhealthy candidate selected: %q", p)
	}
	s.ProbeResult("wss", 2*time.Millisecond, true, now)
	if p, _, _ := s.Select(); p != "wss" {
		t.Fatalf("recovered candidate = %q", p)
	}
}

func TestDuplicateCacheTransportOnlyAndExpiry(t *testing.T) {
	c := NewDuplicateCache(2, time.Second)
	now := time.Now()
	p := make([]byte, 32)
	binary.LittleEndian.PutUint32(p, 4)
	binary.LittleEndian.PutUint32(p[4:], 7)
	binary.LittleEndian.PutUint64(p[8:], 9)
	if c.Seen(p, now) || !c.Seen(p, now) {
		t.Fatal("transport duplicate suppression failed")
	}
	if c.Seen(p, now.Add(2*time.Second)) {
		t.Fatal("expired entry still suppressed")
	}
	handshake := append([]byte(nil), p...)
	binary.LittleEndian.PutUint32(handshake, 1)
	if c.Seen(handshake, now) || c.Seen(handshake, now) {
		t.Fatal("handshake was suppressed")
	}
	other := append([]byte(nil), p...)
	binary.LittleEndian.PutUint64(other[8:], 10)
	if c.Seen(other, now) {
		t.Fatal("distinct counter was suppressed")
	}
}

func TestValidPathControl(t *testing.T) {
	if !ValidPathControl(FramePathProbe, make([]byte, 8)) || !ValidPathControl(FramePathAck, make([]byte, 8)) {
		t.Fatal("valid fixed control frame rejected")
	}
	if ValidPathControl(FramePathProbe, nil) || ValidPathControl(FramePrime, make([]byte, 8)) {
		t.Fatal("invalid control frame accepted")
	}
}
