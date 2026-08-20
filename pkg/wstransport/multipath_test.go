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

// TestRegisterPathStartsUnhealthy is a regression test for the bug that made
// a multipath-v1 session a permanent split-brain: a candidate must start
// unhealthy at registration and only become healthy once a real probe/ack
// round trip completes -- never from a synthetic seed baked into
// RegisterPath/Register themselves.
func TestRegisterPathStartsUnhealthy(t *testing.T) {
	s := NewScheduler()
	s.Register("udp-relay", PathUDPRelay)
	if primary, _, _ := s.Select(); primary != "" {
		t.Fatalf("primary immediately after Register = %q, want none", primary)
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
	if !ValidPathControl(FramePathProbe, make([]byte, pathProbeSize)) || !ValidPathControl(FramePathAck, make([]byte, pathProbeSize)) {
		t.Fatal("valid fixed control frame rejected")
	}
	if ValidPathControl(FramePathProbe, nil) || ValidPathControl(FramePrime, make([]byte, pathProbeSize)) {
		t.Fatal("invalid control frame accepted")
	}
}

// TestPathProbeFrameClearsValidDatagramFloor guards against a regression that
// once made every WSS-carried candidate permanently unhealthy: an encoded
// probe/ack frame must be large enough to survive ValidDatagram's 16-byte
// floor, since Bind.Send/read (the WSS carrier) silently drops anything
// smaller with no error.
func TestPathProbeFrameClearsValidDatagramFloor(t *testing.T) {
	frame := EncodeControlFrame(FramePathProbe, make([]byte, pathProbeSize))
	if !ValidDatagram(frame) {
		t.Fatalf("encoded probe frame (%d bytes) does not clear ValidDatagram's floor", len(frame))
	}
}

// TestScoreNeutralWithNoDeliveryRatioData guards the bootstrap case score's
// doc comment calls out explicitly: a candidate with no comparable
// delivery-ratio sample yet (DeliveryRatio == -1) must add no penalty at
// all, not be scored as if it had confirmed total loss.
func TestScoreNeutralWithNoDeliveryRatioData(t *testing.T) {
	s := NewScheduler()
	p := &candidate{PathStatus: PathStatus{DeliveryRatio: -1}}
	if got := s.score(p); got != 0 {
		t.Fatalf("score with no delivery-ratio data = %v, want 0", got)
	}
}

// TestScoreDeliveryRatioPenaltyScalesAndCaps exercises score's throughput
// term directly: no penalty at or above minDeliveryRatio, a penalty scaled
// linearly by shortfall below it, and the natural cap at DeliveryRatio == 0
// (shortfall == 1) landing exactly at maxThroughputPenalty.
func TestScoreDeliveryRatioPenaltyScalesAndCaps(t *testing.T) {
	s := NewScheduler() // defaults: minDeliveryRatio=0.85, maxThroughputPenalty=500ms
	atThreshold := &candidate{PathStatus: PathStatus{DeliveryRatio: defaultMinDeliveryRatio}}
	if got := s.score(atThreshold); got != 0 {
		t.Fatalf("score at threshold ratio = %v, want 0", got)
	}
	// shortfall = (0.85-0.425)/0.85 = 0.5 -> penalty = 250ms.
	halfShortfall := &candidate{PathStatus: PathStatus{DeliveryRatio: defaultMinDeliveryRatio / 2}}
	wantHalf := time.Duration(0.5 * float64(defaultMaxThroughputPenalty))
	if got := s.score(halfShortfall); got != wantHalf {
		t.Fatalf("score at half shortfall = %v, want %v", got, wantHalf)
	}
	zero := &candidate{PathStatus: PathStatus{DeliveryRatio: 0}}
	if got := s.score(zero); got != defaultMaxThroughputPenalty {
		t.Fatalf("score at zero delivery ratio = %v, want capped at %v", got, defaultMaxThroughputPenalty)
	}
}

// TestReportDeliveryRatioClampsAndSmooths checks the three properties
// ReportDeliveryRatio's doc comment promises: out-of-range inputs clamp to
// [0,1], the first sample sets the value directly (no smoothing against the
// -1 sentinel), and every subsequent sample is EWMA-smoothed like RTT.
func TestReportDeliveryRatioClampsAndSmooths(t *testing.T) {
	s := NewScheduler()
	s.Register("a", PathWSS)
	s.ReportDeliveryRatio("a", 2.0) // out of range: clamp to 1, first sample sets directly
	if got := s.Status()[0].DeliveryRatio; got != 1.0 {
		t.Fatalf("first (clamped) sample = %v, want 1.0", got)
	}
	s.ReportDeliveryRatio("a", -5.0) // out of range: clamp to 0, then EWMA-smoothed against 1.0
	want := (1.0*7 + 0.0) / 8
	if got := s.Status()[0].DeliveryRatio; got != want {
		t.Fatalf("smoothed sample = %v, want %v", got, want)
	}
}

// TestSelectHysteresisMarginBlocksSmallFlap is the flap-prevention test the
// plan's Testing section calls out explicitly: once a delivery-ratio sample
// makes the challenger's score gap over the incumbent smaller than
// switchMargin, primary must not flip.
func TestSelectHysteresisMarginBlocksSmallFlap(t *testing.T) {
	s := NewScheduler()
	s.SetV2Options(V2Options{SwitchMargin: 50 * time.Millisecond, MinDwell: time.Millisecond})
	s.Register("a", PathWSS)
	s.Register("b", PathUDPRelay)
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("a", 10*time.Millisecond, true, now)
		s.ProbeResult("b", 12*time.Millisecond, true, now)
	}
	if primary, _, _ := s.Select(); primary != "a" {
		t.Fatalf("initial primary = %q, want a", primary)
	}
	time.Sleep(2 * time.Millisecond) // clear the 1ms MinDwell
	// shortfall*500ms = 40ms -> raises a's score by 40ms, to 12ms above b's
	// raw 12ms -- under the 50ms margin.
	s.ReportDeliveryRatio("a", defaultMinDeliveryRatio*(1-0.08))
	if primary, _, _ := s.Select(); primary != "a" {
		t.Fatalf("primary flapped to %q on a sub-margin score gap, want a to remain incumbent", primary)
	}
}

// TestSelectSwitchesWhenGapExceedsMarginAndDwellSatisfied is
// TestSelectHysteresisMarginBlocksSmallFlap's counterpart: once the gap
// clears the margin and dwell has elapsed, the switch does commit.
func TestSelectSwitchesWhenGapExceedsMarginAndDwellSatisfied(t *testing.T) {
	s := NewScheduler()
	s.SetV2Options(V2Options{SwitchMargin: 50 * time.Millisecond, MinDwell: time.Millisecond})
	s.Register("a", PathWSS)
	s.Register("b", PathUDPRelay)
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("a", 10*time.Millisecond, true, now)
		s.ProbeResult("b", 12*time.Millisecond, true, now)
	}
	if primary, _, _ := s.Select(); primary != "a" {
		t.Fatalf("initial primary = %q, want a", primary)
	}
	time.Sleep(2 * time.Millisecond)
	// shortfall*500ms = 80ms -> raises a's score 80ms above b's, over margin.
	s.ReportDeliveryRatio("a", defaultMinDeliveryRatio*(1-0.16))
	if primary, _, _ := s.Select(); primary != "b" {
		t.Fatalf("primary = %q after exceeding switch margin, want b", primary)
	}
}

// TestSelectMinDwellBlocksImmediateSwitch checks the other half of
// hysteresis: even a large, clearly-over-margin score gap must not switch
// primary before the incumbent has held the role for MinDwell.
func TestSelectMinDwellBlocksImmediateSwitch(t *testing.T) {
	s := NewScheduler()
	s.SetV2Options(V2Options{SwitchMargin: 10 * time.Millisecond, MinDwell: time.Hour})
	s.Register("a", PathWSS)
	s.Register("b", PathUDPRelay)
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("a", 10*time.Millisecond, true, now)
		s.ProbeResult("b", 12*time.Millisecond, true, now)
	}
	if primary, _, _ := s.Select(); primary != "a" {
		t.Fatalf("initial primary = %q, want a", primary)
	}
	s.ReportDeliveryRatio("a", 0) // maximal shortfall: b is now the clear best by any margin
	if primary, _, _ := s.Select(); primary != "a" {
		t.Fatalf("primary = %q immediately after becoming clearly worse, want a to remain incumbent until MinDwell elapses", primary)
	}
}

// TestSelectFailsOverInstantlyWhenIncumbentUnhealthyDespiteHysteresis checks
// selectLocked's documented exception: an incumbent that drops out of the
// healthy set fails over immediately, even with a MinDwell/SwitchMargin
// large enough to block every other kind of switch.
func TestSelectFailsOverInstantlyWhenIncumbentUnhealthyDespiteHysteresis(t *testing.T) {
	s := NewScheduler()
	s.SetV2Options(V2Options{SwitchMargin: time.Hour, MinDwell: time.Hour})
	s.Register("a", PathWSS)
	s.Register("b", PathUDPRelay)
	now := time.Now()
	s.ProbeResult("a", time.Millisecond, true, now)
	s.ProbeResult("b", time.Millisecond, true, now)
	incumbent, _, _ := s.Select()
	if incumbent == "" {
		t.Fatal("no primary selected")
	}
	for i := 0; i < 3; i++ {
		s.ProbeResult(incumbent, 0, false, now)
	}
	if primary, _, _ := s.Select(); primary == incumbent || primary == "" {
		t.Fatalf("primary = %q after incumbent went unhealthy, want failover to the other candidate", primary)
	}
}

// TestSelectV2ProtectsIncumbentFromUnsampledChallenger is a regression test
// for a production incident: a UDP-relay candidate answered health probes
// perfectly (great RTT, 0% loss) while silently dropping every real
// WireGuard packet, and immediately stole primary from a working WSS
// incumbent on probe RTT alone. With CapabilityMultipathV2 negotiated, a
// challenger with no ReportDeliveryRatio sample yet must not unseat a
// healthy incumbent no matter how much better its raw probe score is.
func TestSelectV2ProtectsIncumbentFromUnsampledChallenger(t *testing.T) {
	s := NewScheduler()
	s.SetV2(true)
	s.Register("wss", PathWSS)
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("wss", 70*time.Millisecond, true, now)
	}
	if primary, _, _ := s.Select(); primary != "wss" {
		t.Fatalf("initial primary = %q, want wss", primary)
	}
	s.Register("udp-relay", PathUDPRelay)
	for i := 0; i < 4; i++ {
		s.ProbeResult("udp-relay", time.Millisecond, true, now) // far better RTT, still unsampled
	}
	if primary, _, _ := s.Select(); primary != "wss" {
		t.Fatalf("primary = %q after an unsampled challenger registered with better RTT, want wss to remain incumbent", primary)
	}
}

// TestSelectV1StillSwitchesImmediatelyToUnsampledChallenger shows the
// protection above is v2-specific: v1 has no delivery-ratio signal to wait
// for, so it keeps switching on RTT/loss alone exactly as before.
func TestSelectV1StillSwitchesImmediatelyToUnsampledChallenger(t *testing.T) {
	s := NewScheduler() // v2 left false
	s.Register("wss", PathWSS)
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("wss", 70*time.Millisecond, true, now)
	}
	s.Register("udp-relay", PathUDPRelay)
	for i := 0; i < 4; i++ {
		s.ProbeResult("udp-relay", time.Millisecond, true, now)
	}
	if primary, _, _ := s.Select(); primary != "udp-relay" {
		t.Fatalf("primary = %q, want immediate v1 switch to udp-relay", primary)
	}
}

// TestSelectV2PromotesChallengerOnceDeliveryProven confirms the incumbent
// protection is temporary, not a permanent freeze: once the challenger earns
// a real delivery-ratio sample and clears the usual margin+dwell hysteresis,
// it can still become primary.
func TestSelectV2PromotesChallengerOnceDeliveryProven(t *testing.T) {
	s := NewScheduler()
	s.SetV2Options(V2Options{SwitchMargin: 5 * time.Millisecond, MinDwell: time.Millisecond})
	s.SetV2(true)
	s.Register("wss", PathWSS)
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("wss", 70*time.Millisecond, true, now)
	}
	if primary, _, _ := s.Select(); primary != "wss" {
		t.Fatalf("initial primary = %q, want wss", primary)
	}
	s.Register("udp-relay", PathUDPRelay)
	for i := 0; i < 4; i++ {
		s.ProbeResult("udp-relay", time.Millisecond, true, now)
	}
	if primary, _, _ := s.Select(); primary != "wss" {
		t.Fatalf("primary = %q before any delivery sample, want wss protected", primary)
	}
	time.Sleep(2 * time.Millisecond) // clear MinDwell
	s.ReportDeliveryRatio("udp-relay", 1.0)
	if primary, _, _ := s.Select(); primary != "udp-relay" {
		t.Fatalf("primary = %q after udp-relay proved perfect delivery, want it promoted", primary)
	}
}
