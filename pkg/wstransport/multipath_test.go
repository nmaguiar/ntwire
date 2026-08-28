package wstransport

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPathStatusJSONUsesStatusAPIFieldNames(t *testing.T) {
	b, err := json.Marshal(PathStatus{
		Name: "udp-relay", Kind: PathUDPRelay, Healthy: true, RTT: 12 * time.Millisecond, Loss: 0.1,
		DuplicatedBytes: 100, DuplicationSuppressedBytes: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`"name":"udp-relay"`, `"kind":"udp-relay"`, `"healthy":true`, `"rtt":12000000`, `"loss":0.1`,
		`"duplicated_bytes":100`, `"duplication_suppressed_bytes":25`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Marshal() = %s, missing %s", got, want)
		}
	}
	if strings.Contains(got, `"Name"`) || strings.Contains(got, `"RTT"`) {
		t.Errorf("Marshal() = %s, contains Go field names", got)
	}
}

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
	if primary != "relay" || alternate != "wss" || !dup {
		t.Fatalf("loss trigger = %q %q %v", primary, alternate, dup)
	}
}

// TestRecordDuplicationTracksAllowedAndSuppressedSeparately checks
// RecordDuplication's contract: allowed bytes accumulate into
// DuplicatedBytes, budget-denied bytes accumulate into
// DuplicationSuppressedBytes, and the two counters never mix -- the
// inspectable signal MultipathBind.Send's duplication budget relies on (see
// item 6, "add per-path counters").
func TestRecordDuplicationTracksAllowedAndSuppressedSeparately(t *testing.T) {
	s := NewScheduler()
	s.Register("relay", PathUDPRelay)
	s.RecordDuplication("relay", 100, true)
	s.RecordDuplication("relay", 40, true)
	s.RecordDuplication("relay", 25, false)
	status := s.Status()
	if len(status) != 1 {
		t.Fatalf("status len = %d, want 1", len(status))
	}
	if status[0].DuplicatedBytes != 140 {
		t.Fatalf("DuplicatedBytes = %d, want 140", status[0].DuplicatedBytes)
	}
	if status[0].DuplicationSuppressedBytes != 25 {
		t.Fatalf("DuplicationSuppressedBytes = %d, want 25", status[0].DuplicationSuppressedBytes)
	}
	// An unregistered candidate must be a silent no-op, not a panic.
	s.RecordDuplication("no-such-candidate", 10, true)
}

func TestSchedulerSelectsWSSWhenItOutperformsDirectUDP(t *testing.T) {
	s := NewScheduler()
	s.Register("direct-udp", PathDirect)
	s.Register("wss", PathWSS)
	now := time.Now()
	for i := 0; i < 4; i++ {
		s.ProbeResult("direct-udp", 80*time.Millisecond, true, now)
		s.ProbeResult("wss", 40*time.Millisecond, true, now)
	}
	if primary, _, _ := s.Select(); primary != "wss" {
		t.Fatalf("primary = %q, want wss when it has half the direct-UDP RTT", primary)
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

func TestActivateCarrierPinsInitialIncumbentAgainstFasterProbe(t *testing.T) {
	s := NewScheduler()
	s.Register("wss", PathWSS)
	s.ActivateCarrier("wss", time.Now())
	s.Register("direct-udp", PathDirect)
	for i := 0; i < 4; i++ {
		s.ProbeResult("direct-udp", time.Millisecond, true, time.Now())
	}
	if primary, alternate, duplicate := s.Select(); primary != "wss" || alternate != "" || duplicate {
		t.Fatalf("selection = %q %q %v, want WSS bootstrap incumbent without duplication", primary, alternate, duplicate)
	}
}

func TestWSSUsesCarrierLifecycleInsteadOfActiveProbes(t *testing.T) {
	s := NewScheduler()
	s.Register("wss", PathWSS)
	s.Register("direct-udp", PathDirect)
	if s.requiresActiveProbe("wss") {
		t.Fatal("WSS unexpectedly requires an active payload-stream probe")
	}
	if !s.requiresActiveProbe("direct-udp") {
		t.Fatal("direct UDP must require active reachability probes")
	}
}

func TestSchedulerStreamCarrierRetainsEscapeRouteAndRecoversAfterReconnect(t *testing.T) {
	s := NewScheduler()
	s.Register("wss", PathWSS)
	now := time.Now()
	s.ActivateCarrier("wss", now)
	if p, _, _ := s.Select(); p != "wss" {
		t.Fatalf("initial candidate = %q, want wss", p)
	}
	s.CarrierFailure("wss")
	if p, _, _ := s.Select(); p != "wss" {
		t.Fatalf("degraded sole candidate = %q, want last incumbent wss", p)
	}
	s.ActivateCarrier("wss", now)
	if p, _, _ := s.Select(); p != "wss" {
		t.Fatalf("recovered candidate = %q", p)
	}
}

func TestSchedulerCarrierFailureImmediatelySelectsStandby(t *testing.T) {
	s := NewScheduler()
	s.Register("wss", PathWSS)
	s.Register("direct-udp", PathDirect)
	now := time.Now()
	s.ActivateCarrier("wss", now)
	s.ProbeResult("direct-udp", 2*time.Millisecond, true, now)
	if p, _, _ := s.Select(); p != "wss" {
		t.Fatalf("initial primary = %q, want wss", p)
	}
	s.CarrierFailure("wss")
	if p, _, _ := s.Select(); p != "direct-udp" {
		t.Fatalf("primary after carrier failure = %q, want direct-udp", p)
	}
	s.ActivateCarrier("wss", now)
	for _, path := range s.Status() {
		if path.Name == "wss" && !path.Healthy {
			t.Fatal("carrier reconnect did not recover failed WSS path")
		}
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

func TestValidateTransportName(t *testing.T) {
	if got, err := ValidateTransportName("websocket"); err != nil || got != "wss" {
		t.Fatalf("websocket = %q, %v", got, err)
	}
	if _, err := ValidateTransportName("wsss"); err == nil {
		t.Fatal("invalid transport accepted")
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

func TestPathMTUProbeBoundsAndRoundTrip(t *testing.T) {
	var nonce [pathProbeSize]byte
	probe := EncodePathMTUProbe(nonce, 1400)
	if len(EncodeControlFrame(FramePathMTUProbe, probe)) != 1400 {
		t.Fatal("MTU probe did not reach requested datagram size")
	}
	got, ok := DecodePathMTUProbe(probe)
	if !ok || got.Target != 1400 {
		t.Fatalf("decoded probe = %#v, %v", got, ok)
	}
	if _, ok := DecodePathMTUProbe(probe[:len(probe)-1]); ok {
		t.Fatal("truncated probe accepted")
	}
}

func TestSchedulerCachesOnlyConfirmedConservativeMTU(t *testing.T) {
	s := NewScheduler()
	s.Register("udp-relay", PathUDPRelay)
	s.ReportDatagramMTU("udp-relay", 1400)
	s.ReportDatagramMTU("udp-relay", 1200)
	s.ReportDatagramMTU("udp-relay", MaxRelayDatagram+1)
	if got := s.Status()[0].DatagramMTU; got != 1420 {
		t.Fatalf("datagram MTU = %d, want 1420", got)
	}
	s.ReportDatagramMTU("udp-relay", 1500)
	if got := s.Status()[0].DatagramMTU; got != 1500 {
		t.Fatalf("datagram MTU = %d, want 1500", got)
	}
}

// TestSelectDoesNotSwitchHealthyIncumbentOnScoreGap protects v3's sticky
// primary: score changes are diagnostic/ranking input for failure recovery,
// not permission to reorder a live flow between carriers.
func TestSelectDoesNotSwitchHealthyIncumbentOnScoreGap(t *testing.T) {
	s := NewScheduler()
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
	for i := 0; i < 20; i++ {
		s.ProbeResult("a", 500*time.Millisecond, true, now)
		s.ProbeResult("b", time.Millisecond, true, now)
	}
	if primary, alternate, duplicate := s.Select(); primary != "a" || alternate != "" || duplicate {
		t.Fatalf("selection after score gap = %q %q %v, want sticky a without payload duplication", primary, alternate, duplicate)
	}
}

// TestSelectFailsOverInstantlyWhenIncumbentUnhealthy checks
// selectLocked's documented exception: an incumbent that drops out of the
// healthy set fails over immediately despite the normal sticky policy.
func TestSelectFailsOverInstantlyWhenIncumbentUnhealthy(t *testing.T) {
	s := NewScheduler()
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

// TestSelectRetainsIncumbentWithoutLegacyV1Flapping shows that the scheduler
// no longer has a less-safe v1 mode: all automatic selections are sticky.
func TestSelectRetainsIncumbentWithoutLegacyV1Flapping(t *testing.T) {
	s := NewScheduler()
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
		t.Fatalf("primary = %q, want sticky wss incumbent", primary)
	}
}

func TestSchedulerForcedSelectionAndFallback(t *testing.T) {
	s := NewScheduler()
	s.Register("wss", PathWSS)
	s.Register("udp-relay", PathUDPRelay)
	s.Register("direct-udp", PathDirect)
	now := time.Now()

	s.ProbeResult("wss", 100*time.Millisecond, true, now)
	s.ProbeResult("udp-relay", 50*time.Millisecond, true, now)
	s.ProbeResult("direct-udp", 10*time.Millisecond, true, now)

	// Automatic mode should pick direct-udp (lowest score/latency)
	primary, _, _ := s.Select()
	if primary != "direct-udp" {
		t.Fatalf("automatic primary = %q, want direct-udp", primary)
	}

	// Force wss manually
	s.SetForced("wss")
	if s.Forced() != "wss" {
		t.Fatalf("Forced() = %q, want wss", s.Forced())
	}
	primary, _, _ = s.Select()
	if primary != "wss" {
		t.Fatalf("forced primary = %q, want wss", primary)
	}

	// Verify Status() reflects forced path
	statuses := s.Status()
	var wssStatus, directStatus *PathStatus
	for i := range statuses {
		if statuses[i].Name == "wss" {
			wssStatus = &statuses[i]
		}
		if statuses[i].Name == "direct-udp" {
			directStatus = &statuses[i]
		}
	}
	if wssStatus == nil || !wssStatus.Primary || !wssStatus.Forced {
		t.Fatalf("wssStatus = %+v, want Primary=true, Forced=true", wssStatus)
	}
	if directStatus == nil || directStatus.Primary || directStatus.Forced {
		t.Fatalf("directStatus = %+v, want Primary=false, Forced=false", directStatus)
	}

	// Now make forced "wss" unhealthy (3 misses)
	for i := 0; i < 3; i++ {
		s.ProbeResult("wss", 0, false, now)
	}
	// Fallback to automatic: direct-udp should become primary!
	primary, _, _ = s.Select()
	if primary != "direct-udp" {
		t.Fatalf("fallback primary = %q, want direct-udp", primary)
	}

	// Recover wss: it should regain primary because user forced it!
	s.ProbeResult("wss", 100*time.Millisecond, true, now)
	primary, _, _ = s.Select()
	if primary != "wss" {
		t.Fatalf("recovered forced primary = %q, want wss", primary)
	}

	// Clear forced mode (set to "auto" or "")
	s.SetForced("auto")
	if s.Forced() != "" {
		t.Fatalf("Forced() after auto = %q, want empty", s.Forced())
	}
	primary, _, _ = s.Select()
	if primary != "wss" {
		t.Fatalf("auto primary = %q, want current healthy incumbent wss", primary)
	}
}
