package client

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

func TestTransitionTransportCandidateLogsSelectedMultipathPrimary(t *testing.T) {
	multipath := wstransport.NewMultipathBind(conn.NewStdNetBind(), "server", false, wstransport.V2Options{})
	defer multipath.Close()
	now := time.Now()
	multipath.Scheduler().Register("wss", wstransport.PathWSS)
	multipath.Scheduler().ProbeResult("wss", time.Millisecond, true, now)
	multipath.Scheduler().Register("udp-relay", wstransport.PathUDPRelay)
	multipath.Scheduler().ProbeResult("udp-relay", 20*time.Millisecond, true, now)

	var logs bytes.Buffer
	c := &Connection{multipath: multipath, log: slog.New(slog.NewTextHandler(&logs, nil))}
	c.transport.Store(uint32(transportWSSRelay))
	c.transitionTransportCandidate(transportStateUDPRelay, "UDP relay path established")

	got := logs.String()
	for _, want := range []string{
		"msg=\"transport candidate state changed\"",
		"event=transport_candidate_transition",
		"candidate_from=WSS",
		"candidate_to=\"UDP via relay\"",
		"primary=WSS",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log = %q, missing %q", got, want)
		}
	}
	if strings.Contains(got, "msg=\"transport state changed\"") {
		t.Errorf("multipath candidate log must not claim an active transport transition: %q", got)
	}
}
