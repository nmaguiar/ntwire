package client

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// Opt in because relay accounting is published on a real 30-second cadence.
// The fixture has two independent relay instances on the same host.
func TestAdaptiveRelayPerformance_LoadAndForwardedBytes(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_RELAY_LOAD") != "1" {
		t.Skip("set NTWIRE_TEST_RELAY_LOAD=1 to measure both relays")
	}
	type egress struct{ toClient, toServer uint64 }
	type snapshot struct {
		member int
		at     time.Time
		bytes  egress
	}
	reports := make(chan snapshot, 32)
	c, stopRelays := newRelayPerformanceFixture(t, 2<<20, func(index int, report protocol.RelayUDPStatsReport) {
		var sent egress
		for _, s := range report.Sessions {
			sent.toServer += s.ServerBytesForwarded
			sent.toClient += s.ClientBytesForwarded
		}
		select {
		case reports <- snapshot{index, time.Now(), sent}:
		case <-t.Context().Done():
		}
	})
	readBoth := func() [2]egress {
		t.Helper()
		start := time.Now()
		timeout := time.NewTimer(40 * time.Second)
		defer timeout.Stop()
		var seen [2]bool
		var totals [2]egress
		for !seen[0] || !seen[1] {
			select {
			case s := <-reports:
				if !s.at.Before(start) {
					seen[s.member], totals[s.member] = true, s.bytes
				}
			case <-timeout.C:
				t.Fatal("missing fresh relay accounting snapshot")
			}
		}
		return totals
	}
	a := c.network.adaptive
	if !a.exploration.CompareAndSwap(false, true) {
		t.Fatal("expected an idle lane before starting the load fixture")
	}
	defer a.exploration.Store(false)
	var flows []net.Conn
	for range 4 {
		flows = append(flows, dialLaneTest(t, "tcp", c.LocalAddresses[0]))
	}
	before := readBoth()
	var first string
	for member, name := range []string{"direct-wss", "relay-a", "relay-b"} {
		expected := protocol.CarrierWSS
		if member > 0 {
			if err := a.qualifyRelay(t.Context()); err != nil {
				t.Fatal(err)
			}
			expected = a.qualifiedRelayStandby(first)
			if member == 1 {
				first = expected
			}
			if err := a.selectPrimary(t.Context(), expected); err != nil {
				t.Fatal(err)
			}
		}
		delivered := measureAdaptiveRelayFlows(t, flows, nil)
		if selected, _, _ := a.bind.LaneState(a.lane); selected != expected {
			t.Fatalf("%s changed carrier under load", name)
		}
		after := readBoth()
		var forwarded uint64
		for index, totals := range after {
			if totals.toClient < before[index].toClient || totals.toServer < before[index].toServer {
				t.Fatal("relay counters reset within the measurement")
			}
			toClient := totals.toClient - before[index].toClient
			toServer := totals.toServer - before[index].toServer
			if member == 0 && toClient+toServer != 0 || member == index+1 && (toClient < delivered/2 || toServer < delivered/2) {
				t.Fatalf("%s: unexpected relay %d byte deltas %d/%d for %d bidirectional payload bytes", name, index+1, toClient, toServer, delivered)
			}
			t.Logf("path=%s relay=%d bytes_to_client=%d bytes_to_server=%d", name, index+1, toClient, toServer)
			forwarded += toClient + toServer
		}
		t.Logf("path=%s relay_egress_per_payload_byte=%.3f", name, float64(forwarded)/float64(delivered))
		before = after
	}
	lost, _, _ := a.bind.LaneState(a.lane)
	measureAdaptiveRelayFlows(t, flows, stopRelays[1])
	if path, _, _ := a.bind.LaneState(a.lane); path == lost || path == "" {
		t.Fatal("lost relay remained primary after failover")
	}
	t.Logf("recovered_carrier=%s", c.TransportInfo().Active)
}

func measureAdaptiveRelayFlows(t *testing.T, flows []net.Conn, interrupt func() error) uint64 {
	t.Helper()
	const size = 8 << 10
	type result struct {
		samples []time.Duration
		resumed time.Time
		err     error
	}
	done := make(chan result, len(flows))
	ready := make(chan struct{}, len(flows))
	fault := make(chan struct{})
	start := time.Now()
	for i, flow := range flows {
		go func() {
			payload := bytes.Repeat([]byte{byte(i + 1)}, size)
			reply := make([]byte, size)
			var r result
			defer func() { done <- r }()
			for time.Since(start) < 3*time.Second || (interrupt != nil && r.resumed.IsZero()) {
				postFault := false
				select {
				case <-fault:
					postFault = true
				default:
				}
				begin := time.Now()
				_ = flow.SetDeadline(begin.Add(20 * time.Second))
				if _, r.err = flow.Write(payload); r.err != nil {
					return
				}
				if _, r.err = io.ReadFull(flow, reply); r.err != nil {
					return
				}
				if !bytes.Equal(payload, reply) {
					r.err = fmt.Errorf("echo mismatch on stream %d", i)
					return
				}
				now := time.Now()
				if len(r.samples) == 0 {
					ready <- struct{}{}
				}
				r.samples = append(r.samples, now.Sub(begin))
				if postFault && r.resumed.IsZero() {
					r.resumed = now
				}
			}
		}()
	}
	var stopped time.Time
	if interrupt != nil {
		timer := time.NewTimer(20 * time.Second)
		defer timer.Stop()
		for range flows {
			select {
			case <-ready:
			case <-timer.C:
				t.Fatal("not all streams delivered data before the scheduled fault")
			}
		}
		stopped = time.Now()
		if err := interrupt(); err != nil {
			t.Fatal(err)
		}
		close(fault)
	}
	var samples []time.Duration
	var lastResumed time.Time
	for range flows {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		samples = append(samples, r.samples...)
		if r.resumed.After(lastResumed) {
			lastResumed = r.resumed
		}
	}
	if len(samples) == 0 {
		t.Fatal("load produced no validated echoes")
	}
	elapsed := time.Since(start)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	payloadBytes := uint64(len(samples)) * size * 2
	t.Logf("flows=%d echoes=%d bidirectional_bytes=%d goodput_per_direction_Mbps=%.2f p99=%s",
		len(flows), len(samples), payloadBytes, float64(payloadBytes)*4/elapsed.Seconds()/1e6, samples[(len(samples)*99-1)/100])
	if interrupt != nil {
		t.Logf("all_original_streams_echoed_after_shutdown_ms=%d", lastResumed.Sub(stopped).Milliseconds())
	}
	return payloadBytes
}
