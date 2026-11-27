package client

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/server"
)

// BenchmarkAdaptiveWSSLaneFanout runs eight persistent TCP streams and
// reports validated echo bytes per direction after all peers qualify.
func BenchmarkAdaptiveWSSLaneFanout(b *testing.B) {
	for _, lanes := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("%d-lane", lanes), func(b *testing.B) {
			benchmarkAdaptiveWSS(b, lanes, 8, 64<<10)
		})
	}
}

// BenchmarkAdaptiveWSSConcurrency holds the workload and listener count
// constant while measuring fan-out and resource cost at higher flow counts.
func BenchmarkAdaptiveWSSConcurrency(b *testing.B) {
	for _, flows := range []int{100, 500, 1000} {
		for _, lanes := range []int{1, 2, 4, 8} {
			b.Run(fmt.Sprintf("%d-flows/%d-lane", flows, lanes), func(b *testing.B) {
				benchmarkAdaptiveWSS(b, lanes, flows, 1024)
			})
		}
	}
}

func benchmarkAdaptiveWSS(b *testing.B, lanes, flows, payloadBytes int) {
	b.Helper()
	f := newReconnectFixture(b)
	cfg := f.serverConfig("100.77.4.0/24", 18250, true, server.TransportConfig{Adaptive: true, AdaptiveMaxLanes: lanes})
	c, _ := connectMultiLaneFixture(b, f, cfg)
	for range lanes - 1 {
		if _, err := c.openAdaptiveLane(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
	var workers sync.WaitGroup
	var start []chan struct{}
	results := make(chan error, flows)
	b.Cleanup(func() {
		for _, trigger := range start {
			close(trigger)
		}
		workers.Wait()
	})
	for id := range flows {
		conn := dialLaneTest(b, "tcp", c.LocalAddresses[0])
		echoLaneTest(b, conn, "warm flow")
		trigger := make(chan struct{})
		start = append(start, trigger)
		workers.Go(func() {
			payload := bytes.Repeat([]byte{byte(id + 1)}, payloadBytes)
			reply := make([]byte, len(payload))
			for range trigger {
				_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
				n, err := conn.Write(payload)
				switch {
				case err != nil:
				case n != len(payload):
					err = io.ErrShortWrite
				default:
					_, err = io.ReadFull(conn, reply)
					if err == nil && !bytes.Equal(payload, reply) {
						err = fmt.Errorf("flow %d received the wrong echo", id)
					}
				}
				results <- err
			}
		})
	}
	if lanes > 1 {
		status := c.TransportDetails().Lanes
		if len(status) != lanes {
			b.Fatalf("expected %d lanes, got %+v", lanes, status)
		}
		for _, lane := range status {
			if lane.ActiveFlows < flows/lanes || lane.ActiveFlows > (flows+lanes-1)/lanes || lane.State != "ready" {
				b.Fatalf("unexpected placement: %+v", status)
			}
		}
	}
	b.SetBytes(int64(flows) * int64(payloadBytes))
	b.ReportAllocs()
	for b.Loop() {
		for _, trigger := range start {
			trigger <- struct{}{}
		}
		for range flows {
			if err := <-results; err != nil {
				b.Fatal(err)
			}
		}
	}
}
