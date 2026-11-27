package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

func TestExecuteLoopback(t *testing.T) {
	for _, tc := range []struct{ transport, workload, path string }{
		{"direct", "bulk", "direct"},
		{"direct-udp", "udp", "direct-udp"},
		{"wss", "interactive", "wss"},
		{"wss", "socks5", "wss"},
		{"wss", "http-connect", "wss"},
		{"adaptive-wss", "http-connect", "adaptive-wss"},
		{"quic-datagram", "http-connect", "quic-datagram"},
		{"multipath", "interactive", "wss"},
	} {
		t.Run(tc.transport+"/"+tc.workload, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
			defer cancel()
			f, err := newFixture(ctx, Options{Transport: tc.transport, Workload: tc.workload,
				Connections: 2, MaxBytes: 2 << 20, SampleWSS: true}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer f.close()
			if err = f.ready(ctx); err != nil {
				t.Fatal(err)
			}
			if got := f.activePath(); got != tc.path {
				t.Fatalf("path %q, expected %q", got, tc.path)
			}
			outbound, inbound, err := f.measurementSnapshots(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if (tc.transport == "wss" || tc.transport == "adaptive-wss") &&
				(!outbound.Performance.Enabled || !inbound.WSS.Performance.Enabled) {
				t.Fatal("WSS queue sampling is disabled")
			}
		})
	}
}

func TestExecuteQUICAdmission_ReportsBothBoundaries(t *testing.T) {
	wait := 2 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	report, err := execute(ctx, []Options{{Transport: "quic-datagram", Workload: "interactive",
		Connections: 1, Duration: 3 * time.Second, MaxBytes: 2 << 20, QUICSendWait: &wait}}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	run := report.Runs[0]
	// execute already verifies an application echo during readiness.
	// This check covers policy reporting and measured QUIC traffic.
	if len(run.SelectedPaths) != 1 || run.SelectedPaths[0] != "quic-datagram" ||
		run.QUICSendWaitUS == nil || *run.QUICSendWaitUS != 2000 {
		t.Fatalf("missing QUIC admission run: %+v", run)
	}
	for _, stats := range []*wstransport.QUICStats{run.QUICTraffic, run.ServerQUICTraffic} {
		if stats == nil || stats.Sent == 0 || stats.Received == 0 {
			t.Fatalf("missing QUIC traffic at a fixture boundary: %+v", stats)
		}
	}
}

func TestExecuteReport(t *testing.T) {
	report, err := Execute(t.Context(), []Options{{Transport: "direct", Workload: "bulk",
		Connections: 1, Duration: 3 * time.Second, MaxBytes: bulkSize}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Runs) != 1 || report.Runs[0].BytesDelivered != bulkSize || report.Runs[0].EndReason != "byte_limit" {
		t.Fatalf("incorrect report: %+v", report)
	}
	process := report.Runs[0].Process
	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && process.RSSPeakBytes == 0 {
		t.Fatal("missing process lifetime peak RSS")
	}
	raw, err := json.Marshal(report)
	if err != nil || strings.Contains(string(raw), "127.0.0.1") || strings.Contains(string(raw), "Bearer") {
		t.Fatalf("report leaked fixture information or failed to encode: %v", err)
	}
}

func TestExecuteBulkRate_ReportsBoundedWritesAndEchoes(t *testing.T) {
	options := Options{Transport: "direct", Workload: "mixed", Connections: 2,
		Duration: 750 * time.Millisecond, MaxBytes: 2 << 20, BulkRateMbps: 2}
	report, err := Execute(t.Context(), []Options{options})
	if err != nil {
		t.Fatal(err)
	}
	run := report.Runs[0]
	bulk := run.Bulk
	if bulk == nil || bulk.LimitMbpsPerWorker != options.BulkRateMbps || bulk.EchoBytes == 0 {
		t.Fatalf("missing paced bulk traffic: %+v", bulk)
	}
	ceiling := uint64(bulkSize) + uint64(run.SampleMS)*uint64(options.BulkRateMbps)*1000/8
	if bulk.SocketBytesWritten > ceiling || bulk.EchoBytes > bulk.SocketBytesWritten || bulk.EchoBytes >= run.BytesDelivered {
		t.Fatalf("bulk traffic exceeded its allowance or included interactive traffic: %+v (ceiling %d)", bulk, ceiling)
	}
	options.Workload = "interactive"
	if err := options.Validate(); err == nil {
		t.Fatal("bulk rate accepted for an interactive-only workload")
	}
}

func TestFixtureProxyRejectsOtherLoopbackPort(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	f := &fixture{target: target.Addr().String()}
	t.Cleanup(f.close)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	upstream, err := f.startProxy(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	socket, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err = socks.Connect(ctx, socket, denied.Addr().String()); err == nil {
		t.Fatal("fixture proxy opened a different loopback destination")
	}
	var rejection *socks.ConnectError
	if !errors.As(err, &rejection) || rejection.Code != 2 {
		t.Fatalf("expected an explicit policy denial: %+v", rejection)
	}
}

func TestExecuteCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Execute(ctx, []Options{{Transport: "direct", Workload: "interactive",
		Duration: time.Second, Connections: 1, MaxBytes: 1 << 20}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func TestHistogram(t *testing.T) {
	var h histogram
	for i := 1; i <= 100; i++ {
		h.add(time.Duration(i) * time.Microsecond)
	}
	d := h.summarize()
	if d.Count != 100 || d.P50US < 50 || d.P50US > 53 || d.P95US < 95 || d.P95US > 100 || d.P99US < 99 || d.P99US > 103 {
		t.Fatalf("incorrect distribution: %+v", d)
	}
}
