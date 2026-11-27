package benchmark

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

const (
	probeInterval = 20 * time.Millisecond
	ioTimeout     = 2 * time.Second
	bulkSize      = 32 << 10
)

type Options struct {
	Transport, Workload string
	Connections         int
	Warmup, Duration    time.Duration
	MaxBytes            int64
	SampleWSS           bool
	QUICSendWait        *time.Duration
	Profiles            string
	LinkOutage          time.Duration
	KernelServer        bool
	AdaptiveMTU         int
	BulkRateMbps        int
}

func (o Options) proxyWorkload() bool {
	return o.Workload == "socks5" || o.Workload == "http-connect"
}

func (o Options) Validate() error {
	switch o.Transport {
	case "direct", "direct-udp", "alternate-udp", "adaptive-wss", "quic-datagram", "adaptive-auto", "wss", "multipath", "udp-relay", "native-wireguard-go", "native-wireguard-kernel":
	default:
		return errors.New("unknown benchmark transport")
	}
	if o.KernelServer {
		switch o.Transport {
		case "direct-udp", "alternate-udp", "multipath", "wss", "udp-relay", "native-wireguard-go", "native-wireguard-kernel":
		default:
			return errors.New("the kernel server fixture requires a legacy or native WireGuard transport")
		}
	}
	if o.AdaptiveMTU != 0 && ((o.Transport != "adaptive-wss" && o.Transport != "quic-datagram" && o.Transport != "adaptive-auto") ||
		o.AdaptiveMTU < wstransport.MinTunnelMTU || o.AdaptiveMTU > wstransport.DefaultTunnelMTU) {
		return errors.New("adaptive MTU requires an adaptive benchmark transport and a value from 1280 to 1420")
	}
	if o.QUICSendWait != nil && ((o.Transport != "quic-datagram" && o.Transport != "adaptive-auto") ||
		*o.QUICSendWait < 0 || *o.QUICSendWait > wstransport.MaxQUICSendWait) {
		return errors.New("QUIC admission wait requires a QUIC laboratory fixture and a duration from 0 to 5ms")
	}
	switch o.Workload {
	case "interactive", "bulk", "mixed", "setup", "udp", "socks5", "http-connect":
	default:
		return errors.New("workload must be interactive, bulk, mixed, setup, udp, socks5, or http-connect")
	}
	if o.Connections < 1 || o.Connections > 10000 {
		return errors.New("connections must be between 1 and 10000")
	}
	if o.Workload == "mixed" && o.Connections < 2 {
		return errors.New("mixed requires at least two connections")
	}
	if o.BulkRateMbps < 0 || o.BulkRateMbps > 10000 ||
		(o.BulkRateMbps != 0 && o.Workload != "bulk" && o.Workload != "mixed") {
		return errors.New("bulk rate must be 0 to 10000 Mbit/s per worker and requires a bulk or mixed workload")
	}
	if o.Duration < 100*time.Millisecond || o.Duration > 5*time.Minute || o.Warmup < 0 || o.Warmup > time.Minute {
		return errors.New("duration must be 100ms to 5m and warm-up must be 0 to 1m")
	}
	if o.MaxBytes < bulkSize || o.MaxBytes > 64<<30 {
		return errors.New("max-bytes must be between 32768 and 68719476736")
	}
	return nil
}

// RelayStarter is supplied only by the laboratory command. Using an explicit
// fixture keeps relay discovery and its dependencies out of the shipped CLI.
type RelayStarter func(context.Context, *server.Server, string, Options) (RelayFixture, error)

type RelayFixture struct {
	Close func()
}

type Report struct {
	Schema       int      `json:"schema"`
	Commit       string   `json:"commit,omitempty"`
	Modified     bool     `json:"modified"`
	GoVersion    string   `json:"go_version"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	CPUs         int      `json:"logical_cpus"`
	GOMAXPROCS   int      `json:"gomaxprocs"`
	Fixture      string   `json:"fixture"`
	Backend      string   `json:"backend"`
	ProfileFiles []string `json:"profiles,omitempty"`
	Runs         []Run    `json:"runs"`
}

type Run struct {
	Transport           string                        `json:"transport_requested"`
	SelectedPaths       []string                      `json:"selected_paths"`
	TunnelMTU           int                           `json:"tunnel_mtu,omitempty"`
	QUICSendWaitUS      *int64                        `json:"quic_send_wait_us,omitempty"`
	Workload            string                        `json:"workload"`
	Connections         int                           `json:"connections"`
	WarmupMS            int64                         `json:"warmup_ms"`
	DurationMS          int64                         `json:"duration_ms"`
	SampleMS            int64                         `json:"sample_duration_ms"`
	MaxBytes            int64                         `json:"max_bytes_per_direction"`
	EndReason           string                        `json:"end_reason"`
	SetupUS             int64                         `json:"ntwire_connect_us,omitempty"`
	ReadyUS             int64                         `json:"first_echo_us"`
	Iterations          uint64                        `json:"iterations"`
	Failures            uint64                        `json:"failures"`
	Aborted             uint64                        `json:"aborted"`
	MissedArrivals      uint64                        `json:"missed_interactive_arrivals"`
	BytesDelivered      uint64                        `json:"echo_bytes_per_direction"`
	BitsPerSecond       float64                       `json:"echo_bps_per_direction"`
	Latency             Distribution                  `json:"response_latency"`
	Connect             Distribution                  `json:"connection_setup"`
	Process             Resources                     `json:"process"`
	HostCPU             *HostCPU                      `json:"host_cpu,omitempty"`
	ClientWSS           *wstransport.QueuePerformance `json:"client_wss,omitempty"`
	ServerWSS           *wstransport.QueuePerformance `json:"server_wss,omitempty"`
	Topology            string                        `json:"topology"`
	RelayTraffic        *protocol.ClientUDPRelayStats `json:"client_udp_relay,omitempty"`
	QUICTraffic         *wstransport.QUICStats        `json:"client_quic,omitempty"`
	ServerQUICTraffic   *wstransport.QUICStats        `json:"server_quic,omitempty"`
	LinkRecovery        *LinkRecovery                 `json:"link_recovery,omitempty"`
	AdaptivePerformance *client.AdaptivePerformance   `json:"adaptive_performance,omitempty"`
	Bulk                *BulkTraffic                  `json:"bulk,omitempty"`
}

type BulkTraffic struct {
	LimitMbpsPerWorker int     `json:"limit_mbps_per_worker,omitempty"`
	SocketBytesWritten uint64  `json:"socket_bytes_written"`
	EchoBytes          uint64  `json:"echo_bytes_per_direction"`
	SocketWriteBPS     float64 `json:"socket_write_bps"`
	EchoBPS            float64 `json:"echo_bps_per_direction"`
}

type Distribution struct {
	Count uint64 `json:"count"`
	P50US int64  `json:"p50_us,omitempty"`
	P95US int64  `json:"p95_us,omitempty"`
	P99US int64  `json:"p99_us,omitempty"`
}

// Use 16 bins per power of two without retaining individual operations.
type histogram [56 * 16]uint64

func (h *histogram) add(d time.Duration) {
	us := uint64(max(1, d.Microseconds()))
	exp := bits.Len64(us) - 1
	base := uint64(1) << exp
	h[exp*16+int((us-base)*16/base)]++
}

func (h *histogram) summarize() Distribution {
	var d Distribution
	for _, n := range h {
		d.Count += n
	}
	if d.Count == 0 {
		return d
	}
	var seen uint64
	for i, n := range h {
		seen += n
		base := uint64(1) << (i / 16)
		us := int64(base + (base*uint64(i%16+1)-1)/16)
		if d.P50US == 0 && seen >= (d.Count*50+99)/100 {
			d.P50US = us
		}
		if d.P95US == 0 && seen >= (d.Count*95+99)/100 {
			d.P95US = us
		}
		if seen >= (d.Count*99+99)/100 {
			d.P99US = us
			break
		}
	}
	return d
}

func Execute(ctx context.Context, options []Options) (Report, error) {
	return execute(ctx, options, false, nil)
}

// ExecuteLab runs repository benchmarks, including the native peer and
// optionally an explicitly provisioned UDP relay.
func ExecuteLab(ctx context.Context, options []Options, relay RelayStarter) (Report, error) {
	return execute(ctx, options, true, relay)
}

func newReport(topology string) Report {
	report := Report{Schema: 1, GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		CPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), Fixture: topology, Backend: "userspace"}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				report.Commit = setting.Value
			case "vcs.modified":
				report.Modified = setting.Value == "true"
			}
		}
	}
	return report
}

func execute(ctx context.Context, options []Options, laboratory bool, relay RelayStarter) (Report, error) {
	report := newReport("loopback")
	if len(options) == 0 {
		return report, errors.New("no benchmark modes selected")
	}
	for _, o := range options {
		if err := o.Validate(); err != nil {
			return report, err
		}
		if (o.Transport == "direct" || nativeTransport(o.Transport)) && o.proxyWorkload() {
			return report, errors.New("proxy workload requires a WireGuard transport with an ntwire proxy listener")
		}
		if o.Transport == "native-wireguard-kernel" || o.KernelServer {
			return report, errors.New("kernel WireGuard requires the split Linux laboratory")
		}
		if !laboratory && (o.Transport == "udp-relay" || o.Transport == "native-wireguard-go" || o.Transport == "alternate-udp" || o.Transport == "adaptive-wss" || o.Transport == "quic-datagram" || o.Transport == "adaptive-auto") {
			return report, errors.New("transport is available in the performance laboratory command")
		}
		if o.Transport == "udp-relay" && relay == nil {
			return report, errors.New("missing laboratory relay fixture")
		}
		if len(options) > 1 && o.Profiles != "" {
			return report, errors.New("run profiles with one transport at a time")
		}
	}
	for _, o := range options {
		result, files, err := run(ctx, o, relay)
		if err != nil {
			return report, fmt.Errorf("%s: %w", o.Transport, err)
		}
		report.Runs = append(report.Runs, result)
		report.ProfileFiles = append(report.ProfileFiles, files...)
	}
	return report, nil
}

func run(ctx context.Context, o Options, relay RelayStarter) (Run, []string, error) {
	f, err := newFixture(ctx, o, relay)
	if err != nil {
		return Run{}, nil, err
	}
	defer f.close()
	return measureFixture(ctx, o, f)
}

func measureFixture(ctx context.Context, o Options, f *fixture) (Run, []string, error) {
	readyStart := time.Now()
	if err := f.ready(ctx); err != nil {
		return Run{}, nil, fmt.Errorf("waiting for fixture echo: %w", err)
	}
	ready := time.Since(readyStart)
	var hostCPU HostCPU
	if f.topology == peerTopology && os.Getenv("NTWIRE_BENCH_HOST_CPU") == "1" {
		hostCPU = sampleIdleHostCPU(ctx)
	}
	if o.Warmup > 0 {
		warm := f.measure(ctx, o, o.Warmup)
		if ctx.Err() != nil {
			return Run{}, nil, ctx.Err()
		}
		if warm.data.iterations == 0 {
			return Run{}, nil, errors.New("warm-up completed without a successful echo")
		}
	}
	clientQueue, serverBefore, err := f.measurementSnapshots(ctx)
	if err != nil {
		return Run{}, nil, fmt.Errorf("sample fixture before measurement: %w", err)
	}
	var quicBefore, serverQUICBefore *wstransport.QUICStats
	if o.Transport == "quic-datagram" || o.Transport == "adaptive-auto" {
		quicBefore = f.client.TransportInfo().QUIC
		if f.server != nil {
			serverQUICBefore = f.server.QUICPerformance()
		}
	}
	var relayBefore protocol.ClientUDPRelayStats
	if o.Transport == "udp-relay" {
		relayBefore = f.client.UDPRelayTraffic()
	}
	prof, err := startProfiles(o.Profiles)
	if err != nil {
		return Run{}, nil, err
	}
	if f.recovery != nil {
		if err := f.recovery.begin(); err != nil {
			_, _ = prof.finish()
			return Run{}, nil, err
		}
	} else if f.peerTCPDir != "" {
		if err := os.WriteFile(filepath.Join(f.peerTCPDir, "measurement-start"), nil, 0600); err != nil {
			_, _ = prof.finish()
			return Run{}, nil, err
		}
	}
	var cpuStart, cpuEnd hostCPUSnapshot
	if hostCPU.IdleElapsedUS > 0 {
		cpuStart = readHostCPU()
	}
	measured := f.measure(ctx, o, o.Duration)
	if hostCPU.IdleElapsedUS > 0 {
		cpuEnd = readHostCPU()
	}
	var markerErr error
	if f.peerTCPDir != "" {
		markerErr = os.WriteFile(filepath.Join(f.peerTCPDir, "measurement-end"), nil, 0600)
	}
	afterClient, serverAfter, sampleErr := f.measurementSnapshots(ctx)
	files, err := prof.finish()
	if err = errors.Join(err, markerErr); err != nil {
		return Run{}, nil, err
	}
	if err = ctx.Err(); err != nil {
		return Run{}, nil, err
	}
	if sampleErr != nil {
		return Run{}, nil, fmt.Errorf("sample fixture after measurement: %w", sampleErr)
	}
	data := &measured.data
	result := Run{Transport: o.Transport, Topology: f.topology, SelectedPaths: measured.paths, Workload: o.Workload, Connections: o.Connections,
		WarmupMS: o.Warmup.Milliseconds(), DurationMS: o.Duration.Milliseconds(), SampleMS: measured.elapsed.Milliseconds(),
		MaxBytes: o.MaxBytes, EndReason: measured.endReason, SetupUS: f.setup.Microseconds(), ReadyUS: ready.Microseconds(),
		Iterations: data.iterations, Failures: data.failures, Aborted: data.aborted, MissedArrivals: data.missed, BytesDelivered: data.bytes,
		BitsPerSecond: float64(data.bytes) * 8 / measured.elapsed.Seconds(), Latency: data.latency.summarize(),
		Connect: data.connect.summarize(), Process: measured.resources, HostCPU: hostCPU.measured(cpuStart, cpuEnd)}
	if o.Workload == "bulk" || o.Workload == "mixed" {
		result.Bulk = &BulkTraffic{
			LimitMbpsPerWorker: o.BulkRateMbps,
			SocketBytesWritten: data.bulkWritten,
			EchoBytes:          data.bulkEchoed,
			SocketWriteBPS:     float64(data.bulkWritten) * 8 / measured.elapsed.Seconds(),
			EchoBPS:            float64(data.bulkEchoed) * 8 / measured.elapsed.Seconds(),
		}
	}
	if o.QUICSendWait != nil {
		us := o.QUICSendWait.Microseconds()
		result.QUICSendWaitUS = &us
	}
	if serverQUICBefore != nil {
		if after := f.server.QUICPerformance(); after != nil {
			delta := after.Delta(*serverQUICBefore)
			result.ServerQUICTraffic = &delta
		}
	}
	if f.client != nil {
		info := f.client.TransportDetails()
		result.TunnelMTU = info.TunnelMTU
		result.AdaptivePerformance = info.AdaptivePerformance
		if after := info.QUIC; quicBefore != nil && after != nil {
			delta := after.Delta(*quicBefore)
			result.QUICTraffic = &delta
		}
	}
	if f.recovery != nil {
		result.LinkRecovery = &f.recovery.report
	}
	if o.SampleWSS {
		result.ClientWSS = afterClient.Performance.Delta(clientQueue.Performance)
		result.ServerWSS = serverAfter.WSS.Performance.Delta(serverBefore.WSS.Performance)
	}
	if o.Transport == "udp-relay" {
		after := f.client.UDPRelayTraffic()
		if after.PacketsSent >= relayBefore.PacketsSent && after.PacketsReceived >= relayBefore.PacketsReceived &&
			after.BytesSent >= relayBefore.BytesSent && after.BytesReceived >= relayBefore.BytesReceived {
			result.RelayTraffic = &protocol.ClientUDPRelayStats{
				BytesSent: after.BytesSent - relayBefore.BytesSent, PacketsSent: after.PacketsSent - relayBefore.PacketsSent,
				BytesReceived: after.BytesReceived - relayBefore.BytesReceived, PacketsReceived: after.PacketsReceived - relayBefore.PacketsReceived,
			}
		}
	}
	return result, files, nil
}

type totals struct {
	iterations, failures, aborted, missed, bytes uint64
	bulkWritten, bulkEchoed                      uint64
	latency, connect                             histogram
}

type measurement struct {
	data      totals
	elapsed   time.Duration
	endReason string
	paths     []string
	resources Resources
}

type byteBudget struct{ remaining atomic.Int64 }

func (b *byteBudget) take(n int) bool {
	for left := b.remaining.Load(); left >= int64(n); left = b.remaining.Load() {
		if b.remaining.CompareAndSwap(left, left-int64(n)) {
			return true
		}
	}
	return false
}

func (f *fixture) measure(ctx context.Context, o Options, duration time.Duration) measurement {
	start := time.Now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(duration))
	defer cancel()
	budget := &byteBudget{}
	budget.remaining.Store(o.MaxBytes)
	var result measurement
	result.resources.FDPeak = openFDs()
	result.resources.FDLimit = openFDLimit()
	resourceStart := processCounters()
	var merger sync.Mutex
	var workers sync.WaitGroup
	var exhausted atomic.Bool
	var bulkInterval time.Duration
	if o.BulkRateMbps > 0 {
		bulkInterval = 8 * bulkSize * time.Second / (time.Duration(o.BulkRateMbps) * 1_000_000)
	}
	for i := 0; i < o.Connections; i++ {
		workers.Go(func() {
			data := f.worker(ctx, o.Workload, i, budget, &exhausted, bulkInterval)
			merger.Lock()
			result.data.iterations += data.iterations
			result.data.failures += data.failures
			result.data.aborted += data.aborted
			result.data.missed += data.missed
			result.data.bytes += data.bytes
			result.data.bulkWritten += data.bulkWritten
			result.data.bulkEchoed += data.bulkEchoed
			for j := range data.latency {
				result.data.latency[j] += data.latency[j]
				result.data.connect[j] += data.connect[j]
			}
			merger.Unlock()
		})
	}
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	nextFD := start.Add(time.Second)
	sample := func(snapshot counters) {
		path := f.activePath()
		if len(result.paths) < 128 && (len(result.paths) == 0 || result.paths[len(result.paths)-1] != path) {
			result.paths = append(result.paths, path)
		}
		result.resources.HeapPeakBytes = max(result.resources.HeapPeakBytes, snapshot.heap)
		result.resources.GoroutinePeak = max(result.resources.GoroutinePeak, snapshot.goroutines)
	}
	sample(resourceStart)
	for {
		select {
		case <-ticker.C:
			sample(processCounters())
			if now := time.Now(); result.resources.FDPeak > 0 && !now.Before(nextFD) {
				result.resources.FDPeak = max(result.resources.FDPeak, openFDs())
				nextFD = now.Add(time.Second)
			}
		case <-done:
			result.elapsed = time.Since(start)
			end := processCounters()
			sample(end)
			result.resources.delta(resourceStart, end)
			result.endReason = "duration"
			if exhausted.Load() {
				result.endReason = "byte_limit"
			}
			return result
		}
	}
}

func (f *fixture) worker(ctx context.Context, workload string, index int, budget *byteBudget, exhausted *atomic.Bool, bulkInterval time.Duration) totals {
	var data totals
	var socket net.Conn
	var stop func() bool
	closeSocket := func() {
		if socket != nil {
			stop()
			_ = socket.Close()
			socket = nil
		}
	}
	defer closeSocket()
	if workload == "bulk" || (workload == "mixed" && index > 0) {
		return f.bulkWorker(ctx, index, budget, exhausted, bulkInterval)
	}
	const size = 128
	payload := bytes.Repeat([]byte{byte(index%251 + 1)}, size)
	reply := make([]byte, size)
	next := time.Now()
	var socketCount int
	for ctx.Err() == nil {
		if !budget.take(size) {
			exhausted.Store(true)
			break
		}
		started := time.Now()
		if socket == nil {
			var err error
			socket, err = f.dial(ctx, ioTimeout)
			if err != nil {
				data.recordFailure(ctx)
				next = data.waitNext(ctx, next)
				continue
			}
			socketCount++
			opened := socket
			stop = context.AfterFunc(ctx, func() { _ = opened.Close() })
			data.connect.add(time.Since(started))
		}
		err := exchange(ctx, socket, payload, reply, ioTimeout)
		if err != nil {
			data.recordFailure(ctx)
			closeSocket()
			next = data.waitNext(ctx, next)
			continue
		}
		data.iterations++
		data.bytes += uint64(size)
		now := time.Now()
		data.latency.add(now.Sub(next))
		if f.recovery != nil && index == 0 && f.recovery.measuring {
			f.recovery.observe(now, socketCount)
		}
		if workload == "setup" {
			closeSocket()
		}
		next = data.waitNext(ctx, next)
	}
	return data
}

// Use a continuous full-duplex echo stream for bulk data so that a single
// application round trip does not cap each flow to one chunk in flight.
func (f *fixture) bulkWorker(ctx context.Context, index int, budget *byteBudget, exhausted *atomic.Bool, interval time.Duration) totals {
	var data totals
	started := time.Now()
	socket, err := f.dial(ctx, ioTimeout)
	if err != nil {
		data.recordFailure(ctx)
		return data
	}
	defer socket.Close()
	writer, ok := socket.(interface{ CloseWrite() error })
	if !ok {
		data.failures++
		return data
	}
	data.connect.add(time.Since(started))
	deadline, _ := ctx.Deadline()
	_ = socket.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()

	payload := bytes.Repeat([]byte{byte(index%251 + 1)}, bulkSize)
	type writeOutcome struct {
		bytes uint64
		err   error
	}
	writeResult := make(chan writeOutcome, 1)
	go func() {
		defer writer.CloseWrite()
		var outcome writeOutcome
		defer func() { writeResult <- outcome }()
		var next time.Time
		var timer *time.Timer
		if interval > 0 {
			timer = time.NewTimer(interval)
			timer.Stop()
			defer timer.Stop()
		}
		for ctx.Err() == nil {
			if timer != nil {
				if wait := time.Until(next); wait > 0 {
					timer.Reset(wait)
					select {
					case <-ctx.Done():
						return
					case <-timer.C:
					}
				}
				// A blocked write must not accumulate send credit.
				next = time.Now().Add(interval)
			}
			if !budget.take(len(payload)) {
				exhausted.Store(true)
				break
			}
			n, err := socket.Write(payload)
			outcome.bytes += uint64(n)
			if err != nil || n != len(payload) {
				if err == nil {
					err = io.ErrShortWrite
				}
				outcome.err = err
				return
			}
		}
	}()
	reply := make([]byte, len(payload))
	for {
		_, err = io.ReadFull(socket, reply)
		if err != nil || !bytes.Equal(reply, payload) {
			break
		}
		data.iterations++
		data.bytes += uint64(len(reply))
	}
	_ = socket.Close()
	outcome := <-writeResult
	data.bulkWritten = outcome.bytes
	data.bulkEchoed = data.bytes
	if !errors.Is(err, io.EOF) || outcome.err != nil {
		data.recordFailure(ctx)
	}
	return data
}

func (t *totals) recordFailure(ctx context.Context) {
	deadline, timed := ctx.Deadline()
	if ctx.Err() != nil || (timed && time.Until(deadline) <= 0) {
		t.aborted++
	} else {
		t.failures++
	}
}

// At most one due request per worker. Skip missed intervals without an
// unbounded catch-up burst.
func (t *totals) waitNext(ctx context.Context, previous time.Time) time.Time {
	next := previous.Add(probeInterval)
	if delay := time.Until(next); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
	}
	if behind := time.Since(next); behind >= probeInterval && ctx.Err() == nil {
		missed := behind / probeInterval
		t.missed += uint64(missed)
		return next.Add(missed * probeInterval)
	}
	return next
}

func exchange(ctx context.Context, socket net.Conn, payload, reply []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := socket.SetDeadline(deadline); err != nil {
		return err
	}
	if n, err := socket.Write(payload); err != nil {
		return err
	} else if n != len(payload) {
		return io.ErrShortWrite
	}
	if _, err := io.ReadFull(socket, reply); err != nil {
		return err
	}
	if !bytes.Equal(payload, reply) {
		return errors.New("fixture returned unexpected bytes")
	}
	return nil
}
