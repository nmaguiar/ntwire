# Performance benchmarks

`ntwire benchmark` starts a disposable userspace ntwire server, pinned TLS control listener, and echo target on the same machine. It uses a temporary SSH identity, test-only tunnel grant and numeric IPv4 loopback addresses. The command accepts only its built-in `loopback` fixture. It does not use your running connections, proxy environment or configured servers. No elevated permissions are needed. Local TCP listeners are bound to loopback. Where the production WireGuard bind opens a wildcard UDP socket, the fixture advertises its loopback address and authorizes only the disposable peer.

~~~sh
go build -o /tmp/ntwire-benchmark ./cmd/ntwire
/tmp/ntwire-benchmark benchmark --compare-transports --workload mixed --connections 10 --warmup 2s --duration 10s --json
/tmp/ntwire-benchmark benchmark --transport wss --workload http-connect --connections 10 --duration 10s --sample-wss
~~~

For Windows, use `go build -o ntwire-benchmark.exe ./cmd/ntwire` and run the resulting executable. The fixture limits run time, worker count and payload bytes in each direction. Use `--max-bytes` to control the per-interval byte cap. Raising concurrency toward 10,000 on a development machine can hit process socket, memory or local port limits before the tunnel saturates.

| Workload | Exercise |
|---|---|
| `interactive` | Small responses on persistent TCP connections with a nominal 20 ms per-worker send interval |
| `setup` | A fresh local TCP connection and an echo round trip per request |
| `bulk` | Bidirectional echo stream with continuous writes |
| `mixed` | One interactive flow with the remaining workers streaming bulk data |
| `udp` | Fixed UDP tunnel echo |
| `socks5` and `http-connect` | Local proxy handshakes over WireGuard, using a fixture-only transparent SOCKS upstream that permits one echo address and port |

`--compare-transports` compares host TCP/UDP, native direct UDP, WSS and negotiated multipath-v3. Proxy workloads skip the raw host comparison. Interpret `selected_paths` alongside the request. Multipath can select WSS as its primary in an unshaped test. The fixture's sample does not imply that every carrier moved application bytes. Keep v3 and forced WSS results labeled separately.

The JSON report includes the Go toolchain, OS and architecture, build commit when present, worker count, actual measurement duration, per-direction delivered echo rate, response latency and process resources. Connection setup records local dial time plus proxy negotiation when applicable. For fixed tunnels, dialing a local listener can finish before the server opens the target, so first echo is a separate readiness measure. Response percentiles use bounded histograms and represent successful observations. Errors, aborted work and missed interactive arrivals appear separately. Check them alongside the percentiles, especially on saturated runs. Bulk throughput counts echoed, validated bytes. A `byte_limit` result can end before the requested duration and should only be compared with equivalent runs.

### WSS diagnostics and profiles

Use `--sample-wss` to sample one in 16 attempted WSS send batches. Queue metrics cover batches that reached the writer. Residence is measured from enqueue to the start of the write, while queue depth is the number of other batches awaiting the writer. The report has separate client and server counters for sampled datagrams, encrypted payload bytes, residence histogram, and unsampled overflow drops. Histogram bin zero is below 1 µs. Bin `i` covers durations from `2^(i-1)` through `2^i-1` µs, with the final bin also covering overflow. Compare with the flag off and report sampling costs separately.

`write_duration_log2_us` uses the same bins for time spent in sampled batches
between the first and last WebSocket write attempts. Fully expired batches
produce residence samples only. Write duration includes TLS and time blocked
in the write call. It ends before TCP acknowledges the bytes.

For CPU, heap, allocation and goroutine profiles, run one transport and specify a new private directory. The process owns both ends, so profiles aggregate the client, server, fixture and measurement code. JSON includes process CPU time on Linux, macOS and Windows, plus Go heap and allocation accounting. Linux and macOS include process-lifetime peak RSS, including warm-up. Linux also samples open file descriptors about once per second and reports the process soft limit. Short spikes can fall between samples. Use one process per sample when comparing RSS. In the separate-peer fixture, these fields describe the client process. Measure host-wide CPU, kernel networking and softirq separately.

~~~sh
/tmp/ntwire-benchmark benchmark --transport wss --workload mixed --connections 10 --duration 5s --profiles ./local-wss-profiles
go tool pprof -top ./local-wss-profiles/cpu.pprof
~~~

If your Go distribution omits `go tool pprof`, use the standalone
[pprof CLI](https://go.dev/wiki/PGO-Tools).

### Repeated runs and release evidence

With Python 3.11 or later, run a paired comparison with independent processes and alternating order. The destination directory must be new.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-benchmark --output ./local-perf-results \
  --duration 30s --warmup 10s --connections 10 --repeat 7
~~~

Keep `environment.json`, all raw reports and `summary.json`. The per-mode summary lists selected paths, completion and failure counts, stop reasons, and distributions across accepted runs. Check the stop reasons before comparing absolute figures. The first mode is the reference for paired comparisons, and positive percentage deltas mean a larger metric. With at least seven matched repetitions, the harness reports a bootstrap interval for the median paired delta. Use a quiet dedicated runner before making throughput claims. Sample small payloads and responsiveness under bulk load as separate comparisons. The hosted scheduled workflow is a functional smoke with raw artifacts and no throughput thresholds.

Use `--hardware-notes` to record the CPU model, clock policy, container or
VM constraints, and relevant NIC or offload settings in `environment.json`.
That report also records the binary hashes and workload parameters. Keep it
with the raw samples, which identify the build revision and whether it
came from a modified checkout.

The runner records failed or excluded samples and continues the comparison.
It reports a failing exit status if any sample fails, omits the missing
pair from the corresponding comparison, and marks the WSS sampling gate
inconclusive. It records repetitions where one
run reached the byte cap and the other reached the duration. Those
repetitions are omitted from the paired metric deltas and make the WSS
sampling gate inconclusive. Increase the byte cap or reduce the duration
and rerun before making a release comparison.

The scheduled workflow also exercises SOCKS5 and HTTP CONNECT over direct
UDP and WSS on Linux, macOS, and Windows. It stores raw reports as functional
smoke evidence without enforcing throughput thresholds on hosted runners.
Ordinary CI runs the Go fixture tests and the Python runner tests.

Use `--compare-wss-sampling` to pair WSS with sampling off and on using the
same executable and workload. The comparison requires error-free measured
echoes over WSS in both runs and checks that the sampled run recorded queue
batches on both endpoints in loopback and separate-peer runs. A missing
observation excludes the run and makes the sampling gate inconclusive.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-benchmark \
  --output ./local-wss-sampling --compare-wss-sampling --sampling-margin-pct 2 \
  --workload mixed --connections 4 --bulk-rate-mbps 25 \
  --warmup 2s --duration 6s --repeat 11
~~~

### Relay and native WireGuard comparison

Build the repository-only laboratory command to add a real UDP relay and a
native WireGuard-go peer. It uses the same workload engine and JSON schema as
`ntwire benchmark`.

~~~sh
go build -o /tmp/ntwire-bench-lab ./tests/performance/lab
python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
  --output ./local-relay-results --modes direct-udp native-wireguard-go udp-relay \
  --workload interactive --connections 2 --repeat 7 --require-progress
~~~

`udp-relay` starts a real relay and server agent with a disposable registration.
The client uses direct TLS for control and WSS to bootstrap WireGuard. Samples
start after a successful echo with UDP relay selected and ciphertext counters
advancing in both directions. With
`--require-progress`, a passing run must show the UDP relay as the primary at
every sampled observation and report measured ciphertext packets in both
directions. Counter deltas omit observed resets during a measurement.

`native-wireguard-go` configures a static server peer and uses the upstream
WireGuard UDP bind with a userspace netstack. It exercises an ordinary native
WireGuard peer without ntwire client authentication or local forwarding, so
its measurements include those differences. In the loopback fixture, both
peer endpoints, any relay, and the echo target run in one process. See the
separate-peer fixture for the Linux kernel client.

### Linux loopback impairment

On an isolated Linux worker with permission to create network namespaces and
configure qdiscs, install `unshare` and `iproute2` with seeded netem support and
use the laboratory command. The runner creates a fresh network namespace per
sample before enabling loopback and applying the qdisc. The host namespace
keeps its interfaces and routes.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
  --output ./local-impaired-results --modes direct-udp udp-relay wss \
  --workload interactive --connections 2 --repeat 7 --require-progress \
  --netem 5 0.5 100 42
~~~

The example applies 5 ms delay per loopback transmission, 0.5% random loss,
and a 100 Mbit/s rate limit using seed 42. Raw reports include the kernel's
configured qdisc and observed packet and drop counters. The qdisc affects
every loopback hop in the fixture, including control setup, local forwarding
and the echo target. Compare results with matched topology and settings.

Keep the ordinary [Docker end-to-end fixtures](../tests/e2e/) for product
compatibility, the existing `BenchmarkSmartProxyTransport` fixture for
Smart Egress comparisons, and the separate [Linux acceleration procedure](LINUX-ACCELERATION.md#metrics-and-performance)
for kernel server backend qualification.


### Linux separate-peer baseline and recovery

Use `--peer-netem` on an isolated Linux worker with permission to create
network namespaces and veth links, plus a kernel with WireGuard support
when selecting `native-wireguard-kernel`. The launcher starts independent
client and server processes, with the echo service in the server namespace.
The namespaces have no default route and share one veth link. Each sample
gets fresh namespaces, keys, and counters. The first four profile values
set client upload delay in milliseconds, loss percentage, rate in Mbit/s,
and seed. The next four set server download impairment.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
  --output ./local-peer-results \
  --modes direct direct-udp alternate-udp native-wireguard-kernel udp-relay wss multipath \
  --peer-netem 2 0.1 100 42 4 0.1 200 43 \
  --workload interactive --connections 2 --repeat 7 --require-progress
~~~

The raw JSON includes qdisc counters for each direction. Client process
CPU and heap measurements exclude the separate server, relay and kernel
networking. With `--sample-wss`, separate-peer reports include client and
server WSS queue samples. A private fixture socket supplies a server
snapshot just before and just after the measured interval. Rejection and
expiration counts cover the interval, while peak buffered bytes include
warm-up. Use the one-process fixture to profile both endpoints together.
The real UDP relay runs beside the server in this topology. An independent
impaired server-to-relay leg or physical NIC measurements require a separate
controlled deployment.

`native-wireguard-kernel` uses a stock Linux WireGuard client interface
with one peer and one route to the authorized virtual address. The
fixture checks kernel handshake and bidirectional byte counters before
measurement. The server still runs its portable data plane.
`alternate-udp` advertises a primary UDP port with no responder, then
uses the existing alternate port and coordinated v3 promotion. Preflight
waits for successful tunneled echoes on that path before sampling.

To measure interruption and resumption, add `--link-outage-ms 750`,
`--workload interactive --connections 1 --duration 8s` to a separate-peer
run. After one second of measured traffic, the launcher takes down only
the fixture client link for the requested interval. The report records
the gap between the last observed echo before the interruption and the
first observed echo after restoration, and whether the probe worker
replaced its local socket. The runner excludes trials without complete
observations for the requested outage. `summary.json` gives the response-gap
distribution per mode, socket reuse and replacement counts, and paired gap
deltas for comparable trials. These observations describe application
recovery. Use transport and session data to distinguish reauthentication
from recovery on the original WireGuard peer.

The harness supports `--sampling-margin-pct 2` with
`--compare-wss-sampling` to check the paired 95% intervals for throughput
and CPU per delivered GiB. Every repetition must contribute to both
metrics. Missing measurements or intervals that straddle the margin give
an inconclusive verdict and a failing status. Keep diagnostic sampling
opt-in until the cost is qualified on the target workload and hardware.

Use independent comparisons for the existing-path optimizations.

| Profile | Workload and control |
|---|---|
| Clean, low-delay link | Run `bulk` with one worker for single-flow goodput. Run `interactive` separately for idle response latency. |
| Shared bottleneck | Run `mixed` with 2 and 10 workers at 100 Mbit/s. Check interactive p99, successful responses and missed arrivals alongside delivered bulk bytes. |
| High bandwidth-delay product | Run `bulk` with one worker over a 100 ms RTT. Use a matching unshaped or low-delay control before changing TCP windows. |
| Loss and recovery | Compare the mixed workload at 0% and 0.5% directional loss. Run the link-outage fixture separately to isolate resumption time and local socket reuse. |
| Setup and concurrency | Use `setup` for repeated fresh TCP connections. The `socks5` and `http-connect` workloads measure each worker's proxy setup and then reuse its connection. For long-lived flows, increase `interactive` workers in steps and preserve failure, FD and memory measurements at each step. |

Run candidate and reference for the same duration with enough byte headroom
to reach the time limit. A short capacity smoke can establish where to
investigate, while sustained capacity requires repeated runs and a soak.

The manual `Performance smoke` workflow can optionally run the privileged
separate-peer fixture and upload its raw results. Use a dedicated worker
and record physical CPU, NIC, offloads and host-wide resources before
making release performance claims.

For a data-path change, pass a reference build through `--baseline-binary`
and use one `--modes` value. The runner alternates the two binaries under
the same profile and records both hashes. Compare idle and loaded
workloads separately.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-bench-candidate \
  --baseline-binary /tmp/ntwire-bench-baseline --output ./udp-comparison \
  --modes direct-udp --peer-netem 0 0 100 42 0 0 100 43 \
  --workload bulk --connections 1 --duration 10s --repeat 7 --require-progress
~~~

### Single-flow throughput across RTTs

Use the separate-peer fixture to change the server backend while keeping
the client, workload, carrier and binary fixed. The kernel comparison
requires Linux WireGuard, namespace and firewall support on an isolated
worker. It uses the existing required kernel mode and fails if setup
cannot complete. The installed benchmark command uses the userspace
backend.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
  --output ./single-flow-high-rtt --modes direct-udp --compare-server-backends \
  --peer-netem 60 0 250 42 60 0 250 43 --peer-queue-packets 8192 \
  --workload bulk --connections 1 --duration 8s --warmup 1s --repeat 7
~~~

Repeat in a new output directory with 2 ms delay in each direction as a
low-RTT control. The 250 Mbit/s and 120 ms RTT profile has a nominal
bandwidth-delay product of about 3.75 MB. Size the delay queue for the
shaped traffic, then check both qdisc reports for drops. Keep that queue
capacity fixed within each pair. The measured interval uses a fresh
bulk flow, so its goodput includes TCP startup. Longer intervals can
help distinguish startup costs from a sustained limit.

Run host-direct and native-kernel-client controls separately with
`--modes direct native-wireguard-kernel` and the same qdisc settings.
The backend comparison changes the server TCP stack, WireGuard
implementation and packet bridge together. A throughput difference
locates a candidate bottleneck for profiling. TCP socket telemetry or
a controlled window change is needed to attribute it to window sizing.
Reported process CPU in these split runs describes the client.

The pinned WireGuard netstack adapter uses 1 MiB initial TCP buffers and a
4 MiB autotuning ceiling. Phase 1 evaluated larger ceilings with separate lab
builds. See the [no-go decisions](#phase-1-no-go-decisions) for the measured
window and memory tradeoffs.

### Counted TCP forwarding

Fixed TCP tunnels and transparent SOCKS server forwarding reuse the scratch
buffers used to count successfully written bytes during a stream. The idle
cache retains up to 2 MiB per process. Buffers are cleared before reuse, and
each active copy continues to own its buffer. Uncounted forwarding keeps the
standard Go copy path, including kernel fast paths when the socket pair is
eligible. Counted forwarding continues updating counters during the transfer
and propagating TCP half-closes.

Compare builds with `--baseline-binary --modes direct-udp --workload setup`
at a fixed connection count, then compare a one-connection `bulk` run and
a paced `mixed` workload over WSS. Report allocated bytes per successful
iteration alongside latency, errors, and goodput. Loopback reports include
allocation from both endpoints and the fixture. In split runs the allocation
counter describes only the client.

### UDP send overhead

Run the bind microbenchmarks on Linux to measure allocations and send time
for a single small datagram and for batches of full-size datagrams.

~~~sh
go test ./pkg/wstransport -run '^$' -bench '^BenchmarkUDPBindSend(Single|Batch)$' -benchmem -count 7
~~~

The receiver drains a local socket, and the benchmark records work at the
send call. Use a paired application bulk run to check delivered throughput
before enabling an optimization based on bind allocation results.

The bind writes single datagrams directly on the selected UDP socket,
including full-size packets. Sends of multiple datagrams still use Linux
batch I/O. To isolate the one-packet path before and after this change,
run `BenchmarkUDPBindSendBatch/1/standard` against both builds. Seven
paired Linux arm64 VM runs with a 1,420-byte payload reduced the send
cost from 292 allocated bytes and seven allocations to zero per call.
Median paired send time fell 12.3%, with a 95% interval of −22.3% to
−0.3%. The test measures the send call with a loopback receiver.
On the same VM, seven paired native UDP runs with four flows and 25 Mbit/s
per bulk worker reduced process allocations per completed iteration by
5.6%, with a 95% interval of −5.9% to −5.5%. The goodput interval was
−0.95% to +1.35%. No application requests failed or missed their scheduled
arrival. CPU and response p99 differences were inconclusive.
The separate-peer clean bulk control used one flow at 100 Mbit/s and
4 ms nominal RTT. Its seven pairs recorded zero qdisc drops and zero
application failures. The paired goodput interval was −0.42% to +1.79%.

Use `-bench '^BenchmarkUDPBindReceiveSingle$'` to measure per-datagram
receive allocations. This benchmark includes a loopback send with reused
buffers. macOS and Windows use the single-datagram bind path, while Linux
uses its batch receiver.

`BenchmarkUDPBindReceiveWindow` supplies the full WireGuard receive array
and measures sparse arrivals and prequeued bursts. The Linux receive
window starts at eight descriptors. Filling the window doubles it up to 128.
Thirty-two consecutive reads using at most a quarter of the window halve
it down to eight. The syscall returns as soon as packets are available.
WireGuard continues to supply its ordinary buffer array.

Seven paired Linux arm64 VM trials reduced median loopback send-and-read
time by 28.6% for a single arrival and 3.6% for bursts of eight. Nine
longer 64-packet burst pairs had a timing interval of −3.4% to +8.6%.
High packet-rate hardware qualification remains open. A separate
seven-pair native UDP trial with four flows and a 25 Mbit/s cap per bulk
worker reduced median paired response p99 by 9.1% (95% interval −14.3%
to −4.8%). Its goodput interval was −0.47% to +0.28%, with zero failed or
missed operations. The CPU effect was inconclusive.
Seven separate-peer single-flow pairs at 250 Mbit/s and 4 ms nominal RTT
had a goodput interval of −1.08% to +0.13%, with zero application failures
or qdisc drops.

### Phase 1 no-go decisions

These experiments used controlled Linux arm64 VM fixtures. The corresponding
ntwire pilots and their benchmark switches have been removed. Results below
are historical. Default activation was evaluated against goodput, completion
rate, and latency or resource improvement at matched load.

| Pilot | Observed result | Decision |
| --- | --- | --- |
| WSS byte budget and 20 ms expiration | Seven paced lossy pairs put byte-only p99 between −50% and +50%, with completion between −8.2% and +21.0%. The age policy also failed the goodput guard. In saturated runs median interactive completion fell from 16.8 replies/s to 11.0 with the byte budget and 10.5 with expiration. | No-go for this queue and drop policy. Keep sampling of the ordinary WSS queue and writer. Remove the unreleased `transport.wss_queue` block from any local pilot configuration before startup. |
| WSS `TCP_NOTSENT_LOWAT` presets | At 16 KiB, paced bulk goodput ranged from −26.3% to −0.2%. At 64 KiB the server-only p99 interval was −38.6% to +18.2%. A longer both-endpoint run recorded two application failures in one tuned sample, and paired p99 ranged from −17.65% to 0.0%. | No automatic preset. Keep the existing operator TCP socket option. |
| Smaller emulated bottleneck queue (32 instead of 4,096 netem packets) | Seven WSS saturation pairs at 25 Mbit/s and 4 ms RTT had application failures in both arms. Paced lossy WSS p99 rose 5.9–38.5%. The unpaced UDP control lost 77.5% of median paired bulk goodput and failures increased from 2 to 57. | No-go for this queue-depth prescription. Keep the generic lab queue-depth control. |
| Client UDP timer pacing | At 300 Mbit/s the timer-floor trial reduced paired bulk delivery by 31.3–54.5%. At 450 Mbit/s the interval was −43.5% to −3.9%. At lower offered load p99 rose 14.8–28.0% with comparable bulk delivery. | Reject the per-batch timer design. |
| Smaller server UDP socket buffers | A 64 KiB request under saturation had a median 4,369 receive-buffer errors, increased application failures from 40 to 51, and put goodput between −8.82% and +38.67%. At 256 KiB there were 630 median buffer errors and inconclusive p99. | Retain the existing socket requests. |
| Linux userspace UDP descriptor reuse, GSO, and GRO | Descriptor reuse reduced allocations but missed the 5% end-to-end throughput noninferiority guard. Split and loopback tunnel tests reported zero segmented sends and zero coalesced groups. Preformed socket-level GRO batches were faster, and ordinary tunnel traffic did not demonstrate that benefit. | Remove these userspace pilots. Qualify any future host or kernel optimization separately on representative hardware. |
| Shared relay UDP receive batching | Seven bulk pairs observed a median 15,158 multi-datagram reads. Goodput ranged from −28.2% to +12.5% and CPU per GiB from −11.2% to +23.6%. Sparse and paced mixed p99 medians did not improve. | Keep the normal receive path and its measured address-allocation improvements. |
| Wider gVisor TCP ceiling | At 120 ms, 16 MiB improved single-flow median goodput by 10.6% while client RSS rose from 108 to 212 MiB. At 4 ms goodput fell 5.0%. An independent 8 MiB trial gained 28.3% on one 120 ms flow, then lost 73.6% on four flows with 9,605 upstream qdisc drops and higher client RSS. | Keep the pinned gVisor defaults. |

### WSS writer and TCP backlog diagnosis

Use the Linux split-peer fixture and `--sample-wss-tcp` to retain `ss -tin`
observations for established TCP sockets between the two synthetic peers.
The launcher samples each direction about every 250 ms during measurement,
with a cap of 1,200 sampling intervals. Raw socket lines include
idle control connections. The TCP Send-Q includes unacknowledged and
unsent data, and `notsent` identifies the unsent part when reported by the
kernel. Run qualification separately to avoid the extra sampler overhead.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
  --output ./wss-tcp-diagnostics --modes wss --sample-wss --sample-wss-tcp \
  --peer-netem 2 0 25 42 2 0 25 43 --peer-queue-packets 4096 \
  --workload mixed --connections 4 --duration 4s --warmup 1s --repeat 5
~~~

On the Linux arm64 VM, the median of five per-run peak unsent observations
at 25 Mbit/s was about 365 KiB upstream and 527 KiB downstream. Median
sampled write p99 bins ended at 63 and 31 µs respectively, while application
p99 ranged from 172 ms to 1.57 s and each run reported application failures.
In the paced 0.5% loss profile, median per-run peak unsent observations
were about 230 KiB upstream and 249 KiB downstream, with zero application
failures. These observations separate bytes queued in TCP from time spent
inside the WSS writer. They do not attribute the full application tail to
any one stage.

### WSS outbound copy cost

The ordinary WebSocket send path copies the WireGuard buffers before
`Send` returns. For multi-datagram batches within WireGuard's
batch size, the copies share one backing allocation. Each datagram has its
own capacity-limited slice, and the writer emits one binary message per
datagram. Single-datagram calls use a single pass through the input.

~~~sh
go test ./pkg/wstransport -run '^$' -bench '^BenchmarkWebSocketBindSendCopy$' -benchmem -count 7
~~~

The benchmark enqueues to the ordinary WSS writer queue and drains it
locally, isolating ciphertext copy and enqueue cost at one, two, 16, and
64 datagrams. For an application comparison, run `run.py --baseline-binary`
with `--modes wss`. Use both a bulk workload and a paced mixed workload
and compare delivered throughput, response p99, and completed requests.
In a separate diagnostic comparison, `--sample-wss` records the ratio of
sampled datagrams to batches reaching the writers.

Seven paired Linux arm64 VM runs measured 2 allocations per send at all
four tested batch sizes. The references used 2, 3, 17, and 65 allocations
respectively. Median paired copy-and-enqueue time fell by 24.5% for two
datagrams, 40.6% for 16, and 47.0% for 64. The single-datagram time interval
spanned −4.1% to +15.1%.

The unpaced userspace bulk fixture sampled one datagram per write batch
and had high throughput variance. The isolated paced mixed fixture had
zero reported application failures. The paired 95% intervals were −10.3%
to +6.7% for interactive p99 and −0.01% to +1.0% for bulk goodput. A separate
eight-flow loopback run paced at 25 Mbit/s per worker delivered a goodput
interval of −0.27% to +0.42%, with zero reported application failures.
The copy-and-enqueue gain applies to multi-datagram sends. Use workloads
with observed batching to evaluate an application-level gain.

### WSS inbound allocation cost

Each WSS reader reuses 2 KiB of scratch space and gives the inbound queue
an independently owned datagram. Larger messages allocate temporary
storage for their remainder. They keep the existing frame limits and stay
on the same one-message-per-datagram wire format.

~~~sh
go test ./pkg/wstransport -run '^$' -bench '^BenchmarkWebSocketBindReceive$' -benchmem -count 7
~~~

Seven paired Linux arm64 VM runs measured a loopback WebSocket write and
delivery into the bind caller's buffer. At 1,420 bytes, allocations fell
from 11 to 6 per operation and total allocated bytes fell from 5,016 to
1,752. Median paired time fell 30.5% (95% interval −31.5% to −27.8%). The
32-byte case used one fewer allocation, and the 16 KiB case used 2 KiB
fewer allocated bytes. The large-message timing result was inconclusive.

In seven paired loopback tunnel runs with four flows and a 25 Mbit/s cap
per bulk worker, allocated bytes per completed operation fell 27.4% and
CPU per delivered GiB rose 3.1%. The goodput interval was −0.09% to
+0.57%, and no operations failed or missed an arrival. With 0.5% random
loss per direction and an 8 Mbit/s cap per bulk worker, allocated bytes
per operation fell 22.0%. Goodput stayed within 0.9% of the reference.
Interactive p99 was inconclusive in both profiles. The lossy comparison
recorded 549 missed arrivals after the change and 487 in the reference.
The unpaced single-flow control at 60 ms RTT and 100 Mbit/s had zero
qdisc drops or reported application failures. The paired goodput interval
of −52.6% to +72.4% leaves high-RTT throughput qualification open.

### WSS write deadlines

One cancellable context and one timer belong to each WSS writer. The timer
is armed for a dequeued batch and stopped when that batch finishes. If it
fires, cancellation interrupts the write and retires that carrier through
the existing failure and redial path. Each replacement has its own writer
and timer.

A paced loopback allocation profile on Linux arm64 attributed 13.5% of
sampled objects to per-batch `context.WithTimeout` calls. Reusing the
deadline state reduced allocated bytes per completed operation by 8.4%
across seven paired runs with four flows and a 25 Mbit/s cap per bulk
worker. Goodput was within −0.53% to +0.30% of the reference. Neither
build reported failed or missed operations. The CPU and p99 differences
were inconclusive.

### Adaptive carrier prototype checks

Run the real relay fixture to exercise one TCP stream through WireGuard,
switching between direct UDP, an alternate UDP socket, relay UDP, and TLS
WebSocket. The test checks traffic on every selected path and verifies the
original WireGuard handshake timestamp.

~~~sh
go test ./pkg/relay -run '^TestAdaptiveCarrier_'
go test ./pkg/wstransport -run '^$' -bench '^BenchmarkAdaptiveBindSendSingle$' -benchmem -count 7
~~~

The benchmark compares the existing UDP bind with adaptive dispatch for a
single datagram. Measure complete application throughput separately before
using the prototype for a release claim.

### Phase 2 qualification

Seven isolated Linux arm64 VM repetitions each exercised a lost primary
commit reply, WSS-to-QUIC failover, and live switching across both adaptive
UDP ports with renewal. In the WSS loss fixture, delivery resumed on the
existing TCP and UDP sockets in 26.9–30.6 ms with an available HTTPS
control path. A separate fixture recovered from a transient control
failure and kept both sockets. Closing the active alternate UDP socket
also preserved the TCP stream and returned it to WSS in 206–249 ms in
three macOS arm64 repetitions. These tests checked that the WireGuard
handshake timestamp stayed constant.

Both restricted-MTU tests passed at 1,380 bytes of outer MTU in an
isolated Linux namespace. The client retained WSS when native UDP or QUIC
could not carry the complete protected datagram. Seven 750 ms shared-link
outages at 100 Mbit/s and 4 ms nominal RTT produced a median 855 ms
application response gap (846–865 ms). Every run reused the local socket.

At 50 Mbit/s, 20 ms nominal RTT, and 0.1% loss in each direction, seven
paired mixed runs with one bulk worker capped at 2 Mbit/s completed
without application failures. QUIC and WSS bulk goodput stayed within
0.03%. The QUIC p99 interval was −15.6% to +14.8%, and client CPU per
delivered GiB rose 32.3–58.0%. WSS became unavailable in all seven
references in a separate four-worker, 0.5% loss run, so that profile
yielded no usable paired comparison. QUIC reported application failures
and queue drops in that profile. Use QUIC as an opt-in reachability and
recovery option pending a measured performance win on a path where
both carriers work.

For native UDP, seven macOS arm64 pairs at 20 Mbit/s per bulk worker
showed a goodput interval of −3.7% to +7.7% against the Phase 0 reference,
with zero application failures and 53 missed arrivals in each arm.
Uncapped loopback testing gave a wider interval of −16.4% to +1.1%,
and the Linux VM peak-throughput samples varied substantially. Peak-rate
noninferiority still requires a dedicated worker.

An isolated binary matrix paired the previous local main build
(`5f913adb538bf977dc2d62205177da74a742fedb`) with the Phase 2 client and
server. Both mixed-version orders delivered the fixed TCP workload over
legacy WSS, and two Phase 2 binaries delivered it over the negotiated
adaptive WSS path. The later Phase 3 Docker Compose run passed the
direct and relayed scenarios on the combined worktree. The full Linux
race suite remains a release check.

### Multi-lane flow placement

~~~sh
go test ./pkg/client -run '^(TestAdaptiveMultiLane_|TestLaneScale)'
go test ./pkg/client -run '^$' -bench '^BenchmarkAdaptiveWSSLaneFanout$' -benchmem -count 7
go test ./pkg/client -run '^$' -bench '^BenchmarkAdaptiveWSSConcurrency$' -benchmem -benchtime=3x
~~~

The fixtures qualify independent WireGuard peers, preserve live TCP
streams and UDP associations through normal scaling and renewal, and
verify parent-wide revocation. Additional tests exercise alternate UDP
and QUIC child paths, then fall back to WSS on the same child while
keeping a TCP flow and the anchor's active carrier. The local listeners
stay bound to the logical connection. `ntwire transport -v` and the
dashboard's **WireGuard lanes** panel report carrier, state and active
leases. Lease counts include setup and pooled sockets. When draining
starts, a plain HTTP proxy uses a fresh pool on its next request and closes
the old pool's idle sockets. An idle browser also releases them through
the existing HTTP idle timeout.

The automatic WSS pilot requires 30 seconds of sustained send queue
pressure with concurrent active flows. The client qualifies one canary
at a time up to the negotiated cap. The client keeps it after a
30-second compared window if one
direction improves delivered goodput by at least 15%, the other active
direction stays within 5%, and offered rates and concurrent flow counts
are comparable. Both periods require at least five fresh windows, and
the child must carry sustained traffic in the direction that improved.
A trial expires after 60 seconds. Success requires a new baseline on the
whole kept cohort before testing another lane. A retained child drains
after two minutes of low demand or a sustained carrier outage. The client
waits for existing leases and applies a five-minute cooldown plus jitter
after unsuccessful trials or retirement. The governor compares delivery
within the same link budget and adds no physical bandwidth assumption.
Native UDP and QUIC provide child carriers and failover. Automatic lane
growth presently uses WSS pressure evidence. Qualification on dedicated
hosts and representative profiles is required before widening defaults.

The fan-out benchmark warms eight fixed TCP streams and runs with 1, 2,
4 and 8 ready WSS lanes, checking placement and delivered bytes.
A separate concurrency benchmark verifies 100, 500 and 1,000
simultaneous TCP streams with 1 KiB request and echo payloads.
A result is aggregate goodput per
direction with 64 KiB outstanding per flow. A Linux worker can run the
benchmark executable through `tests/performance/linux-netem.sh` in an
isolated namespace to exercise a common constrained link. Compare the
same settings and repeat both cases in alternating order. Loopback
shaping affects all local hops, so release qualification also needs
separate-peer tests.

A macOS arm64 loopback screening run on an Apple M2 Pro with Go 1.27.4
used seven paired rounds, alternating lane order with eight measured
iterations per run. Peak RSS includes the fixture's server and client in
one process. The interval is the paired bootstrap 95% interval for the
relative change versus one lane.

| WSS lanes | Median goodput per direction | Paired delta (95% interval) | Median peak RSS |
|---|---:|---:|---:|
| 1 | 275 Mb/s | baseline | 90 MiB |
| 2 | 281 Mb/s | +9.4% (−0.9% to +21.4%) | 100 MiB |
| 4 | 271 Mb/s | −1.0% (−5.6% to +12.5%) | 121 MiB |
| 8 | 260 Mb/s | −12.5% (−30.0% to +28.0%) | 147 MiB |

All 28 runs confirmed the requested lane count and validated the echoed
bytes. A second 28-run sweep used a local Linux arm64 VM with a shared
100 Mbps loopback qdisc, 1 ms netem delay, and 1% random loss. Its median
goodput per direction was 12.80, 12.72, 12.48 and 12.48 Mb/s at 1, 2, 4
and 8 lanes respectively. The two-lane paired change was −1.9% with a
95% interval of −6.0% to +6.9%. Both eight-flow screens fall short of the
15% improvement gate, and peak memory increases as lanes are added.
Keep the one-lane default. The opt-in governor still retains a lane
only after a measured gain.

The macOS concurrency sweep validated 100, 500 and 1,000 active TCP
streams at all four lane counts. Repeated 1,000-stream measurements can
exhaust ephemeral ports on the host, so the paired comparison used a
fresh Linux network namespace per run. Each run kept 1,000 fixed TCP
streams open and exchanged 1 KiB on each stream per iteration. In six
completed pairs the median goodput per direction was 42.0 Mb/s on one
lane and 116.5 Mb/s on two, with a paired median gain of 174% (95%
interval of +93% to +417%). All seven two-lane runs completed. One
one-lane run timed out after WSS send-queue saturation. The Linux
fixture process peaked at about 1.5 GiB RSS for both variants, including
client, server and target. This supports the opt-in pilot for bursty,
high-concurrency WSS workloads. Separate-host latency under load,
long-lived resource limits and higher connection counts require
qualification on a dedicated worker.

### Performance-aware relay pilot

~~~sh
go test ./pkg/client -run '^TestAdaptiveRelayPerformance_'
go test ./pkg/client -run '^$' -bench '^BenchmarkAdaptiveRelayPerformance$' -benchmem -benchtime=32x
~~~

`relay.performance_routing` enables per-lane trials. The parent
observer monitors traffic on the anchor and child lanes and focuses
on one active lane at a time. It uses real forwarding counters,
bounded WireGuard tunnel echoes and existing path-epoch commits.
The scorer needs at least six recent tunnel RTT samples per path
and three comparable delivery windows. A relay needs a sustained
advantage, and a comparable direct path gets preference. An idle or
inconclusive trial tries to restore the qualified incumbent. Carrier
failure can interrupt a trial and trigger immediate recovery.

The paired integration test injects timing and delivery observations
to exercise the decision deterministically. It confirms the selection,
recovery, and live TCP data using real relays and WireGuard peers. A
separate test measures lane-local delivery and tunnel RTT with live
traffic through a child.

A local macOS arm64 screen used seven rounds in rotated order, 32
validated 16 KiB echo exchanges per run, one established TCP stream,
and real authorized relay forwarding. The fixture applied an opt-in
2 MiB/s directional ceiling to relay A. WireGuard and policy checks
were active in all three cases.

| Path | Median application goodput per direction | Median echo time |
|---|---:|---:|
| Direct WSS | 154 Mb/s | 0.85 ms |
| Relay A, capped | 0.72 Mb/s | 184 ms |
| Relay B, uncapped | 90 Mb/s | 1.46 ms |

All 21 runs completed. The capped relay illustrates how UDP policing
and inner TCP recovery interact under a bursty workload. The three
paths have comparable workload inputs and sharply different measured
costs. This profile favors the direct path. The results qualify local
functionality and keep general rollout dependent on separate-peer
trials across representative direct and relay networks.

### Negotiated WebSocket carrier pilot

Use the laboratory command to compare the existing WebSocket route and the
opt-in authenticated carrier on the same host. The report separates session
setup with the extra attach exchange from the steady-state workload.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
  --output ./local-adaptive-wss-results --modes wss adaptive-wss \
  --workload interactive --connections 2 --duration 10s --repeat 7 --require-progress
~~~


### Paired QUIC DATAGRAM pilot

Compare WSS and QUIC on the same adaptive device with the same fixed lane
MTU. The laboratory requires its selected carrier to exchange an echo
before measuring. With `--require-progress`, QUIC samples must retain
that path throughout measurement and record bidirectional encrypted
datagrams. The report includes queue drops observed by the client.
This QUIC comparison runs through the performance lab binary. Detailed
transport status shows carrier RTT when available. It uses QUIC's
smoothed RTT, an existing WebSocket heartbeat, or the authenticated UDP
qualification probe. These are carrier measurements. Application
latency and sustained goodput are measured separately.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
  --output ./local-quic-results --modes adaptive-wss quic-datagram \
  --adaptive-mtu 1280 --workload mixed --connections 4 \
  --duration 10s --repeat 7 --require-progress
~~~

Use the split Linux fixture for comparisons with directional shaping and
record the exact network profile. The QUIC pilot uses quic-go v0.66.0,
licensed under MIT. The performance gate must account for the second
layer of encryption, the path's actual encrypted-datagram budget and
any new queue drops. A successful size qualification alone establishes
reachability. [QUIC dependency release](https://github.com/quic-go/quic-go/releases/tag/v0.66.0)

For continuity of a coordinated switch, the following integration test
changes a live lane from QUIC to WSS after discarding the server's commit
reply, then returns it to QUIC. It checks payload delivery on the same
TCP stream, its original WireGuard handshake, and request replay.

~~~sh
go test ./pkg/client -run '^TestAdaptiveCarrier_PrimaryReconcilesLostCommit$'
~~~

### QUIC queue admission experiment

The laboratory can compare the existing drop policy with admission of a
complete WireGuard batch. Use `--quic-send-wait 0` for batching alone or
`--quic-send-wait 2ms` to allow a short wait for capacity in the existing
32-slot send queue. The maximum experimental wait is 5 ms per batch and
only one sender can wait per peer. The queue size stays fixed. The wait
ends if the carrier or bind closes. QUIC still controls congestion and
paces transmission. The experiment has no effect on ordinary connections.

~~~sh
/tmp/ntwire-bench-lab benchmark --transport quic-datagram --adaptive-mtu 1280 \
  --workload mixed --connections 4 --warmup 2s --duration 8s --json
/tmp/ntwire-bench-lab benchmark --transport quic-datagram --adaptive-mtu 1280 \
  --workload mixed --connections 4 --warmup 2s --duration 8s --quic-send-wait 2ms --json
~~~

The JSON report records explicit wait settings, queue drops, how often a
sender waited, and aggregate admission wait time. The one-process fixture
reports both client and server counters. The separate-peer runner reports
client counters. A drop reduction needs to hold alongside comparable
goodput, tail latency, and missed interactive arrivals before rollout.

~~~sh
python3 tests/performance/run.py --binary /tmp/ntwire-bench-lab \
  --output ./quic-admission-results --modes quic-datagram --compare-quic-admission \
  --adaptive-mtu 1280 --peer-netem 10 0.5 50 42 10 0.5 50 43 \
  --workload mixed --connections 4 --warmup 2s --duration 8s --repeat 7 --require-progress
~~~

### Sustained carrier observations

With adaptive feedback negotiated, the client forms five-second
forwarding windows while traffic is active. Upload delivery is counted
at the server forwarding boundary. Download delivery is counted at the
client. Offered rates describe bytes accepted from each sender, including
proxy framing where applicable. A direction with no offered traffic
has no measurement for that window. These observations describe
delivery at the tunnel boundaries. They do not measure target
application acknowledgments or establish available link capacity.

`ntwire transport -v` reports time-weighted delivered rates by direction
across one bounded lane history. The history keeps up to twelve windows
for sixty seconds. Rates are calculated across the observed paths
without adding estimates for different carriers on the same lane.
The performance lab's JSON report includes the retained windows, which
may include warm-up observations. RTT comes from the carrier. The
adaptive client can request an extra WebSocket heartbeat when at least
16 KiB was forwarded in the last one-second observation. It uses the
existing heartbeat loop, with at most one ping in flight and two
seconds between pings. A local write backlog suppresses extra requests.
WebSocket queue p95 is available when queue sampling is enabled.
Ordinary bearer renewal can retain completed windows when the granted
tunnels stay the same. Any interval that crosses the renewal is discarded.

With the opt-in adaptive carrier and both feedback and path selection
negotiated, the client can run one trial on a qualified WSS or QUIC alternate
or a qualified authorized UDP relay. It waits at least 30 seconds on the
incumbent and requires six recent RTT observations and three active
forwarding windows before it starts. Local write backlog, elevated sampled
WSS queue residence, or sustained QUIC send queue drops delay exploration.
The client also defers new trials when two current windows on the same
path and authorization generation show upload or download pressure. Each
window must show that direction's delivery falling below 80% of a busy
sender's accepted bytes, or the corresponding sender's queue signal.
`ntwire transport -v` reports the pressured direction and the lower of
its two observed delivery rates. The evidence expires after 10 seconds
and leaves failure recovery independent. It applies to the single-lane
feedback path and does not set a pacing rate.

The parent also admits at most one optional standby qualification or
performance trial at a time across WSS, QUIC, native UDP, and relay paths.
Current directional pressure or WSS write backlog suspends that work.
The same shared observations can suppress optional qualification while
multiple managed lanes are active. A qualified standby remains available
for recovery. There is one outbound primary per lane, and the current
carriers retain their existing congestion control and queue bounds.

With multiple managed lanes, the same observer requests feedback for the
anchor and its children every five seconds while forwarding is active.
The requests share a two-second deadline. Each lane's byte deltas are
normalized using its own elapsed clock before the receiver and sender
rates are combined with the parent's local counters. An unavailable lane,
changed roster, new path epoch, authorization change, or mismatched clock
invalidates the shared window. The automatic WSS lane trial reuses this
sample and issues no second feedback request for its child.

After two comparable windows, `ntwire transport -v` reports the observed
upload and download floors across the parent. Those observations expire
after 10 seconds. They stay separate from the path comparison history.
A queue on just one carrier is insufficient evidence of shared pressure.
The shared report uses aggregate delivery shortfall and does not apply a
rate cap or split a fixed budget between lanes.

The trial forwards existing traffic on the same WireGuard lane for up to
30 seconds. When the incumbent is native or relayed UDP, the trial ends
after 20 seconds to leave time to restore its 30-second retained proof.
When measured traffic goes idle the client attempts to restore the
incumbent early.

The comparison requires six recent RTT observations per path and
three comparable demand windows. It estimates the time to deliver a
reference 128 KiB in each active direction using observed delivery and
RTT. The initial improvement margin is 15% and 5 ms. A reversal
within two minutes requires 20% and 10 ms. At least three of the latest
comparable windows must clear the margin, and confidence must reach
0.65. Sparse, stale, or inconclusive evidence triggers an attempt to
restore the incumbent. The next trial waits at least two minutes plus
per-trial jitter. `ntwire transport -v` reports the trial result and
recent evidence.

Relay comparisons use tunnel RTT on both paths and keep it separate from
carrier RTT in performance windows. During forwarding on a single lane,
the client sends at most one small ICMP echo every two seconds to the
authenticated server's tunnel address. Outstanding echoes have a 650 ms
deadline. The client earns one probe after at least 16 KiB of forwarding
while active, and checks for a local WebSocket write backlog before sending.
Performance windows record completed probe attempts and successful replies.
Path or generation
changes discard in-flight observations. A direct-to-relay trial must clear
the sustained gain threshold. A relay-to-direct trial can retain the direct
path if its measured completion cost is within 5% or 2 ms, whichever is
larger, across enough fresh matched windows. Missing tunnel observations
leave the incumbent in place.

The live relay fixture exercises the detailed observation windows on WSS
and relay UDP and checks the same TCP socket across path changes. The
scoring tests exercise equivalent, faster, and insufficiently observed
paths with controlled inputs.

~~~sh
go test ./pkg/client -run '^TestAdaptive(Relay_Qualifies|Trial_.*Relay)'
~~~

To observe multiple windows and include a regular session renewal, run
one steady workload for at least 24 seconds following warm-up.

~~~sh
/tmp/ntwire-bench-lab benchmark --transport adaptive-wss --adaptive-mtu 1280 \
  --workload interactive --connections 4 --warmup 2s --duration 24s --sample-wss --json
~~~

Use the lab's `adaptive-auto` mode with a sustained fixture workload
to record both selected paths and the trial decision. To compare fixed
carriers, the lab also provides `adaptive-wss` and `quic-datagram`.

~~~sh
/tmp/ntwire-bench-lab benchmark --transport adaptive-auto --adaptive-mtu 1280 \
  --workload interactive --connections 4 --warmup 2s --duration 78s --sample-wss --json
~~~

Hard WSS failure can move a lane to an already-qualified QUIC standby
without waiting for performance windows. The following fixture closes
the original WSS socket, rejects replacement upgrades, and times the
first successful exchange on both the existing TCP and UDP sockets.
It checks that the same WireGuard handshake is retained. The HTTPS
control channel stays available throughout the test.

~~~sh
go test ./pkg/client -run '^TestAdaptiveCarrier_WSSFailureRecoversThroughQualifiedQUIC$' -count=7 -v
~~~

## Phase 5 Smart Egress Proxy qualification

Adaptive ranking and warm preparation are independent opt-ins. The ranking
test compares a low-setup, lower-bandwidth egress with a higher-setup egress
that can finish bulk traffic sooner. It also checks route restrictions and
expired path evidence. Private transfer observations are kept in memory
and never cause DNS queries. The native SOCKS resolver already coalesces
in-flight lookups through Go's resolver. Its address API supplies no DNS TTL
for a second cache. The existing authorized numeric dial remains the only
target connection per submission. Racing target addresses was deferred.

Run the local ranking and live Smart Proxy checks with controlled fixtures.

~~~sh
go test ./pkg/egressrouter -run '^Test(AdaptiveRanking|WarmService)'
go test ./pkg/egressrouter -run '^$' -bench '^BenchmarkSmartProxyPerformanceRanking$' -benchtime=150ms -count=3
go test ./pkg/client -run '^$' -bench '^BenchmarkSmartProxyWarmService$' -benchtime=12x -count=3
go test ./pkg/client -run '^$' -bench '^BenchmarkSmartProxyAdaptiveFanout$/^(100|500|1000|4096)$' -benchtime=1x
go test ./pkg/client -run '^$' -bench '^BenchmarkSmartProxyAdaptiveFanout$/^10000$' -benchtime=1x
~~~

On an M2 Pro running darwin/arm64 with Go 1.27.4 and GOMAXPROCS=2, the warm
benchmark sent SOCKS traffic through an authenticated local attachment, a
loopback WireGuard UDP path with 10 ms delay per forwarded packet, and a local
TCP echo target. Requests were spaced by 300 ms. Across three runs of 12
samples per mode, the median run's setup p95 was 125.0 ms with Adaptive and
87.3 ms with Adaptive plus warm preparation, a 30% reduction. The median
run's TTFB p95 was 173.1 ms and 146.3 ms respectively. All 36 measured warm
requests reused a preparation. Destination-aware setup p95 was 125.0 ms
in its median run. These samples describe one repeating setup workload.

The single-group fan-out smoke held and exchanged application bytes on 100,
500, 1,000 and 4,096 simultaneous SOCKS connections. All ran through one local
direct WireGuard UDP egress. The 4,096 runs took about 1.4–2.2 seconds to open
the group, exchange one byte in each direction on every connection and
initiate close. Each iteration allocated approximately 893–901 MB
cumulatively. Peak resident memory and long-duration saturation were outside
this smoke test. In the ranking microbenchmark, the median 2-member operation
was 1.33 µs with Adaptive and 1.00 µs with Destination aware. The median
64-member operation was 43.0 µs and 32.5 µs respectively.

The 10,000-flow run used three groups with independent WireGuard peers and
targets on the same host. The 8,061st indexed dial failed with
`EADDRNOTAVAIL` on the local proxy connection. A subsequent Linux run
verified this count with its larger ephemeral port range. See the
[standard rollout results](#standard-connection-rollout). Production
qualification also needs a repeated
heterogeneous-egress workload on separate hosts with concurrent interactive
and bulk traffic and sustained resource measurements. The local evidence
supports keeping warm preparation opt-in and the existing selection defaults.

The local Go suite and focused Phase 5 race tests passed. The full macOS
race attempt hit carrier qualification and forwarding deadlines in the
client integration package. The QUIC commit and hostname-binding cases
also failed under race instrumentation in the saved Phase 4 snapshot.
The uninstrumented Smart Proxy and hostname-binding compatibility tests
passed with Phase 5. Docker returned HTTP 503 on the local socket, so the
Compose deployment smoke remains pending.

## Phase 6 Linux backend qualification

The [Linux acceleration guide](LINUX-ACCELERATION.md) documents the backend
split, explicit consent, rollback and paired release gates. Backend comparisons
now retain host busy and softirq counters, an idle baseline and per-case
qualification results. The automated case result describes one transport and
one workload. A release still needs the cross-transport and deployment checks.

The legacy kernel bridge is available through `--acceleration=required`.
On Linux, `auto` with `allow_auto: true` tries the bridge and permits
fallback after clean teardown. Adaptive sessions keep their userspace
device. The earlier Linux bridge pilots fell short of the performance
target. The Linux amd64 and arm64 build checks passed. A Docker retest on
Linux arm64 with LinuxKit 7.0.14 passed opted-in kernel startup, userspace
fallback with capabilities removed, rollback, hybrid peer isolation, crash
recovery, native and allocated UDP relay, alternate UDP, and WSS integrity
with and without multipath. A later amd64 binary smoke passed isolation,
startup, clean fallback and crash cleanup in Docker's amd64 execution
environment on the arm64 host. Native amd64 hardware qualification
remains open.

Seven separate-peer pairs per transport compared the kernel bridge and
userspace backend at 100 Mbit/s in each direction and 20 ms nominal RTT,
with a two-connection mixed workload and a 10 Mbit/s cap per bulk worker.
Every sample delivered traffic. The existing release gate reported:

| Transport | Paired verdict |
|---|---|
| Direct UDP | Insufficient benefit. Bulk delivery was equivalent, while median host CPU per delivered GiB was 31.6% higher with the kernel bridge. |
| Alternate UDP | Passed the throughput and p95 guard. |
| WSS | Passed the throughput and p95 guard. |
| UDP relay | Inconclusive at the p95 margin. |

Acceleration stays an explicit operator choice. This profile leaves the
overall backend performance qualification open. It also leaves open a
native-only acceleration comparison on dedicated hosts.

## Phase 7 release decisions

The new carriers are opt-in startup alternatives for the initial WireGuard
lane. A healthy WSS upgrade keeps its existing behavior. HTTP/3 follows
raw QUIC during fallback and requires a complete encrypted datagram in
both directions. HTTP/2 can start where the HTTPS origin remains reachable
and a WebSocket upgrade fails. The HTTP carriers use the same session
grants and WireGuard validation as the existing adaptive bind.

| Task | Disposition | Release evidence or reopening condition |
|---|---|---|
| P7-T01 HTTP/3 CONNECT-UDP | Implemented as an opt-in reachability pilot. | Fixed TCP and UDP forwarding, TCP renewal continuity, explicit rejection of unrelated UDP targets, and isolated Linux MTU fallback. Qualify with representative separate-host paths, reverse-path loss and MTU conditions before wider rollout. |
| P7-T02 HTTP/2 framed carrier | Implemented as an opt-in reachability pilot. | Verified TLS bootstrap, TCP and UDP forwarding, credential renewal, revocation, length bounds and denial handling. Qualify streaming through representative proxies and HTTP/2 ingress before wider rollout. |
| P7-T03 stream bonding | Deferred. | First demonstrate a single-flow ceiling that survives TCP window, CPU and carrier tuning and can be relieved within one physical link budget. Reopen with a controlled, single-destination prototype whose useful delivery improves by at least 15% with bounded reassembly. |
| P7-T04 packet bonding | Deferred. | Show a shared-link case where qualified alternatives improve unique payload goodput over the best path while tolerating packet reordering, replay-window pressure and rekeys. The Phase 3 WSS fan-out result supports flow isolation at high concurrency. Same-lane striping still needs a controlled comparison. |
| P7-T05 adaptive FEC | Deferred. | Require a repeatable loss case where a bounded parity prototype improves delivery or latency under the same total wire budget against tuned no-FEC. Measure clean links, bursts and congestive loss independently. |
| P7-T06 asymmetric paths | Deferred. | Show a persistent opposing path advantage on a controlled asymmetric topology and a useful gain over the best single path. A candidate protocol must commit both directions together and preserve symmetric-path recovery. |

Run the local integration and performance screens with a controlled fixture.

~~~sh
go test ./pkg/client -run '^TestAdaptiveCarrier_HTTP[23]'
go test ./pkg/client -run '^$' -bench '^BenchmarkAdaptiveHTTPCarrier$' -benchmem -count 7
~~~

Seven loopback samples per case ran in an isolated Linux arm64 Docker VM
with Go 1.27.4, a 1,280-byte lane MTU, two Go workers and a 300 ms benchmark
target. These are medians from serial TCP echo on the one-process fixture.
Bulk rate counts the sent 64 KiB per request/echo round trip.

| Carrier | 29-byte echo | 64 KiB echo rate |
|---|---:|---:|
| WSS | 126 µs | 54.0 MB/s |
| HTTP/2 | 136 µs | 34.4 MB/s |
| HTTP/3 | 135 µs | 2.3 MB/s |

HTTP/3 bulk results ranged from 1.0 to 18.9 MB/s. The screen supports
keeping both HTTP paths as reachability pilots. Broad rollout still
requires paired comparisons under load and loss, plus investigation of
the HTTP/3 bulk variability.

The reduced MTU test requires an isolated namespace with loopback MTU at
most 1,380 bytes. Run `TestAdaptiveCarrier_HTTP3SmallMTUUsesHTTP2` there
with `NTWIRE_TEST_LIMITED_UDP_MTU=1`. The fixed 1,420-byte lane must bootstrap
through HTTP/2 when the dedicated UDP path cannot carry the full HTTP/3
datagram. A separate 1,280-byte fixture tests successful HTTP/3 delivery.

The full Go suite and the Docker Compose direct and relay end-to-end run
passed. Linux arm64 passed the reduced-MTU fixture and focused race checks,
including the reconnect case rerun in isolation. Core client and server
builds also passed for Linux amd64, macOS amd64 and Windows amd64/arm64.
macOS race runs hit carrier and forwarding deadlines. Runtime checks on
Windows and Kubernetes ingress validation remain release gates.

HTTP/3 uses the HTTP/3 implementation shipped by the already pinned quic-go
release and adds its pure-Go QPACK dependency, v0.6.0. The MIT notice ships
with the client, server, relay and GUI. Deployment uses a dedicated port and
same-instance control routing. The rollout gate also covers ingress
streaming, platform smoke, module vulnerability scans, binary overhead
and before/after goodput and latency measurements. [QPACK license](https://github.com/quic-go/qpack/blob/v0.6.0/LICENSE.md)
· [HTTP Datagrams](https://www.rfc-editor.org/rfc/rfc9297.html)
· [CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298.html)

## Standard connection rollout

`ntwire connect` and GUI profiles with no saved override now offer adaptive
WireGuard by default over verified HTTPS. The server still controls admission
to the adaptive plane and the allowed carriers. If its adaptive lane budget
is full, a session with optional adaptive features can use the existing
WireGuard plane. If an adaptive upgrade is unreachable, the client can retry
once using its existing authentication method, issuer, verified origin and
WireGuard key. Authentication and authorization denials stop the retry.

Eight isolated Linux arm64 CLI cases exercised the candidate, the prior
pilot build and the committed legacy tree at `5f913adb538bf977dc2d62205177da74a742fedb`.
They covered adaptive negotiation without a flag, both legacy/candidate
orders, a disabled adaptive plane, and the explicit client rollback.
Every case verified the selected carrier and fixed-tunnel echo.
The separate Compose verifier also passed both relay/server version orders
against the committed legacy tree, with 20 consecutive rounds each across
session renewal.

The paired smoke used Go 1.27.4, LinuxKit 7.0.14 on arm64, separate veth
peers, two Go workers, seven alternating pairs and a three-second measured
window. Adaptive sessions stayed on WSS in these windows. The comparison
therefore measures the overhead of default negotiation and the initial lane.

| Profile | Bulk or interactive goodput, paired 95% interval | Response p99, paired 95% interval | Median session setup change |
|---|---:|---:|---:|
| 100 Mbit/s per direction, 4 ms nominal RTT, zero loss, interactive | −0.04% to +0.04% | 0% to +4.5% | +8.3% |
| 100 Mbit/s per direction, 20 ms nominal RTT, 0.1% loss per direction, 10 Mbit/s bulk cap, mixed | 0% to +1.0% bulk | −11.8% to +7.1% | +11.4% |

Both profiles completed every sample. The extra adaptive attach exchange
increased initial setup time. These results support the client default for
operator-enabled servers. Automatic promotion and wider activation still
need sustained separate-host performance evidence.

A separate 65-second mixed run used the same impaired profile, a
1,280-byte lane MTU and a 2 Mbit/s bulk cap. The client automatically
trialed QUIC and restored WSS when the median estimated gain across three
comparable windows was 0.23%. All 3,171 operations completed. This verified
live automatic trial and restoration on the controlled path.

The Linux Smart Proxy fan-out smoke verified echo with 4,096 and 10,000
simultaneous connections across configured groups. The 10,000-flow run
took 3.40 seconds and the container peaked at 1.63 GiB across both cases.
This qualifies the aggregate loopback capacity smoke. Sustained capacity
and heterogeneous egress still require a longer, separate-host run.

The full Go suite, focused Linux session race checks, release fuzz smoke,
Docker direct and relayed end-to-end cases, and cross-builds passed. The
native kernel WireGuard client and the 1,380-byte outer-MTU cases also
passed. The base and accelerated Kubernetes overlays rendered with
Kustomize. Live
Kubernetes ingress and Windows runtime checks remain open. Binary scans
found zero reachable vulnerabilities in the candidate client and server.
The scanner reported a module-level OpenPGP advisory and the build graph
contains no OpenPGP package. [Go advisory](https://pkg.go.dev/vuln/GO-2026-5932)

## Programme closeout and release gates

| Phase | Implementation disposition | Evidence required for wider release or defaults |
|---|---|---|
| 0 Performance foundation | Benchmark CLI, lab, workload profiles and stage counters available. | Maintain scheduled, repeatable baselines on dedicated workers and record skip reasons for unsupported hardware. |
| 1 Existing data paths | Measured changes retained and unsuccessful pilots recorded above. | Confirm platform-specific queue and socket behavior on release hardware. |
| 2 Adaptive carriers | Standard clients offer adaptive negotiation for operator-enabled servers. Existing carriers and optional QUIC measured and exercised. | Run sustained separate-host path and saturation tests before expanding automatic promotion. Shared-capacity feedback currently gates exploration. Aggregate pacing and fair allocation remain open. |
| 3 Multi-lane | Transparent optional children with leases, drain and shared quotas. | Keep the one-lane default. Qualify 5,000–10,000 aggregate connections on suitable hardware before broadening the high-concurrency pilot. |
| 4 Relay performance | Optional authorized per-lane discovery, qualification and routing. | Validate real multi-region cost, failover and loaded direct/relay comparisons. |
| 5 Smart Egress | Optional adaptive scoring and bounded service preparation. Aggregate 10,000-flow loopback smoke passed. | Confirm sustained loaded workloads with heterogeneous egress, DNS privacy, app affinity and deployment smoke. |
| 6 Linux acceleration | Explicitly authorized Linux auto setup and safe userspace fallback verified on arm64 and emulated amd64. | Direct UDP missed the benefit gate and UDP relay was inconclusive. Native amd64 hardware and deployment qualification remain open. |
| 7 Additional carriers | HTTP pilots independently disableable. Experimental transport slices deferred. | Qualify each carrier in its intended restricted network, then consider broader opt-in. Keep bonding and FEC off the release path. |

Disable experimental or pilot capabilities before a binary downgrade and
remove newly added fields from overlays read by an older strict parser.
Keep existing credentials and listeners. See [Release requirements](RELEASE.md)
and the [HTTP carrier configuration](CONFIGURATION.md#http-carrier-pilots).
