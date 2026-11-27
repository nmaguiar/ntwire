# Phase 0 performance baseline and Phase 1 handoff

The Phase 0 benchmark CLI and laboratory exercise the existing WireGuard
paths using synthetic applications and disposable credentials. The installed
CLI owns a loopback fixture. The Linux laboratory also supports independent
client and server namespaces with directional impairment, an ordinary
WireGuard client, and a real UDP relay. See the [benchmark guide](PERFORMANCE.md)
for commands, workload definitions, profile collection and JSON fields.

## Phase 0 exit criteria

| Task | Evidence |
| --- | --- |
| P0-T01 benchmark CLI and fixture | The CLI runs bounded loopback workloads with disposable identities. The Linux lab exercises isolated peers, kernel WireGuard and a real relay. |
| P0-T02 measurement and profiling | Reports include connection setup, response latency, goodput, queue residence and process resources. The profile smoke produced all four profiles. The seven-pair WSS sampling comparison met the 2% overhead margin for the paced loopback workload. |
| P0-T03 comparative baseline and CI | Seven independent repetitions across seven reference paths, separate single-flow and loaded samples, and an outage smoke provide a baseline for Phase 1. The workflow schedules portable smoke runs and supports a manual Linux namespace run. |

These results qualify the fixtures for Phase 1 comparisons. Use host-wide
measurements on dedicated runners to qualify throughput defaults or
hardware-dependent optimizations for release.

## Reference evidence

The reference laboratory was built for Linux arm64 with Go 1.27.3 from a
modified checkout of `5f913adb538bf977dc2d62205177da74a742fedb`. Its SHA-256 is
`4069ac81b69b8e745e43be973d9e902a09c78a5d48b8287204c23a99b3eb40c1`.
The recorded upstream main at handoff was `2debf7db1cd2b0519d634b8a609278f47a72be11`.
The archived executable identifies the exact binary under test. For fresh
comparisons, keep the exact baseline and candidate binaries, or commit the
source for both builds, and record both binary hashes.

The Linux split runs used an Apple Silicon VM with two pinned vCPUs and
isolated veth peers. The client egress was shaped to 100 Mbit/s at 2 ms
one-way delay and the server egress to 200 Mbit/s at 4 ms, with seeds 42 and
43. Loaded loss was applied independently in both directions. These runs
describe the isolated fixture and are suitable for reproducing its baseline
and selecting measurements for Phase 1. Hardware and NIC qualification
require dedicated runners. For split runs, process resource counters belong
to the client. Use host-wide counters for kernel or relay efficiency claims.

The interactive reference used two workers, a 1 s warm-up and a 3 s
measurement interval. All 49 runs finished with measured echoes and zero
reported application failures. Multipath-v3 negotiated its normal mode and
selected WSS in this fixture.

| Requested mode | Observed path | Median of seven per-run p99 values |
| --- | --- | ---: |
| Host direct | TCP over veth | 14.34 ms |
| ntwire native UDP | Direct UDP | 13.82 ms |
| Official Linux WireGuard | Kernel client peer | 14.34 ms |
| Alternate UDP | Alternate UDP | 13.31 ms |
| Relay UDP | Authenticated UDP relay | 13.31 ms |
| WSS | WSS | 12.80 ms |
| Multipath-v3 | WSS | 12.80 ms |

These short trials establish a working comparative baseline. Use longer
trials and more latency samples to qualify a p99 improvement.

The seven 4 s single-flow bulk pairs also completed. Native UDP delivered a
median 28.6 Mbit/s per direction and WSS delivered 5.0 Mbit/s. The paired WSS
goodput interval spanned approximately −91% to +205%. Six of seven native
UDP runs also recorded upstream qdisc drops with configured random loss at
zero. Use these samples to reproduce the saturated-profile variability.
For a clean throughput control, verify qdisc drops and match the queue and
rate across builds before interpreting an improvement.

The four-flow mixed profile used 0.5% random loss in each direction. Median
delivered goodput was 51.6 Mbit/s per direction for native UDP and 26.7 Mbit/s
for WSS. Median per-run interactive p99 was 111 ms for UDP and 393 ms for WSS.
One WSS run had no successful interactive response, so the p99 comparison
has six pairs. Review that starvation and the 1,065 missed WSS interactive
arrivals alongside the p99 values when testing whether WSS queueing explains
the tail latency.

The current Go 1.27.4 laboratory reran the 750 ms link outage. The application
response gap was 860 ms over native UDP and 841 ms over WSS in one trial each.
Both workers reused their local socket. These single trials verify recovery
reporting and do not establish a recovery percentile.

Use WSS queue diagnostics only when measuring a queue hypothesis. The paired
2% noninferiority gate covers throughput and CPU per delivered GiB. Seven
paired Go 1.27.4 runs on macOS arm64 passed for the paced loopback mixed
workload with four workers and 25 Mbit/s per bulk worker. The 95% paired
intervals were −0.28% to +0.48% for goodput and −4.13% to +1.86% for CPU
per delivered GiB. Earlier trials were inconclusive on CPU. Sampling
remains opt-in. Leave it off for ordinary baseline and candidate runs.

The macOS Go 1.27.4 smoke also completed three repetitions each of fresh TCP
setup, fixed UDP echo, SOCKS5 and HTTP CONNECT over native UDP and WSS. The
100-worker interactive smoke completed 30,000 exchanges per transport over
three runs without reported failures. An earlier 500-worker smoke recorded
failures and serves as a saturation data point. The WSS profile run produced
CPU, heap, allocation and goroutine profiles and sampled queue residence at
both endpoints.

## Phase 1 comparison procedure

1. Select one bottleneck and one candidate change. Build the reference and
   candidate with the same patched Go version and build flags. Keep the
   fixture workload, directional qdiscs, CPU placement, and byte limits
   identical. Use `run.py --baseline-binary` for an alternating pair, with
   seven or more completed repetitions and enough byte headroom to finish
   the intended measurement window.
2. Run native UDP or relay UDP for packet hot-path changes. Compare useful
   delivery, CPU and allocations with a clean UDP control. For forwarding
   changes, use fresh connection setup and single-flow bulk. For WSS queue
   changes, measure interactive p99, missed arrivals and bulk delivery in
   the same loaded run, plus a high-BDP throughput control.
3. Keep `environment.json`, raw per-run JSON and `summary.json`. Record the
   actual paths, any excluded or failed samples, and paired confidence
   intervals. Choose tolerances before collecting the comparison. Use the
   initial 5% native UDP throughput margin only when the calibrated runner
   can resolve it. An interval that crosses a tolerated regression leaves
   the change unqualified. Keep conditional optimizations disabled until
   their performance and compatibility checks pass.
4. Repeat recovery and legacy protocol checks for transport or forwarding
   changes. Check for response gaps, socket replacement and pre/post-outage
   progress. Run the ordinary [release checks](RELEASE.md) before shipping.
