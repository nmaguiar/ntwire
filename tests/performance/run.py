#!/usr/bin/env python3
"""Run paired, controlled local benchmarks and retain raw JSON."""

import argparse
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys


DEFAULT_MODES = ("direct", "direct-udp", "wss", "multipath")
MODES = (*DEFAULT_MODES, "native-wireguard-go", "native-wireguard-kernel", "udp-relay", "alternate-udp", "adaptive-wss", "quic-datagram", "adaptive-auto")
KERNEL_SERVER_MODES = {"direct-udp", "alternate-udp", "multipath", "wss", "udp-relay",
                       "native-wireguard-go", "native-wireguard-kernel"}
DEFAULT_PEER_QUEUE_PACKETS = 1024
MIN_PEER_QUEUE_PACKETS = 16
MAX_PEER_QUEUE_PACKETS = 32768
NETEM_STATS_PREFIX = "ntwire netem qdisc "


def write_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def server_peak_rss_bytes(stderr):
    prefix = "ntwire server peak RSS KiB "
    for line in stderr.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix)) * 1024
    return None


def comparison(baseline, candidate, field):
    deltas = []
    for reference, trial in zip(baseline, candidate):
        if reference is None or trial is None:
            continue
        a, b = field(reference), field(trial)
        if a and b is not None:
            deltas.append(100 * (b / a - 1))
    if not deltas:
        return None
    result = {"pairs": len(deltas), "median_pct": statistics.median(deltas),
              "min_pct": min(deltas), "max_pct": max(deltas)}
    if len(deltas) >= 7:
        rng = random.Random(0)
        medians = sorted(statistics.median(rng.choices(deltas, k=len(deltas))) for _ in range(5000))
        result["bootstrap_95_pct"] = [medians[125], medians[4874]]
    return result


def comparable_runs(baseline, candidate):
    """Keep matched runs that completed the same kind of measurement window."""
    references, trials, unmatched = [], [], []
    for index, (reference, trial) in enumerate(zip(baseline, candidate), 1):
        if reference is None or trial is None:
            continue
        if reference["end_reason"] != trial["end_reason"]:
            unmatched.append(index)
            continue
        references.append(reference)
        trials.append(trial)
    return references, trials, unmatched


def cpu_per_gib(run):
    delivered = run["echo_bytes_per_direction"]
    seconds = run["process"].get("process_cpu_seconds")
    if delivered and seconds is not None:
        return seconds * (1 << 30) / delivered
    return None


def host_cpu_per_gib(run):
    """Busy ticks above the idle baseline per bidirectional GiB."""
    cpu = run.get("host_cpu")
    delivered = run["echo_bytes_per_direction"]
    if not cpu or not delivered or not cpu["idle_baseline_elapsed_us"]:
        return None
    busy = cpu["busy_ticks"] - cpu["idle_baseline_busy_ticks"] * (
        cpu["elapsed_us"] / cpu["idle_baseline_elapsed_us"])
    return busy * (1 << 30) / (2 * delivered) if busy > 0 else None


def allocated_bytes_per_iteration(run):
    allocated = run["process"].get("allocated_bytes")
    if run["iterations"] and allocated is not None:
        return allocated / run["iterations"]
    return None


def interactive_completed_per_second(run):
    count = run["response_latency"].get("count")
    elapsed = run.get("sample_duration_ms")
    if count is not None and elapsed:
        return count * 1000 / elapsed
    return None


def backend_response_p95(run):
    response = run["response_latency"]
    return response.get("p95_us") if response.get("count", 0) >= 30 else None


def summarize_mode(runs):
    accepted = [run for run in runs if run is not None]
    recovery = [run["link_recovery"] for run in accepted if run.get("link_recovery")]

    def distribution(field):
        samples = [value for run in accepted if (value := field(run)) is not None]
        if not samples:
            return None
        return {"runs": len(samples), "min": min(samples),
                "median": statistics.median(samples), "max": max(samples)}

    summary = {
        "accepted_runs": len(accepted),
        "excluded_runs": len(runs) - len(accepted),
        "selected_paths": sorted({path for run in accepted for path in run["selected_paths"]}),
        "end_reasons": {reason: sum(run["end_reason"] == reason for run in accepted)
                        for reason in sorted({run["end_reason"] for run in accepted})},
        "echo_bps_per_direction": distribution(lambda run: run["echo_bps_per_direction"]),
        "bulk_socket_write_bps": distribution(lambda run: run.get("bulk", {}).get("socket_write_bps")),
        "bulk_echo_bps_per_direction": distribution(lambda run: run.get("bulk", {}).get("echo_bps_per_direction")),
        "response_p99_us": distribution(lambda run: run["response_latency"].get("p99_us")),
        "response_p95_us": distribution(lambda run: run["response_latency"].get("p95_us")),
        "interactive_completed_per_second": distribution(interactive_completed_per_second),
        "connection_setup_p95_us": distribution(lambda run: run["connection_setup"].get("p95_us")),
        "process_cpu_seconds_per_gib": distribution(cpu_per_gib),
        "host_busy_ticks_per_gib": distribution(host_cpu_per_gib),
        "process_allocated_bytes_per_iteration": distribution(allocated_bytes_per_iteration),
        "process_lifetime_peak_rss_bytes": distribution(
            lambda run: run["process"].get("process_lifetime_peak_rss_bytes")),
        "sampled_open_fd_peak": distribution(lambda run: run["process"].get("sampled_open_fd_peak")),
        "completed": sum(run["iterations"] for run in accepted),
        "failures": sum(run.get("failures", 0) for run in accepted),
        "aborted": sum(run.get("aborted", 0) for run in accepted),
        "missed_interactive_arrivals": sum(run.get("missed_interactive_arrivals", 0) for run in accepted),
    }
    if recovery:
        summary["link_recovery"] = {
            "response_gap_ms": distribution(
                lambda run: (run.get("link_recovery") or {}).get("response_gap_ms")),
            "socket_reused_runs": sum(result.get("socket_replaced") is False for result in recovery),
            "socket_replaced_runs": sum(result.get("socket_replaced") is True for result in recovery),
        }
    if peak := distribution(lambda run: run.get("server_process_lifetime_peak_rss_bytes")):
        summary["server_process_lifetime_peak_rss_bytes"] = peak
    return summary


def netem_profile(values):
    delay, loss, rate = map(float, values[:3])
    seed = int(values[3])
    numbers = (delay, loss, rate)
    if (not all(map(math.isfinite, numbers)) or not 0 <= delay <= 1000 or
            not 0 <= loss <= 100 or not 1 <= rate <= 10000 or not 1 <= seed <= 2**32 - 1):
        raise ValueError("netem requires delay 0–1000 ms, loss 0–100%, rate 1–10000 Mbit/s and a nonzero uint32 seed")
    return {"delay_ms": delay, "loss_percent": loss, "rate_mbit": rate, "seed": seed}


def netem_stats(stderr, prefix=NETEM_STATS_PREFIX):
    for line in reversed(stderr.splitlines()):
        if line.startswith(prefix):
            qdiscs = json.loads(line.removeprefix(prefix))
            for qdisc in qdiscs:
                if qdisc["kind"] == "netem":
                    return qdisc
    raise ValueError("netem wrapper did not report an active qdisc")


def profile_args(profile):
    numbers = ("delay_ms", "loss_percent", "rate_mbit", "seed")
    return [f"{profile[key]:g}" if key != "seed" else str(profile[key]) for key in numbers]


def qdisc_stats(stderr, split):
    if not split:
        return netem_stats(stderr)
    return {direction: netem_stats(stderr, f"ntwire netem {direction} ")
            for direction in ("upstream", "downstream")}


def wss_tcp_samples(stderr):
    records = {"upstream": [], "downstream": []}
    for line in stderr.splitlines():
        if line.startswith("ntwire wss tcp "):
            direction, index, socket = line.removeprefix("ntwire wss tcp ").split(maxsplit=2)
            records[direction].append({"sample": int(index), "socket": socket})
    if not all(records.values()):
        raise ValueError("missing established TCP samples in one or both directions")
    return records


def sampling_gate(metrics, margin, expected_pairs, failed_samples=()):
    """Distinguish a measured regression from an inconclusive comparison."""
    if failed_samples or metrics.get("different_end_reason_repetitions"):
        return "inconclusive"
    throughput_result = metrics["echo_bps_per_direction_delta"] or {}
    cpu_result = metrics["process_cpu_per_gib_delta"] or {}
    if throughput_result.get("pairs") != expected_pairs or cpu_result.get("pairs") != expected_pairs:
        return "inconclusive"
    throughput = throughput_result.get("bootstrap_95_pct")
    cpu = cpu_result.get("bootstrap_95_pct")
    if (throughput and throughput[1] < -margin) or (cpu and cpu[0] > margin):
        return "regression"
    if throughput and cpu and throughput[0] >= -margin and cpu[1] <= margin:
        return "pass"
    return "inconclusive"


def kernel_backend_gate(metrics, transport, workload, expected_pairs, failed_samples):
    """Evaluate one paired case. Release qualification still requires all transports."""
    if failed_samples or metrics["different_end_reason_repetitions"]:
        return "inconclusive"

    def interval(name):
        value = metrics.get(name) or {}
        if value.get("pairs") == expected_pairs:
            return value.get("bootstrap_95_pct")
        return None

    throughput = interval("bulk_echo_bps_per_direction_delta" if workload in ("mixed", "bulk")
                          else "echo_bps_per_direction_delta")
    latency = interval("response_p95_us_delta")
    if (throughput and throughput[1] < -5) or (latency and latency[0] > 5):
        return "regression"
    if not throughput or not latency or throughput[0] < -5 or latency[1] > 5:
        return "inconclusive"
    if transport != "direct-udp":
        return "pass"
    cpu = interval("host_cpu_per_gib_delta")
    if throughput[0] >= 15 or (cpu and cpu[1] <= -15):
        return "pass"
    if throughput[1] < 15 and cpu and cpu[0] > -15:
        return "insufficient_benefit"
    return "inconclusive"


def wss_sampling_exclusion(run, sampled):
    if not run["iterations"] or run["selected_paths"] != ["wss"]:
        return "sampling comparison requires measured echoes on WSS throughout the run"
    if run.get("failures"):
        return "sampling comparison requires error-free measured traffic"
    client = run.get("client_wss") or {}
    server = run.get("server_wss") or {}
    if not sampled:
        if client.get("enabled") or server.get("enabled"):
            return "WSS sampling was enabled in the reference run"
        return None
    if any(not queue.get("enabled") or not queue.get("sampled_batches") for queue in (client, server)):
        return "WSS sampling did not record queue batches at every measured endpoint"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--baseline-binary", type=Path,
                        help="pair one transport across a reference and a candidate build")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--hardware-notes",
                        help="record the benchmark CPU model, clock policy, and fixture hardware")
    parser.add_argument("--modes", nargs="+", choices=MODES, default=list(DEFAULT_MODES))
    parser.add_argument("--workload", default="mixed")
    parser.add_argument("--connections", type=int, default=10)
    parser.add_argument("--duration", default="30s")
    parser.add_argument("--warmup", default="10s")
    parser.add_argument("--max-bytes", type=int, default=4 << 30)
    parser.add_argument("--bulk-rate-mbps", type=int, default=0,
                        help="application bulk write limit in Mbit/s per worker")
    parser.add_argument("--repeat", type=int, default=7)
    parser.add_argument("--sample-wss", action="store_true")
    parser.add_argument("--sample-wss-tcp", action="store_true",
                        help="collect TCP socket backlog from the isolated WSS peers for diagnosis")
    parser.add_argument("--adaptive-mtu", type=int, help="match adaptive fixture MTUs from 1280 to 1420")
    comparison_group = parser.add_mutually_exclusive_group()
    comparison_group.add_argument("--compare-wss-sampling", action="store_true",
                        help="pair WSS runs with sampling off and on")
    comparison_group.add_argument("--compare-quic-admission", action="store_true",
                                  help="compare QUIC legacy admission, batching, and batching with a 2ms wait")
    comparison_group.add_argument("--compare-server-backends", action="store_true",
                                  help="pair userspace and required kernel WireGuard on the isolated server")
    parser.add_argument("--require-kernel-qualification", action="store_true",
                        help="fail unless the paired backend case passes its qualification thresholds")
    parser.add_argument("--require-progress", action="store_true",
                        help="fail if a measured run completes no echoes")
    parser.add_argument("--sampling-margin-pct", type=float,
                        help="require WSS sampling noninferiority in throughput and process CPU per GiB")
    parser.add_argument("--link-outage-ms", type=int,
                        help="drop the fixture client link for 100–10000 ms after one second of measurement")
    topology = parser.add_mutually_exclusive_group()
    topology.add_argument("--netem", nargs=4, metavar=("DELAY_MS", "LOSS_PERCENT", "RATE_MBIT", "SEED"),
                        help="run each sample in a fresh shaped Linux network namespace")
    topology.add_argument("--peer-netem", nargs=8,
                          metavar=("UP_DELAY", "UP_LOSS", "UP_RATE", "UP_SEED",
                                   "DOWN_DELAY", "DOWN_LOSS", "DOWN_RATE", "DOWN_SEED"),
                          help="run separate Linux peers with independent upstream and downstream qdiscs")
    parser.add_argument("--peer-queue-packets", type=int, default=DEFAULT_PEER_QUEUE_PACKETS,
                        help="netem queue capacity per direction in the split fixture (default: 1024)")
    args = parser.parse_args()
    if not 1 <= args.repeat <= 30:
        parser.error("--repeat must be between 1 and 30")
    if args.bulk_rate_mbps and (not 1 <= args.bulk_rate_mbps <= 10000 or args.workload not in ("bulk", "mixed")):
        parser.error("--bulk-rate-mbps requires a value from 1 to 10000 and a bulk or mixed workload")
    if args.adaptive_mtu is not None and (not 1280 <= args.adaptive_mtu <= 1420 or
                                          set(args.modes) - {"adaptive-wss", "quic-datagram", "adaptive-auto"}):
        parser.error("--adaptive-mtu requires an adaptive mode and a value from 1280 to 1420")
    if len(set(args.modes)) != len(args.modes):
        parser.error("--modes cannot contain duplicates")
    if args.baseline_binary and (args.compare_wss_sampling or args.compare_quic_admission or
                                 args.compare_server_backends or len(args.modes) != 1):
        parser.error("--baseline-binary requires one mode and cannot be combined with another comparison")
    if args.compare_server_backends and (
            not args.peer_netem or len(args.modes) != 1 or args.modes[0] not in KERNEL_SERVER_MODES):
        parser.error("--compare-server-backends requires --peer-netem and one legacy or native WireGuard mode")
    if args.require_kernel_qualification and (not args.compare_server_backends or args.repeat < 7):
        parser.error("--require-kernel-qualification requires --compare-server-backends and at least seven pairs")
    if (not MIN_PEER_QUEUE_PACKETS <= args.peer_queue_packets <= MAX_PEER_QUEUE_PACKETS or
            (args.peer_queue_packets != DEFAULT_PEER_QUEUE_PACKETS and not args.peer_netem)):
        parser.error("--peer-queue-packets requires --peer-netem and a capacity from 16 to 32768")
    if args.compare_quic_admission and args.modes != ["quic-datagram"]:
        parser.error("--compare-quic-admission requires --modes quic-datagram")
    if args.compare_wss_sampling and args.sample_wss:
        parser.error("--compare-wss-sampling conflicts with --sample-wss")
    if args.sampling_margin_pct is not None and (
            not args.compare_wss_sampling or not 0 < args.sampling_margin_pct <= 100):
        parser.error("--sampling-margin-pct requires --compare-wss-sampling and a margin in (0, 100]")
    if "native-wireguard-kernel" in args.modes and not args.peer_netem:
        parser.error("the Linux kernel WireGuard client requires --peer-netem")
    if args.link_outage_ms is not None and (
            not args.peer_netem or not 100 <= args.link_outage_ms <= 10000 or
            args.workload != "interactive" or args.connections != 1):
        parser.error("--link-outage-ms requires --peer-netem and one interactive worker")
    profile = None
    if args.netem or args.peer_netem:
        if platform.system() != "Linux":
            parser.error("--netem requires a Linux worker")
        try:
            if args.peer_netem:
                profile = {"upstream": netem_profile(args.peer_netem[:4]),
                           "downstream": netem_profile(args.peer_netem[4:])}
            else:
                profile = netem_profile(args.netem)
        except ValueError as exc:
            parser.error(str(exc))
    modes = args.modes
    if args.compare_wss_sampling:
        modes = ["wss", "wss-sampled"]
    elif args.compare_quic_admission:
        modes = ["quic-datagram", "quic-batch", "quic-wait"]
    elif args.compare_server_backends:
        modes = [modes[0], modes[0] + "-kernel-server"]
    binary = args.binary.resolve(strict=True)
    reference_binary = None
    if args.baseline_binary:
        reference_binary = args.baseline_binary.resolve(strict=True)
        modes = [modes[0] + "-baseline", modes[0]]
    if args.sample_wss_tcp and (not args.peer_netem or set(modes) - {"wss", "wss-baseline"}):
        parser.error("--sample-wss-tcp requires an isolated WSS diagnostic comparison")
    args.output.mkdir(mode=0o700)

    def digest(path):
        with path.open("rb") as source:
            return hashlib.file_digest(source, "sha256").hexdigest()

    network = "unshaped IPv4 loopback"
    if args.peer_netem:
        network = "isolated Linux veth peers with directional qdiscs"
    elif args.netem:
        network = "isolated Linux loopback qdisc"
    affin = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    write_json(args.output / "environment.json", {
        "binary_sha256": digest(binary),
        "baseline_binary_sha256": digest(reference_binary) if reference_binary else None,
        "os_release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "cpu_affinity": affin,
        "gomaxprocs_override": os.environ.get("GOMAXPROCS"),
        "hardware_notes": args.hardware_notes,
        "network": network,
        "netem": profile,
        "peer_queue_packets": args.peer_queue_packets if args.peer_netem else None,
        "link_outage_ms": args.link_outage_ms,
        "bulk_rate_mbps_per_worker": args.bulk_rate_mbps,
        "parameters": {
            "modes": modes,
            "workload": args.workload,
            "connections": args.connections,
            "duration": args.duration,
            "warmup": args.warmup,
            "max_bytes_per_direction": args.max_bytes,
            "repeat": args.repeat,
            "sample_wss": args.sample_wss,
            "sample_wss_tcp": args.sample_wss_tcp,
            "sampling_margin_pct": args.sampling_margin_pct,
            "require_progress": args.require_progress,
            "adaptive_mtu": args.adaptive_mtu,
        },
    })
    runs = {mode: [] for mode in modes}
    environment = {**os.environ, "NTWIRE_BENCH_WSS_TCP": "1" if args.sample_wss_tcp else "0",
                   "NTWIRE_BENCH_HOST_CPU": "1" if args.compare_server_backends else "0"}
    failures = []
    args_common = ["--json", "--workload", args.workload,
                   "--connections", str(args.connections), "--duration", args.duration,
                   "--warmup", args.warmup, "--max-bytes", str(args.max_bytes)]
    if args.sample_wss:
        args_common.append("--sample-wss")
    if args.adaptive_mtu is not None:
        args_common.append(f"--adaptive-mtu={args.adaptive_mtu}")
    if args.bulk_rate_mbps:
        args_common.append(f"--bulk-rate-mbps={args.bulk_rate_mbps}")
    if args.link_outage_ms is not None:
        args_common.append(f"--link-outage={args.link_outage_ms}ms")
    # Rotate queue comparisons through all orderings. Reverse other profiles
    # on alternating repetitions to reduce systematic drift.
    queue_orders = list(itertools.permutations(modes)) if args.compare_quic_admission else []
    for rep in range(1, args.repeat + 1):
        if queue_orders:
            order = queue_orders[(rep - 1) % len(queue_orders)]
        else:
            order = modes if rep % 2 else reversed(modes)
        for mode in order:
            transport = mode.removesuffix("-sampled").removesuffix("-baseline")
            executable = reference_binary if mode.endswith("-baseline") else binary
            flags = [*args_common, *(["--sample-wss"] if mode == "wss-sampled" else [])]
            kernel_server = args.compare_server_backends and mode.endswith("-kernel-server")
            if kernel_server:
                transport = mode.removesuffix("-kernel-server")
                flags.append("--kernel-server")
            if mode in ("quic-batch", "quic-wait"):
                transport = "quic-datagram"
                flags.append("--quic-send-wait=2ms" if mode == "quic-wait" else "--quic-send-wait=0")
            command = [str(executable), "benchmark", *flags, "--transport", transport]
            if args.peer_netem:
                wrapper = Path(__file__).with_name("linux-peers.sh").resolve()
                queue_args = ["--queue-packets", str(args.peer_queue_packets)]
                command = ["sh", str(wrapper), *queue_args, *profile_args(profile["upstream"]),
                           *profile_args(profile["downstream"]), "--", str(executable), transport, *flags]
            elif profile:
                wrapper = Path(__file__).with_name("linux-netem.sh").resolve()
                command = ["sh", str(wrapper), *profile_args(profile), "--", *command]
            sample = f"{rep:02}-{mode}"
            try:
                output = subprocess.run(command, capture_output=True, text=True, timeout=420, env=environment)
            except subprocess.TimeoutExpired:
                write_json(args.output / f"{sample}.failure.json",
                           {"schema": 1, "sample": sample, "error": "command_timeout"})
                failures.append(sample)
                runs[mode].append(None)
                print(f"{sample}: command timed out", file=sys.stderr, flush=True)
                continue
            if output.returncode:
                failure = {"schema": 1, "sample": sample, "exit_code": output.returncode}
                if profile:
                    try:
                        failure["netem_qdisc"] = qdisc_stats(output.stderr, args.peer_netem is not None)
                    except ValueError:
                        pass
                write_json(args.output / f"{sample}.failure.json", failure)
                failures.append(sample)
                runs[mode].append(None)
                print(f"{sample}: {output.stderr.strip()}", file=sys.stderr, flush=True)
                continue
            try:
                report = json.loads(output.stdout)
                if profile:
                    report["netem_qdisc"] = qdisc_stats(output.stderr, args.peer_netem is not None)
                if args.sample_wss_tcp:
                    report["wss_tcp_samples"] = wss_tcp_samples(output.stderr)
                run = report["runs"][0]
                if args.peer_netem and (peak := server_peak_rss_bytes(output.stderr)) is not None:
                    run["server_process_lifetime_peak_rss_bytes"] = peak
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                write_json(args.output / f"{sample}.failure.json",
                           {"schema": 1, "sample": sample, "error": "invalid_report", "detail": str(exc)})
                failures.append(sample)
                runs[mode].append(None)
                continue
            reason = None
            if args.compare_server_backends and report.get("backend") != ("kernel" if kernel_server else "userspace"):
                reason = "fixture report does not confirm the requested server WireGuard backend"
            elif args.compare_server_backends and (
                    not run["iterations"] or run.get("failures") or not run.get("host_cpu")):
                reason = "backend comparison requires measured echoes, host CPU samples and no forwarding failures"
            elif args.compare_server_backends and transport != "multipath" and args.link_outage_ms is None and (
                    run["selected_paths"] != [transport]):
                reason = "backend comparison requires the requested path throughout measurement"
            if args.bulk_rate_mbps and run.get("bulk", {}).get("limit_mbps_per_worker") != args.bulk_rate_mbps:
                reason = "missing bulk write limit in the report"
            if args.link_outage_ms is not None:
                recovery = run.get("link_recovery") or {}
                gap_ms = recovery.get("response_gap_ms")
                if (recovery.get("requested_outage_ms") != args.link_outage_ms or
                        recovery.get("pre_outage_echo") is not True or recovery.get("restored_echo") is not True or
                        type(gap_ms) is not int or gap_ms <= 0 or not isinstance(recovery.get("socket_replaced"), bool)):
                    reason = "missing complete observations for the requested fixture link outage"
            if mode in ("quic-batch", "quic-wait") and run.get("quic_send_wait_us") != (2000 if mode == "quic-wait" else 0):
                reason = "missing QUIC admission configuration in the report"
            if args.compare_wss_sampling and reason is None:
                reason = wss_sampling_exclusion(run, mode == "wss-sampled")
            if (args.require_progress or args.compare_server_backends) and reason is None:
                if not run["iterations"]:
                    reason = "no measured echoes"
                elif (args.link_outage_ms is None and transport not in ("multipath", "adaptive-auto")
                      and run["selected_paths"] != [transport]):
                    reason = f"{transport} was not selected throughout measurement"
                elif args.link_outage_ms is None and transport == "quic-datagram" and not (
                        run.get("client_quic", {}).get("sent") and run.get("client_quic", {}).get("received")):
                    reason = "missing bidirectional measured QUIC datagrams"
                elif args.link_outage_ms is None and transport == "udp-relay":
                    traffic = run.get("client_udp_relay", {})
                    if run["selected_paths"] != ["udp-relay"] or not (
                            traffic.get("packets_sent") and traffic.get("packets_received")):
                        reason = "missing bidirectional measured relay traffic"
            if reason:
                report["exclusion_reason"] = reason
                failures.append(sample)
                runs[mode].append(None)
                print(f"{sample}: {reason}", file=sys.stderr, flush=True)
            else:
                runs[mode].append(run)
            write_json(args.output / f"{sample}.json", report)
            print(f"{rep}/{args.repeat} {mode}", flush=True)
    comparisons = {}
    pairs = [(mode, modes[0], mode) for mode in modes[1:]]
    if args.compare_quic_admission:
        pairs.append(("quic-wait-vs-batch", "quic-batch", "quic-wait"))
    for name, baseline, mode in pairs:
        references, trials, unmatched = comparable_runs(runs[baseline], runs[mode])
        comparisons[name] = {
            "baseline": baseline,
            "different_end_reason_repetitions": unmatched,
            "echo_bps_per_direction_delta": comparison(
                references, trials, lambda run: run["echo_bps_per_direction"]),
            "response_p99_us_delta": comparison(
                references, trials, lambda run: run["response_latency"].get("p99_us")),
            "session_connect_us_delta": comparison(
                references, trials, lambda run: run.get("ntwire_connect_us")),
            "connection_setup_p95_us_delta": comparison(
                references, trials, lambda run: run["connection_setup"].get("p95_us")),
            "process_cpu_per_gib_delta": comparison(
                references, trials, cpu_per_gib),
            "process_allocated_bytes_per_iteration_delta": comparison(
                references, trials, allocated_bytes_per_iteration),
        }
        if args.compare_quic_admission:
            comparisons[name]["quic_send_queue_drops_delta"] = comparison(
                references, trials, lambda run: run.get("client_quic", {}).get("send_queue_drops"))
        if args.compare_server_backends:
            comparisons[name]["response_p95_us_delta"] = comparison(references, trials, backend_response_p95)
            comparisons[name]["host_cpu_per_gib_delta"] = comparison(references, trials, host_cpu_per_gib)
        if args.workload in ("bulk", "mixed"):
            for metric in ("socket_write_bps", "echo_bps_per_direction"):
                comparisons[name][f"bulk_{metric}_delta"] = comparison(
                    references, trials, lambda run: run.get("bulk", {}).get(metric))
        if args.link_outage_ms is not None:
            comparisons[name]["link_recovery_gap_ms_delta"] = comparison(
                references, trials, lambda run: run["link_recovery"].get("response_gap_ms"))
    summary = {"schema": 1, "modes": {mode: summarize_mode(results) for mode, results in runs.items()},
               "comparisons": comparisons, "failed_samples": failures}
    status = 1 if failures else 0
    if args.compare_server_backends:
        result = kernel_backend_gate(comparisons[modes[1]], modes[0], args.workload, args.repeat, failures)
        summary["kernel_backend_gate"] = {"transport": modes[0], "workload": args.workload, "result": result}
        if args.require_kernel_qualification and result != "pass":
            status = 1
    if args.sampling_margin_pct is not None:
        gate = sampling_gate(comparisons["wss-sampled"], args.sampling_margin_pct, args.repeat, failures)
        summary["sampling_gate"] = {"margin_pct": args.sampling_margin_pct, "result": gate}
        if gate != "pass":
            status = 1
    write_json(args.output / "summary.json", summary)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
