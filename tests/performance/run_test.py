import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from run import (comparable_runs, comparison, host_cpu_per_gib, kernel_backend_gate, main, netem_profile, netem_stats, qdisc_stats,
                 sampling_gate, summarize_mode, wss_sampling_exclusion,
                 wss_tcp_samples)


class NetemTest(unittest.TestCase):
    def test_kernel_gate_pairs_and_noise(self):
        run = {"echo_bytes_per_direction": 1 << 29, "host_cpu": {
            "busy_ticks": 60, "elapsed_us": 2000000, "idle_baseline_busy_ticks": 5,
            "idle_baseline_elapsed_us": 1000000,
        }}
        self.assertEqual(host_cpu_per_gib(run), 50)
        run["host_cpu"]["busy_ticks"] = 9
        self.assertIsNone(host_cpu_per_gib(run))

        def bounds(low, high, pairs=7):
            return {"pairs": pairs, "bootstrap_95_pct": [low, high]}

        good = {
            "different_end_reason_repetitions": [],
            "bulk_echo_bps_per_direction_delta": bounds(-2, 2),
            "response_p95_us_delta": bounds(-3, 4),
            "host_cpu_per_gib_delta": bounds(-21, -16),
        }
        cases = (
            ({}, "direct-udp", [], "pass"),
            ({"host_cpu_per_gib_delta": bounds(-12, -9)}, "direct-udp", [], "insufficient_benefit"),
            ({"host_cpu_per_gib_delta": bounds(-22, -9)}, "direct-udp", [], "inconclusive"),
            ({"host_cpu_per_gib_delta": None}, "udp-relay", [], "pass"),
            ({"bulk_echo_bps_per_direction_delta": bounds(16, 20), "host_cpu_per_gib_delta": None},
             "direct-udp", [], "pass"),
            ({"response_p95_us_delta": bounds(6, 12)}, "wss", [], "regression"),
            ({"response_p95_us_delta": bounds(2, 7)}, "wss", [], "inconclusive"),
            ({"response_p95_us_delta": bounds(1, 2, pairs=6)}, "wss", [], "inconclusive"),
            ({}, "direct-udp", ["02-direct-udp"], "inconclusive"),
        )
        for overrides, transport, failures, expected in cases:
            self.assertEqual(kernel_backend_gate({**good, **overrides}, transport, "mixed", 7, failures), expected)

    def test_profile(self):
        self.assertEqual(
            netem_profile(["5", "0.5", "100", "42"]),
            {"delay_ms": 5, "loss_percent": 0.5, "rate_mbit": 100, "seed": 42},
        )
        for values in (
            ["NaN", "0", "100", "42"],
            ["5", "-1", "100", "42"],
            ["5", "0.5", "0", "42"],
            ["5", "0.5", "100", "4294967296"],
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                netem_profile(values)

    def test_only_active_netem_diagnostics_are_read(self):
        result = netem_stats(
            'ignored fixture diagnostic\n'
            'ntwire netem qdisc [{"kind":"noqueue"},{"kind":"netem","packets":23}]\n'
        )
        self.assertEqual(result["packets"], 23)
        with self.assertRaises(ValueError):
            netem_stats('ntwire netem qdisc [{"kind":"noqueue"}]')

    def test_failed_runs_do_not_shift_pairing(self):
        delta = comparison([100, 1000, 200], [110, None, 220], lambda rate: rate)
        self.assertEqual(delta["pairs"], 2)
        self.assertAlmostEqual(delta["median_pct"], 10)

    def test_pairs_require_matching_measurement_stop_reason(self):
        timed = {"end_reason": "duration"}
        capped = {"end_reason": "byte_limit"}
        baseline, candidate, unmatched = comparable_runs(
            [timed, capped, timed, None, capped], [capped, capped, timed, timed, None]
        )
        self.assertEqual(baseline, [capped, timed])
        self.assertEqual(candidate, [capped, timed])
        self.assertEqual(unmatched, [1])

    def test_directional_stats_are_kept_separate(self):
        result = qdisc_stats(
            'ntwire netem downstream [{"kind":"netem","packets":20}]\n'
            'ntwire netem upstream [{"kind":"netem","packets":30}]\n', True)
        self.assertEqual(result["upstream"]["packets"], 30)
        self.assertEqual(result["downstream"]["packets"], 20)

    def test_wss_tcp_samples_keep_direction_and_interval(self):
        sample = ("ignored diagnostic\n"
                  "ntwire wss tcp downstream 2 0 512 peer-a peer-b notsent:256\n"
                  "ntwire wss tcp upstream 2 0 0 peer-b peer-a\n")
        result = wss_tcp_samples(sample)
        self.assertEqual(result["downstream"], [{"sample": 2, "socket": "0 512 peer-a peer-b notsent:256"}])
        self.assertEqual(result["upstream"], [{"sample": 2, "socket": "0 0 peer-b peer-a"}])
        with self.assertRaises(ValueError):
            wss_tcp_samples(sample.splitlines()[1])

    def test_sampling_gate_uses_both_confidence_intervals(self):
        results = {
            "echo_bps_per_direction_delta": {"pairs": 8, "bootstrap_95_pct": [-1.5, 0.2]},
            "process_cpu_per_gib_delta": {"pairs": 8, "bootstrap_95_pct": [-0.4, 1.9]},
        }
        self.assertEqual(sampling_gate(results, 2, 8), "pass")
        self.assertEqual(sampling_gate(results, 2, 8, ["02-wss"]), "inconclusive")
        results["different_end_reason_repetitions"] = [2]
        self.assertEqual(sampling_gate(results, 2, 8), "inconclusive")
        del results["different_end_reason_repetitions"]
        results["process_cpu_per_gib_delta"]["bootstrap_95_pct"] = [-0.4, 3.0]
        self.assertEqual(sampling_gate(results, 2, 8), "inconclusive")
        results["process_cpu_per_gib_delta"]["bootstrap_95_pct"] = [2.1, 3.0]
        self.assertEqual(sampling_gate(results, 2, 8), "regression")

    def test_sampling_gate_requires_both_metrics_for_every_repetition(self):
        results = {
            "echo_bps_per_direction_delta": {"pairs": 8, "bootstrap_95_pct": [-1, 1]},
            "process_cpu_per_gib_delta": {"pairs": 7, "bootstrap_95_pct": [-1, 1]},
        }
        self.assertEqual(sampling_gate(results, 2, 8), "inconclusive")
        results["process_cpu_per_gib_delta"]["pairs"] = 8
        results["echo_bps_per_direction_delta"]["pairs"] = 7
        self.assertEqual(sampling_gate(results, 2, 8), "inconclusive")

    def test_wss_sampling_comparison_requires_queue_evidence(self):
        reference = {"iterations": 100, "selected_paths": ["wss"]}
        queue = {"enabled": True, "sampled_batches": 5}
        client_only = {**reference, "client_wss": queue}
        both = {**client_only, "server_wss": queue}
        self.assertIsNone(wss_sampling_exclusion(reference, False))
        self.assertIsNone(wss_sampling_exclusion(both, True))
        self.assertIn("reference run", wss_sampling_exclusion(both, False))
        self.assertIn("queue batches", wss_sampling_exclusion(client_only, True))
        self.assertIn("queue batches", wss_sampling_exclusion(reference, True))
        empty = {**reference, "client_wss": {**queue, "sampled_batches": 0}}
        self.assertIn("queue batches", wss_sampling_exclusion(empty, True))
        switched = {**both, "selected_paths": ["direct-udp", "wss"]}
        self.assertIn("throughout", wss_sampling_exclusion(switched, True))
        failed = {**both, "failures": 1}
        self.assertIn("error-free", wss_sampling_exclusion(failed, True))

    def test_absolute_summary_retains_resource_and_failure_evidence(self):
        timed = {
            "iterations": 30, "failures": 4, "missed_interactive_arrivals": 8,
            "selected_paths": ["wss"], "end_reason": "duration",
            "echo_bps_per_direction": 2000, "echo_bytes_per_direction": 100,
            "bulk": {"socket_write_bps": 1900, "echo_bps_per_direction": 1800},
            "response_latency": {"p99_us": 10}, "connection_setup": {},
            "process": {"process_lifetime_peak_rss_bytes": 4096, "sampled_open_fd_peak": 40,
                        "allocated_bytes": 960},
        }
        capped = {**timed, "failures": 1, "aborted": 2, "end_reason": "byte_limit",
                  "echo_bps_per_direction": 4000, "process": {}}
        summary = summarize_mode([timed, None, capped])
        self.assertEqual(summary["accepted_runs"], 2)
        self.assertEqual(summary["excluded_runs"], 1)
        self.assertEqual(summary["end_reasons"], {"duration": 1, "byte_limit": 1})
        self.assertEqual(summary["echo_bps_per_direction"]["median"], 3000)
        self.assertEqual(summary["bulk_echo_bps_per_direction"]["median"], 1800)
        self.assertEqual(summary["sampled_open_fd_peak"], {"runs": 1, "min": 40, "median": 40, "max": 40})
        self.assertEqual(summary["process_allocated_bytes_per_iteration"]["median"], 32)
        self.assertIsNone(summary["connection_setup_p95_us"])
        self.assertEqual(summary["completed"], 60)
        self.assertEqual(summary["failures"], 5)
        self.assertEqual(summary["aborted"], 2)
        self.assertEqual(summary["missed_interactive_arrivals"], 16)
        self.assertNotIn("link_recovery", summary)

        reused = {**timed, "link_recovery": {"response_gap_ms": 820, "socket_replaced": False}}
        replaced = {**timed, "link_recovery": {"response_gap_ms": 880, "socket_replaced": True}}
        recovery = summarize_mode([reused, None, replaced])["link_recovery"]
        self.assertEqual(recovery["response_gap_ms"], {"runs": 2, "min": 820, "median": 850, "max": 880})
        self.assertEqual(recovery["socket_reused_runs"], 1)
        self.assertEqual(recovery["socket_replaced_runs"], 1)

    def test_forced_transport_requires_matching_path(self):
        report = {"runs": [{"iterations": 10, "selected_paths": ["wss"]}]}
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "output"
            arguments = ["run.py", "--binary", sys.executable, "--output", str(result),
                         "--modes", "direct-udp", "--repeat", "1", "--require-progress",
                         "--hardware-notes", "Dedicated ARM64 lab host"]
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch("run.subprocess.run", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(report), "")),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(), 1)
            sample = json.loads((result / "01-direct-udp.json").read_text())
            self.assertIn("direct-udp was not selected", sample["exclusion_reason"])
            environment = json.loads((result / "environment.json").read_text())
            self.assertEqual(environment["hardware_notes"], "Dedicated ARM64 lab host")
            self.assertEqual(environment["parameters"]["modes"], ["direct-udp"])
            self.assertTrue(environment["parameters"]["require_progress"])

    def test_link_outage_requires_matching_recovery_observations(self):
        qdisc = '[{"kind":"netem","packets":30}]'
        stderr = f"ntwire netem upstream {qdisc}\nntwire netem downstream {qdisc}\n"
        recovered = {"requested_outage_ms": 750, "pre_outage_echo": True, "restored_echo": True,
                     "response_gap_ms": 820, "socket_replaced": False}
        run = {"iterations": 10, "selected_paths": ["direct-udp"], "end_reason": "duration",
               "echo_bps_per_direction": 100, "echo_bytes_per_direction": 10,
               "response_latency": {}, "connection_setup": {}, "process": {}, "link_recovery": recovered}
        wss = {**run, "selected_paths": ["wss"],
               "link_recovery": {**recovered, "response_gap_ms": 902, "socket_replaced": True}}
        samples = [run, wss, wss, {**run, "link_recovery": {**recovered, "requested_outage_ms": 500}}]
        outputs = [subprocess.CompletedProcess([], 0, json.dumps({"runs": [sample]}), stderr)
                   for sample in samples]
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "output"
            arguments = ["run.py", "--binary", sys.executable, "--output", str(result),
                         "--modes", "direct-udp", "wss", "--workload", "interactive", "--connections", "1",
                         "--duration", "5s", "--repeat", "2", "--link-outage-ms", "750",
                         "--peer-netem", "2", "0", "100", "42", "4", "0", "200", "43"]
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch("run.platform.system", return_value="Linux"),
                mock.patch("run.subprocess.run", side_effect=outputs),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(), 1)
            summary = json.loads((result / "summary.json").read_text())
            self.assertEqual(summary["failed_samples"], ["02-direct-udp"])
            recovery = summary["modes"]["direct-udp"]["link_recovery"]
            self.assertEqual(recovery["response_gap_ms"]["median"], 820)
            self.assertEqual(recovery["socket_reused_runs"], 1)
            delta = summary["comparisons"]["wss"]["link_recovery_gap_ms_delta"]
            self.assertEqual(delta["pairs"], 1)
            self.assertAlmostEqual(delta["median_pct"], 10)

    def test_backend_comparison_requires_evidence_from_matching_peers(self):
        def fixture(command, **_):
            self.assertIn("--queue-packets", command)
            self.assertIn("8192", command)
            self.assertIn("direct-udp", command)
            run = {
                "iterations": 10, "selected_paths": ["direct-udp"],
                "end_reason": "duration", "echo_bps_per_direction": 100,
                "response_latency": {}, "connection_setup": {},
                "process": {}, "echo_bytes_per_direction": 10,
                "host_cpu": {"busy_ticks": 40, "softirq_ticks": 3, "elapsed_us": 1000000,
                             "idle_baseline_busy_ticks": 10, "idle_baseline_elapsed_us": 1000000},
            }
            # Simulate a report showing the same backend in both samples.
            report = {"runs": [run], "backend": "userspace"}
            stats = '[{"kind":"netem","packets":30}]'
            stderr = f"ntwire netem upstream {stats}\nntwire netem downstream {stats}\n"
            return subprocess.CompletedProcess(command, 0, json.dumps(report), stderr)

        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "output"
            arguments = ["run.py", "--binary", sys.executable, "--output", str(result),
                         "--modes", "direct-udp", "--compare-server-backends", "--repeat", "1",
                         "--peer-netem", "60", "0", "200", "42", "60", "0", "200", "43",
                         "--peer-queue-packets", "8192"]
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch("run.platform.system", return_value="Linux"),
                mock.patch("run.platform.processor", return_value=""),
                mock.patch("run.subprocess.run", side_effect=fixture) as run_process,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(), 1)
            self.assertNotIn("--kernel-server", run_process.call_args_list[0].args[0])
            self.assertIn("--kernel-server", run_process.call_args_list[1].args[0])
            self.assertEqual(run_process.call_args_list[0].kwargs["env"]["NTWIRE_BENCH_HOST_CPU"], "1")
            sample = json.loads((result / "01-direct-udp-kernel-server.json").read_text())
            self.assertIn("does not confirm", sample["exclusion_reason"])

    def test_quic_admission_runs_three_distinct_modes(self):
        def fixture(command, **_):
            wait = next((flag for flag in command if flag.startswith("--quic-send-wait=")), None)
            run = {
                "iterations": 10, "selected_paths": ["quic-datagram"],
                "end_reason": "duration", "echo_bps_per_direction": 100,
                "response_latency": {}, "connection_setup": {},
                "process": {}, "echo_bytes_per_direction": 10,
                "client_quic": {"sent": 10, "received": 10, "send_queue_drops": 2},
            }
            if wait:
                run["quic_send_wait_us"] = 2000 if wait.endswith("2ms") else 0
            return subprocess.CompletedProcess(command, 0, json.dumps({"runs": [run]}), "")

        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "output"
            arguments = ["run.py", "--binary", sys.executable, "--output", str(result),
                         "--modes", "quic-datagram", "--compare-quic-admission",
                         "--repeat", "1", "--require-progress"]
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch("run.subprocess.run", side_effect=fixture) as run_process,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(main(), 0)
            commands = [call.args[0] for call in run_process.call_args_list if call.args[0][1:2] == ["benchmark"]]
            self.assertEqual(len(commands), 3)
            self.assertNotIn("--quic-send-wait=0", commands[0])
            self.assertIn("--quic-send-wait=0", commands[1])
            self.assertIn("--quic-send-wait=2ms", commands[2])
            summary = json.loads((result / "summary.json").read_text())
            wait = summary["comparisons"]["quic-wait-vs-batch"]
            self.assertEqual(wait["baseline"], "quic-batch")
            self.assertEqual(wait["quic_send_queue_drops_delta"]["pairs"], 1)
