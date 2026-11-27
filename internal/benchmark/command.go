package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/ui"
)

// Command implements the same benchmark flags for the installed client and
// the repository-only laboratory binary.
func Command(args []string, u *ui.UI, startRelay RelayStarter) error {
	return command(args, u, startRelay, "", "")
}

func PeerCommand(args []string, u *ui.UI, startRelay RelayStarter, role, directory string) error {
	return command(args, u, startRelay, role, directory)
}

func command(args []string, u *ui.UI, startRelay RelayStarter, role, directory string) error {
	var options Options
	transports := []string{"direct", "direct-udp", "wss", "multipath"}
	if startRelay != nil {
		transports = append(transports, "native-wireguard-go", "udp-relay", "alternate-udp", "adaptive-wss", "quic-datagram", "adaptive-auto")
	}
	if role != "" {
		transports = append(transports, "native-wireguard-kernel")
	}
	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	fs.SetOutput(u.Err)
	fixture := fs.String("fixture", "loopback", "disposable benchmark fixture (loopback)")
	fs.StringVar(&options.Transport, "transport", "direct-udp", strings.Join(transports, ", "))
	fs.StringVar(&options.Workload, "workload", "interactive", "interactive, bulk, mixed, setup, udp, socks5, or http-connect")
	fs.IntVar(&options.Connections, "connections", 1, "parallel benchmark workers")
	fs.DurationVar(&options.Duration, "duration", 10*time.Second, "measured duration (100ms to 5m)")
	fs.DurationVar(&options.Warmup, "warmup", 2*time.Second, "warm-up duration (0 to 1m)")
	fs.Int64Var(&options.MaxBytes, "max-bytes", 4<<30, "maximum echo bytes per direction per interval")
	fs.IntVar(&options.BulkRateMbps, "bulk-rate-mbps", 0, "limit bulk writes to this many Mbit/s per worker (zero is unlimited)")
	fs.BoolVar(&options.SampleWSS, "sample-wss", false, "sample WSS queue depth and residence")
	var quicSendWait time.Duration
	if startRelay != nil {
		fs.IntVar(&options.AdaptiveMTU, "adaptive-mtu", 0, "fixed tunnel MTU for an adaptive fixture")
		fs.DurationVar(&quicSendWait, "quic-send-wait", 0, "experiment with QUIC batch admission and an optional wait (0 to 5ms)")
	}
	fs.StringVar(&options.Profiles, "profiles", "", "new directory for private CPU, heap, allocation and goroutine profiles")
	if role != "" {
		fs.DurationVar(&options.LinkOutage, "link-outage", 0, "duration of a scheduled fixture link outage")
		fs.BoolVar(&options.KernelServer, "kernel-server", false, "require the isolated Linux kernel WireGuard server backend")
	}
	compare := fs.Bool("compare-transports", false, "run all applicable local transports")
	jsonOutput := fs.Bool("json", false, "emit machine-readable JSON")
	fs.Bool("no-color", false, "disable ANSI colors")
	fs.Usage = func() {
		ui.Spec{
			Tool: "ntwire benchmark", Tagline: "measure an isolated ntwire fixture",
			Flags:    ui.FlagsOf(fs),
			Examples: []string{"ntwire benchmark --compare-transports --workload mixed --connections 10 --duration 30s --json"},
		}.Fprint(u.Err, u)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *fixture != "loopback" || fs.NArg() != 0 {
		return errors.New("benchmark accepts only the built-in loopback fixture and no target addresses")
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "quic-send-wait" {
			options.QUICSendWait = &quicSendWait
		}
	})
	if *compare && options.QUICSendWait != nil {
		return errors.New("--quic-send-wait requires one explicit QUIC transport")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if role != "" {
		if *compare {
			return errors.New("the peer laboratory runs one transport per invocation")
		}
		report, err := executePeer(ctx, options, startRelay, role, directory)
		if err != nil || role == "server" {
			return err
		}
		return json.NewEncoder(u.Out).Encode(report)
	}
	modes := []Options{options}
	if *compare {
		explicitTransport := false
		fs.Visit(func(f *flag.Flag) { explicitTransport = explicitTransport || f.Name == "transport" })
		if explicitTransport {
			return errors.New("--compare-transports conflicts with --transport")
		}
		modes = nil
		for _, transport := range transports {
			if transport == "quic-datagram" || transport == "adaptive-auto" {
				continue // The pilot requires explicit selection in the lab.
			}
			if (transport == "direct" || transport == "native-wireguard-go") && options.proxyWorkload() {
				continue
			}
			options.Transport = transport
			modes = append(modes, options)
		}
	}
	report, err := execute(ctx, modes, startRelay != nil, startRelay)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(u.Out).Encode(report)
	}
	for _, run := range report.Runs {
		fmt.Fprintf(u.Out, "%s %s (%v)  %.2f Mbps per direction  %d completed  %d failed  %d aborted  %s\n",
			run.Transport, run.Workload, run.SelectedPaths, run.BitsPerSecond/1e6, run.Iterations, run.Failures, run.Aborted, run.EndReason)
		if run.Latency.Count > 0 {
			fmt.Fprintf(u.Out, "  Response p50 %d µs, p95 %d µs, p99 %d µs\n", run.Latency.P50US, run.Latency.P95US, run.Latency.P99US)
		}
	}
	return nil
}
