package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	peerInterface = "bench0"
	peerServerIP  = "198.18.40.2"
	peerClientIP  = "198.18.40.1"
	peerTopology  = "linux-veth-two-peers"
)

func executePeer(ctx context.Context, o Options, relay RelayStarter, role, directory string) (Report, error) {
	report := newReport(peerTopology)
	if err := o.Validate(); err != nil {
		return report, err
	}
	if o.LinkOutage != 0 && (o.LinkOutage < 100*time.Millisecond || o.LinkOutage > 10*time.Second ||
		o.Duration < time.Second+o.LinkOutage+3*time.Second || o.Workload != "interactive" || o.Connections != 1) {
		return report, errors.New("link outage requires one interactive worker, 100ms to 10s outage and at least 4s beyond the outage duration")
	}
	if o.proxyWorkload() && (o.Transport == "direct" || nativeTransport(o.Transport)) {
		return report, errors.New("proxy workload requires an ntwire proxy listener")
	}
	ip := peerClientIP
	switch role {
	case "server":
		ip = peerServerIP
	case "client":
	default:
		return report, errors.New("invalid laboratory role")
	}
	if err := checkPeerFixture(ip, directory); err != nil {
		return report, err
	}
	f := &fixture{workload: o.Workload, network: "tcp", topology: peerTopology}
	defer f.close()
	if o.Transport != "direct" && o.SampleWSS {
		f.peerMeasurementsSocket = filepath.Join(directory, "measurements.sock")
	}
	if o.Workload == "udp" {
		f.network = "udp"
	}
	ready := filepath.Join(directory, "ready.json")
	if role == "server" {
		return report, f.servePeer(ctx, o, relay, directory, ready)
	}
	if o.Transport == "wss" && os.Getenv("NTWIRE_BENCH_WSS_TCP") == "1" {
		f.peerTCPDir = directory
	}
	state, err := loadPeerState(ready, o.Transport)
	if err != nil {
		return report, err
	}
	if o.Transport == "direct" {
		f.address = state.Target
	} else {
		expectedBackend := "userspace"
		if o.KernelServer {
			expectedBackend = "kernel"
		}
		if state.Backend != expectedBackend {
			return report, errors.New("fixture server did not start the requested WireGuard backend")
		}
		report.Backend = state.Backend
		if err := f.startClient(o, directory, state); err != nil {
			return report, err
		}
	}
	if o.LinkOutage != 0 {
		f.recovery = &linkRecovery{dir: directory, report: LinkRecovery{RequestedOutageMS: o.LinkOutage.Milliseconds()}}
	}
	run, files, err := measureFixture(ctx, o, f)
	if err == nil {
		report.Runs = []Run{run}
		report.ProfileFiles = files
	}
	return report, err
}

func checkPeerFixture(ip, dir string) error {
	if runtime.GOOS != "linux" {
		return errors.New("the peer laboratory requires Linux")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("the peer laboratory requires a private 0700 state directory")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Name != "lo" && iface.Name != peerInterface && iface.Name != "benchwg" {
			return errors.New("the peer laboratory must run inside its isolated topology")
		}
	}
	iface, err := net.InterfaceByName(peerInterface)
	if err != nil {
		return err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, addr := range addresses {
		if addr.String() == ip+"/30" {
			return nil
		}
	}
	return errors.New("fixture veth address does not match the peer role")
}

func (f *fixture) servePeer(ctx context.Context, o Options, relay RelayStarter, dir, ready string) error {
	// Bound the lifetime even if the launcher loses track of the process.
	ctx, cancel := context.WithTimeout(ctx, 7*time.Minute)
	defer cancel()
	targetHost := "127.0.0.1"
	if o.Transport == "direct" {
		targetHost = peerServerIP
	}
	if err := f.startTarget(ctx, o, targetHost); err != nil {
		return err
	}
	state := fixtureState{Target: f.target}
	if o.Transport != "direct" {
		var err error
		state, err = f.startServer(ctx, o, peerServerIP, dir, relay)
		if err != nil {
			return err
		}
	}
	if f.peerMeasurementsSocket != "" {
		stop, err := servePeerMeasurements(f.peerMeasurementsSocket, func() serverMeasurement { return f.serverMeasurement() })
		if err != nil {
			return fmt.Errorf("start peer measurement snapshots: %w", err)
		}
		defer stop()
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "peer-state-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), ready); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func loadPeerState(path, transport string) (fixtureState, error) {
	var state fixtureState
	info, err := os.Lstat(path)
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return state, errors.New("invalid fixture state file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("invalid fixture state: %w", err)
	}
	if transport == "direct" && fixtureAddress(state.Target, peerServerIP) {
		return state, nil
	}
	if fixtureAddress(state.Target, "127.0.0.1") {
		if nativeTransport(transport) {
			if fixtureAddress(state.WireEndpoint, peerServerIP) && fixtureAddress(state.WireTarget, nativeServerIP) {
				return state, nil
			}
		} else if transport != "direct" {
			control, err := url.Parse(state.Control)
			if err == nil && control.Scheme == "https" && control.User == nil &&
				control.Path == "" && control.RawQuery == "" && control.Fragment == "" && fixtureAddress(control.Host, peerServerIP) {
				return state, nil
			}
		}
	}
	return state, errors.New("fixture state contains an unexpected endpoint")
}

// LinkRecovery measures probe delivery across a fixture-only link outage.
// Response gaps use a single client clock. The link-restored marker is
// observed asynchronously, so this is an application interruption metric.
type LinkRecovery struct {
	RequestedOutageMS int64 `json:"requested_outage_ms"`
	PreOutageEcho     bool  `json:"pre_outage_echo"`
	RestoredEcho      bool  `json:"restored_echo"`
	ResponseGapMS     int64 `json:"response_gap_ms,omitempty"`
	SocketReplaced    bool  `json:"socket_replaced"`
}

type linkRecovery struct {
	dir          string
	measuring    bool
	last         time.Time
	previousDial int
	report       LinkRecovery
}

func (r *linkRecovery) begin() error {
	r.measuring = true
	return os.WriteFile(filepath.Join(r.dir, "measurement-start"), nil, 0600)
}

func (r *linkRecovery) observe(now time.Time, socketCount int) {
	if r.report.RestoredEcho {
		return
	}
	if _, err := os.Stat(filepath.Join(r.dir, "link-restored")); err == nil {
		r.report.RestoredEcho = true
		r.report.PreOutageEcho = !r.last.IsZero()
		if r.report.PreOutageEcho {
			r.report.ResponseGapMS = now.Sub(r.last).Milliseconds()
			r.report.SocketReplaced = socketCount != r.previousDial
		}
		return
	}
	r.last = now
	r.previousDial = socketCount
}

func fixtureAddress(address, host string) bool {
	endpoint, err := netip.ParseAddrPort(address)
	return err == nil && endpoint.Port() != 0 && endpoint.Addr().String() == host
}
