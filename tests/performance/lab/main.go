// Command lab starts a disposable fixture for repository performance testing.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/nmaguiar/ntwire/internal/benchmark"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func main() {
	u := ui.New(os.Stdout, os.Stderr, true)
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "benchmark":
		err = benchmark.Command(os.Args[2:], u, startRelay)
	case len(os.Args) >= 3 && (os.Args[1] == "peer-server" || os.Args[1] == "peer-client"):
		err = benchmark.PeerCommand(os.Args[3:], u, startPeerRelay, os.Args[1][5:], os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "usage: ntwire-bench-lab benchmark [flags]")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startPeerRelay(ctx context.Context, s *server.Server, dir string, o benchmark.Options) (benchmark.RelayFixture, error) {
	return startRelayOn(ctx, s, dir, "198.18.40.2", o)
}

func startRelay(ctx context.Context, s *server.Server, dir string, o benchmark.Options) (benchmark.RelayFixture, error) {
	return startRelayOn(ctx, s, dir, "127.0.0.1", o)
}

func startRelayOn(ctx context.Context, s *server.Server, dir, host string, o benchmark.Options) (fixture benchmark.RelayFixture, err error) {
	key := filepath.Join(dir, "relay-id")
	if _, e := sshkey.GenerateIdentityFile(key); e != nil {
		return fixture, e
	}
	public, e := os.ReadFile(key + ".pub")
	if e != nil {
		return fixture, e
	}
	reservation, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host)})
	if e != nil {
		return fixture, e
	}
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	_ = reservation.Close()

	cfg := relay.Config{Domain: "ntwire.test", Registrations: []relay.RegistrationConfig{{Name: "benchmark", PublicKey: string(public)}}}
	cfg.Listen.Public = "127.0.0.1:0"
	cfg.Listen.Agents = "127.0.0.1:0"
	cfg.Listen.UDPRelay = net.JoinHostPort(host, "0")
	cfg.Listen.UDPRelayPorts = fmt.Sprintf("%d-%d", port, port)
	cfg.TLS.Ephemeral = true
	cfg.Limits.HandshakeTimeout = 5 * time.Second
	// This in-process config bypasses the YAML loader's defaults. Allocation
	// replies use DialBackTimeout as their WebSocket write deadline.
	cfg.Limits.DialBackTimeout = 3 * time.Second
	cfg.Limits.MaxPendingPerServer = 8
	cfg.Limits.MaxConnsPerServer = 16
	cfg.Limits.MaxUDPRelaySessionsPerServer = 1
	cfg.Limits.UDPRelayIdleTimeout = time.Minute
	logger := slog.New(slog.DiscardHandler)
	r, e := relay.New(cfg, logger)
	if e != nil {
		return fixture, e
	}
	if e = r.Start(); e != nil {
		return fixture, e
	}
	cleanup := func() { _ = r.Close() }
	defer func() {
		if err != nil {
			cleanup()
		}
	}()
	agent, e := server.NewRelayAgent(server.RelayConfig{
		Enabled: true, Name: "benchmark", URL: "wss://" + r.AgentsAddr().String(),
		IdentityFile: key, Fingerprint: r.Fingerprint(),
		ReconnectMin: 250 * time.Millisecond, ReconnectMax: 2 * time.Second,
	}, logger)
	if e != nil {
		return fixture, e
	}
	registered := make(chan protocol.RelayRegisterResponse, 1)
	agent.OnRegistration = func(response protocol.RelayRegisterResponse) {
		select {
		case registered <- response:
		default:
		}
	}
	agent.OnUDPStats = func(report protocol.RelayUDPStatsReport) { s.RecordUDPRelayStatsFrom(agent, report) }
	agentContext, cancelAgent := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		agent.Run(agentContext)
	}()
	cleanup = func() {
		cancelAgent()
		<-done
		_ = agent.Close()
		_ = r.Close()
	}
	wait, cancelWait := context.WithTimeout(ctx, 10*time.Second)
	defer cancelWait()
	select {
	case response := <-registered:
		if response.UDPRelayAddr == "" || response.UDPRelayAddr != r.UDPRelayAddr() {
			return fixture, errors.New("registration did not provide the fixture UDP relay address")
		}
		s.EnableUDPRelay(agent, response.UDPRelayAddr)
	case <-wait.Done():
		return fixture, fmt.Errorf("register fixture relay: %w", wait.Err())
	}
	fixture.Close = cleanup
	return fixture, nil
}
