package benchmark

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.org/x/net/netutil"
)

type fixture struct {
	target, address, network, workload string
	topology                           string
	requiredPath                       string
	nativePath                         string
	nativeProof                        func() error
	nativeDial                         func(context.Context, string, string) (net.Conn, error)
	setup                              time.Duration
	client                             *client.Connection
	server                             *server.Server
	cleanup                            []func()
	recovery                           *linkRecovery
	peerMeasurementsSocket             string
	peerTCPDir                         string
}

func (f *fixture) close() {
	for i := len(f.cleanup) - 1; i >= 0; i-- {
		f.cleanup[i]()
	}
}

func newFixture(ctx context.Context, o Options, startRelay RelayStarter) (_ *fixture, err error) {
	f := &fixture{workload: o.Workload, network: "tcp", topology: "loopback"}
	defer func() {
		if err != nil {
			f.close()
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = f.startTarget(ctx, o, "127.0.0.1"); err != nil {
		return nil, err
	}
	if o.Transport == "direct" {
		f.address = f.target
		return f, nil
	}
	dir, e := os.MkdirTemp("", "ntwire-benchmark-")
	if e != nil {
		return nil, e
	}
	f.cleanup = append(f.cleanup, func() { _ = os.RemoveAll(dir) })
	state, err := f.startServer(ctx, o, "127.0.0.1", dir, startRelay)
	if err != nil {
		return nil, err
	}
	if err = f.startClient(o, dir, state); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fixture) startTarget(ctx context.Context, o Options, host string) error {
	// Keep the fixture hard-limited even if another local process discovers
	// the listener. Its only response is a same-size echo.
	fixtureCtx, cancel := context.WithCancel(ctx)
	f.cleanup = append(f.cleanup, cancel)
	targetLimit := &byteBudget{}
	targetLimit.remaining.Store(2*o.MaxBytes + bulkSize)
	if o.Workload == "udp" {
		f.network = "udp"
		pc, e := net.ListenPacket("udp4", net.JoinHostPort(host, "0"))
		if e != nil {
			return e
		}
		f.target = pc.LocalAddr().String()
		done := make(chan struct{})
		f.cleanup = append(f.cleanup, func() { _ = pc.Close(); <-done })
		go func() {
			defer close(done)
			packet := make([]byte, 129)
			for {
				n, addr, e := pc.ReadFrom(packet)
				if e != nil {
					return
				}
				if n == 128 && targetLimit.take(n) {
					_, _ = pc.WriteTo(packet[:n], addr)
				}
			}
		}()
	} else {
		listener, e := net.Listen("tcp4", net.JoinHostPort(host, "0"))
		if e != nil {
			return e
		}
		f.target = listener.Addr().String()
		echoCtx, stopEcho := context.WithCancel(fixtureCtx)
		done := make(chan struct{})
		f.cleanup = append(f.cleanup, func() { stopEcho(); _ = listener.Close(); <-done })
		go func() {
			defer close(done)
			serveTCP(echoCtx, listener, o.Connections+2, func(_ context.Context, conn net.Conn) {
				echo(conn, targetLimit)
			})
		}()
	}
	return nil
}

type fixtureState struct {
	Target, Control, WireEndpoint, WireServerKey, WireClientKey, WireTarget string
	Backend                                                                 string
}

func (f *fixture) startServer(ctx context.Context, o Options, host, dir string, startRelay RelayStarter) (fixtureState, error) {
	state := fixtureState{Target: f.target}
	key := filepath.Join(dir, "identity")
	if _, e := sshkey.GenerateIdentityFile(key); e != nil {
		return state, e
	}
	keys := filepath.Join(dir, "keys")
	if e := os.Mkdir(keys, 0700); e != nil {
		return state, e
	}
	pub, e := os.ReadFile(key + ".pub")
	if e != nil {
		return state, e
	}
	if e = os.WriteFile(filepath.Join(keys, "fixture.pub"), pub, 0600); e != nil {
		return state, e
	}

	// The production server accepts an explicit advertised UDP port. Reserve
	// it before setup, then release it so the production bind can open it.
	pc, e := net.ListenPacket("udp4", net.JoinHostPort(host, "0"))
	if e != nil {
		return state, e
	}
	wireAddress := pc.LocalAddr().String()
	defer pc.Close()
	var cfg server.Config
	cfg.Listen.WireGuard = wireAddress
	cfg.Acceleration.Mode = "off"
	state.Backend = "userspace"
	if o.KernelServer {
		cfg.Acceleration.Mode = "required"
		state.Backend = "kernel"
	}
	cfg.Auth.AuthorizedKeysDir = keys
	cfg.Auth.SessionTTL = time.Hour
	cfg.Network.TunnelCIDR = "100.70.0.0/24"
	cfg.Transport.SampleWSS = o.SampleWSS
	cfg.Transport.Adaptive = o.Transport == "adaptive-wss" || o.Transport == "quic-datagram" || o.Transport == "adaptive-auto"
	cfg.Transport.AdaptiveTunnelMTU = o.AdaptiveMTU
	cfg.Transport.QUICSendWait = o.QUICSendWait
	if o.Transport == "quic-datagram" || o.Transport == "adaptive-auto" {
		quicSocket, err := net.ListenPacket("udp4", net.JoinHostPort(host, "0"))
		if err != nil {
			return state, err
		}
		cfg.Transport.QUICListen = quicSocket.LocalAddr().String()
		_ = quicSocket.Close()
		if cfg.Transport.AdaptiveTunnelMTU == 0 {
			cfg.Transport.AdaptiveTunnelMTU = wstransport.MinTunnelMTU
		}
	}
	mp := o.Transport == "multipath" || o.Transport == "udp-relay" || o.Transport == "alternate-udp"
	cfg.Transport.Multipath = &mp
	if o.Transport != "wss" && o.Transport != "udp-relay" {
		cfg.Network.AdvertisedEndpoint = wireAddress
	}
	if o.Transport == "alternate-udp" {
		// Hold the advertised primary port open without a responder. The
		// unadvertised primary listener serves no client traffic. Only the
		// advertised alternate can validate a direct candidate.
		blocked, err := net.ListenPacket("udp4", net.JoinHostPort(host, "0"))
		if err != nil {
			return state, err
		}
		f.cleanup = append(f.cleanup, func() { _ = blocked.Close() })
		alternate, err := net.ListenPacket("udp4", net.JoinHostPort(host, "0"))
		if err != nil {
			return state, err
		}
		cfg.Listen.WireGuardAlt = alternate.LocalAddr().String()
		_ = alternate.Close()
		cfg.Network.AdvertisedEndpoint = blocked.LocalAddr().String()
		cfg.Transport.Promotion = true
	}
	if o.Transport == "udp-relay" {
		cfg.Relay.Enabled = true
		cfg.Transport.Force = "udp-relay"
		if f.topology == "loopback" {
			f.topology = "loopback-real-udp-relay-direct-control"
		}
	}
	grant := server.TunnelConfig{Name: "benchmark", Target: f.target, Protocol: f.network, VirtualPort: 18080, Allow: []string{"*"}, UDPIdleTimeout: 2 * time.Second}
	if o.proxyWorkload() {
		upstream, err := f.startProxy(ctx, o.Connections+2)
		if err != nil {
			return state, err
		}
		grant.Target = "socks"
		grant.Socks = &server.SocksConfig{Transparent: true, Upstream: "socks5h://" + upstream}
	}
	cfg.Tunnels = []server.TunnelConfig{grant}
	_ = pc.Close()
	if nativeTransport(o.Transport) {
		if e = f.startNativeServer(cfg, dir, wireAddress, grant.VirtualPort, &state); e != nil {
			return state, e
		}
		return state, e
	}
	log := slog.New(slog.DiscardHandler)
	f.server = server.New(cfg, log)
	tlsManager, e := server.NewTLSManager(cfg)
	if e != nil {
		return state, e
	}
	f.server.SetTLSManager(tlsManager)
	if e = f.server.StartDataPlane(); e != nil {
		return state, e
	}
	f.cleanup = append(f.cleanup, f.server.Close)
	if o.Transport == "udp-relay" {
		if startRelay == nil {
			return state, errors.New("UDP relay requires the laboratory command")
		}
		relay, err := startRelay(ctx, f.server, dir, o)
		if err != nil {
			return state, err
		}
		f.cleanup = append(f.cleanup, relay.Close)
	}
	tlsConfig := tlsManager.Config()
	cert, e := tlsConfig.GetCertificate(nil)
	if e != nil {
		return state, e
	}
	tlsConfig.Certificates = []tls.Certificate{*cert}
	tlsConfig.GetCertificate = nil
	listener, e := net.Listen("tcp4", net.JoinHostPort(host, "0"))
	if e != nil {
		return state, e
	}
	control := &httptest.Server{
		Listener: netutil.LimitListener(listener, 32),
		Config: &http.Server{
			Handler:           f.server.Handler(),
			ReadHeaderTimeout: ioTimeout,
			MaxHeaderBytes:    8 << 10,
		},
		TLS: tlsConfig,
	}
	control.StartTLS()
	f.cleanup = append(f.cleanup, control.Close)
	known := filepath.Join(dir, "known_servers.yaml")
	if e = client.TrustServer(known, strings.TrimPrefix(control.URL, "https://"), tlsManager.Fingerprint()); e != nil {
		return state, e
	}
	state.Control = control.URL
	return state, e
}

func (f *fixture) startClient(o Options, dir string, state fixtureState) error {
	f.target = state.Target
	if nativeTransport(o.Transport) {
		return f.startNativeClient(o, state)
	}
	if o.Transport == "udp-relay" {
		f.requiredPath = "udp-relay"
	}
	options := client.Options{NoWebUI: true, NoBrowser: true, NoSystemProxy: true, StatusFile: filepath.Join(dir, "status.json"),
		IPVersion: "4", Ports: map[string]int{"benchmark": 0}, Logger: slog.New(slog.DiscardHandler), SampleWSS: o.SampleWSS, KnownServersFile: filepath.Join(dir, "known_servers.yaml")}
	if o.Transport == "adaptive-wss" || o.Transport == "quic-datagram" || o.Transport == "adaptive-auto" {
		options.AdaptiveCarrier = true
		options.AdaptiveQUICDiagnostic = o.Transport == "quic-datagram"
		options.QUICSendWait = o.QUICSendWait
		if o.Transport != "adaptive-auto" {
			f.requiredPath = o.Transport
		}
	}
	if o.Transport == "wss" || o.Transport == "direct-udp" {
		options.Transport = o.Transport
	}
	if o.Transport == "udp-relay" {
		options.Transport = o.Transport
		options.DirectUpgradeTiming = &client.DirectUpgradeTiming{RetryInterval: time.Second, ProbeTimeout: 8 * time.Second}
	}
	if o.Transport == "alternate-udp" {
		f.requiredPath = o.Transport
		options.UDPAlt = true
		options.Promote = true
	}
	start := time.Now()
	peer, err := client.ConnectWithOptions(state.Control, filepath.Join(dir, "identity"), protocol.ClientInfo{}, options)
	f.setup = time.Since(start)
	if err != nil {
		return err
	}
	f.client = peer
	f.cleanup = append(f.cleanup, f.client.Close)
	connected := f.client.State()
	if len(connected.Tunnels) != 1 || connected.Tunnels[0].Name != "benchmark" {
		return errors.New("unexpected fixture grant")
	}
	f.address = connected.Tunnels[0].LocalAddress
	return nil
}

// The fixture's transparent SOCKS upstream can reach exactly its disposable
// echo address. It never uses the machine resolver or proxies another target.
func (f *fixture) startProxy(ctx context.Context, maximum int) (string, error) {
	target, err := netip.ParseAddrPort(f.target)
	if err != nil {
		return "", err
	}
	proxy, err := socks.New(socks.Config{
		Filter: socks.FilterConfig{AllowLocalEgress: true, CIDRs: []string{"127.0.0.1/32"}},
		Authorize: func(_ context.Context, host string, ip netip.Addr, port uint16, protocol string) bool {
			return (host == "" || host == target.Addr().String()) && netip.AddrPortFrom(ip, port) == target && protocol == "tcp"
		},
		Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("benchmark fixture does not resolve external names")
		}},
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return "", err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	proxyCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveTCP(proxyCtx, listener, maximum, proxy.ServeConn)
	}()
	f.cleanup = append(f.cleanup, func() {
		stop()
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String(), nil
}

func serveTCP(ctx context.Context, listener net.Listener, maximum int, handle func(context.Context, net.Conn)) {
	var workers sync.WaitGroup
	defer workers.Wait()
	slots := make(chan struct{}, maximum)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		workers.Go(func() {
			defer func() { <-slots }()
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			handle(ctx, conn)
		})
	}
}

func echo(conn net.Conn, budget *byteBudget) {
	buf := make([]byte, bulkSize)
	for {
		_ = conn.SetDeadline(time.Now().Add(3 * ioTimeout))
		n, err := conn.Read(buf)
		if n > 0 {
			if !budget.take(n) {
				return
			}
			if written, err := conn.Write(buf[:n]); err != nil || written != n {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (f *fixture) dial(ctx context.Context, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if f.nativeDial != nil {
		return f.nativeDial(ctx, f.network, f.address)
	}
	socket, err := (&net.Dialer{}).DialContext(ctx, f.network, f.address)
	if err != nil || f.client == nil {
		return socket, err
	}
	switch f.workload {
	case "socks5":
		err = socks.Connect(ctx, socket, f.target)
	case "http-connect":
		err = connectHTTP(ctx, socket, f.target)
	}
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	return socket, nil
}

func connectHTTP(ctx context.Context, socket net.Conn, target string) error {
	deadline, _ := ctx.Deadline()
	_ = socket.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	if _, err := fmt.Fprintf(socket, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return err
	}
	reader := bufio.NewReader(io.LimitReader(socket, 8<<10))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || reader.Buffered() != 0 {
		return errors.New("unexpected fixture CONNECT response")
	}
	return nil
}

func (f *fixture) ready(ctx context.Context) error {
	// The first echo can include a WireGuard handshake and relay promotion.
	// Give that setup its own budget so it does not change workload timeouts.
	const readinessIOTimeout = 8 * time.Second
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	payload, reply := make([]byte, 128), make([]byte, 128)
	var lastErr error
	var timing totals
	for ctx.Err() == nil {
		var initialPath string
		var initialRelay protocol.ClientUDPRelayStats
		if f.requiredPath != "" {
			initialPath = f.activePath()
			if f.requiredPath == "udp-relay" {
				initialRelay = f.client.UDPRelayTraffic()
			}
		}
		socket, err := f.dial(ctx, readinessIOTimeout)
		if err == nil {
			err = exchange(ctx, socket, payload, reply, readinessIOTimeout)
			_ = socket.Close()
		}
		if err == nil {
			if f.requiredPath == "" {
				if f.nativeProof != nil {
					return f.nativeProof()
				}
				return nil
			}
			path := f.activePath()
			if initialPath == f.requiredPath && path == f.requiredPath {
				if f.requiredPath != "udp-relay" {
					return nil
				}
				traffic := f.client.UDPRelayTraffic()
				if traffic.PacketsSent > initialRelay.PacketsSent && traffic.PacketsReceived > initialRelay.PacketsReceived {
					return nil
				}
				err = errors.New("no bidirectional WireGuard ciphertext observed on the selected UDP relay")
			} else {
				err = fmt.Errorf("carrier %s did not remain selected during the echo (%s to %s)", f.requiredPath, initialPath, path)
			}
		}
		lastErr = err
		timing.waitNext(ctx, time.Now())
	}
	return fmt.Errorf("selected path %s: %w", f.activePath(), errors.Join(ctx.Err(), lastErr))
}

func (f *fixture) activePath() string {
	if f.nativeDial != nil {
		return f.nativePath
	}
	if f.client == nil {
		return "direct"
	}
	info := f.client.TransportInfo()
	switch info.Active {
	case "UDP direct", "direct-udp":
		if f.requiredPath == "alternate-udp" {
			return f.requiredPath
		}
		return "direct-udp"
	case "WSS", "WSS fallback", "wss":
		if info.AdaptiveCarrier {
			return "adaptive-wss"
		}
		return "wss"
	}
	return info.Active
}

func (f *fixture) measurementSnapshots(ctx context.Context) (clientQueue wssSnapshot, measuredServer serverMeasurement, err error) {
	if f.client != nil {
		clientQueue = wssSnapshot{Performance: f.client.WSSPerformance()}
	}
	if f.server != nil {
		measuredServer = f.serverMeasurement()
	} else if f.peerMeasurementsSocket != "" {
		measuredServer, err = readPeerMeasurement(ctx, f.peerMeasurementsSocket)
	}
	return clientQueue, measuredServer, err
}

func (f *fixture) serverMeasurement() serverMeasurement {
	m := serverMeasurement{WSS: wssSnapshot{Performance: f.server.WSSPerformance()}}
	return m
}
