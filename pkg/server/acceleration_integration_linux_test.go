//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/vishvananda/netlink"
)

func TestKernelAcceleration_HybridPeerIsolation(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_KERNEL") != "1" {
		t.Skip("requires a privileged Linux worker")
	}
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	s, identity, _ := newTestServer(t, []TunnelConfig{
		{Name: "echo", VirtualPort: 18080, Target: target.Addr().String(), Allow: []string{"*"}},
		{Name: "denied", VirtualPort: 18081, Target: target.Addr().String(), Allow: []string{"other-user"}},
	})
	s.Config.Network.TunnelCIDR = "100.73.0.0/24"
	s.Config.Listen.WireGuard = "127.0.0.1:0"
	s.Config.Transport.Adaptive = true
	s.Config.TLS.Ephemeral = true
	s.Config.Acceleration.AllowAuto = true
	manager, err := NewTLSManager(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	s.SetTLSManager(manager)
	if err := s.StartDataPlane(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := httptest.NewUnstartedServer(s.Handler())
	h.TLS = manager.Config()
	pair, err := h.TLS.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.TLS.Certificates = []tls.Certificate{*pair}
	h.StartTLS()
	defer h.Close()
	ca := filepath.Join(t.TempDir(), "server.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	var metrics bytes.Buffer
	s.writeAccelerationMetrics(&metrics)
	if !strings.Contains(metrics.String(), `backend="kernel"`) ||
		!strings.Contains(metrics.String(), `ntwire_acceleration_plane_info{plane="adaptive",backend="userspace"} 1`) {
		t.Fatalf("incorrect hybrid backend diagnostics: %s", &metrics)
	}
	for _, adaptive := range []bool{false, true} {
		connected, err := client.ConnectWithOptions(h.URL, identity, protocol.ClientInfo{}, client.Options{
			CAFile: ca, AdaptiveCarrier: adaptive, UseWebSocket: !adaptive, NoWebUI: true,
			NoSystemProxy: true, NoBrowser: true, IPVersion: "4",
			StatusFile: filepath.Join(t.TempDir(), "status.json"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer connected.Close()
		if connected.TransportInfo().AdaptiveCarrier != adaptive {
			t.Fatal("wrong carrier mode negotiated")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		conn, err := connected.Stack.DialContext(ctx, "tcp", "100.73.0.1:18080")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("hybrid")); err != nil {
			t.Fatal(err)
		}
		var reply [6]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "hybrid" {
			t.Fatalf("adaptive=%t: got %q, %v", adaptive, reply, err)
		}
		denied, err := connected.Stack.DialContext(ctx, "tcp", "100.73.0.1:18081")
		if err == nil {
			defer denied.Close()
			_ = denied.SetDeadline(time.Now().Add(time.Second))
			_, _ = denied.Write([]byte("denied"))
			if _, err := io.ReadFull(denied, reply[:]); err == nil {
				t.Fatalf("adaptive=%t: ungranted target returned %q", adaptive, reply)
			}
		}
	}
	legacy, err := s.data.stack.LastHandshakes()
	if err != nil || len(legacy) != 1 {
		t.Fatalf("legacy peers: %v, %v", legacy, err)
	}
	adaptive, err := s.adaptive.data.stack.LastHandshakes()
	if err != nil || len(adaptive) != 1 {
		t.Fatalf("adaptive peers: %v, %v", adaptive, err)
	}
	for key, last := range adaptive {
		if _, crossed := legacy[key]; crossed || last.IsZero() {
			t.Fatal("adaptive peer crossed the backend boundary or did not handshake")
		}
	}
}

func TestKernelAcceleration_CrashReleasesPublicBind(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_KERNEL") != "1" {
		t.Skip("requires a privileged Linux worker")
	}
	newServer := func(addr, directory string) *Server {
		config := Config{Acceleration: AccelerationConfig{Mode: "required"}}
		config.Network.TunnelCIDR = "100.64.0.0/24"
		config.Network.WireGuardPrivateKeyFile = filepath.Join(directory, "wireguard.key")
		config.Listen.WireGuard = addr
		return New(config, nil)
	}
	if directory := os.Getenv("NTWIRE_TEST_KERNEL_CRASH_DIR"); directory != "" {
		s := newServer("127.0.0.1:0", directory)
		if err := s.StartDataPlane(); err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		port := s.data.stack.(*kernelStack).bridge.boundPort
		if err := os.WriteFile(filepath.Join(directory, "ready"), []byte(strconv.Itoa(int(port))), 0600); err != nil {
			t.Fatal(err)
		}
		timer := time.NewTimer(15 * time.Second)
		defer timer.Stop()
		<-timer.C
		t.Fatal("parent did not terminate the fixture")
	}
	directory := t.TempDir()
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "wireguard.key"), []byte(key.Private), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestKernelAcceleration_CrashReleasesPublicBind$")
	cmd.Env = append(os.Environ(), "NTWIRE_TEST_KERNEL_CRASH_DIR="+directory)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	var port []byte
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		port, err = os.ReadFile(filepath.Join(directory, "ready"))
		if err == nil && len(port) != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := strconv.ParseUint(string(port), 10, 16); err != nil {
		t.Fatalf("kernel child did not report a bound public port: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := cmd.Wait(); !errors.As(err, &exit) || exit.Exited() {
		t.Fatalf("kernel child did not stop on process kill: %v", err)
	}
	s := newServer(net.JoinHostPort("127.0.0.1", string(port)), directory)
	if err := s.StartDataPlane(); err != nil {
		t.Fatalf("could not reopen backend after process crash: %v", err)
	}
	defer s.Close()
	if backend := s.data.stack.(*kernelStack); backend.PublicKey() != key.Public || backend.bridge.boundPort == 0 {
		t.Fatal("restarted backend did not retain its configured WireGuard identity and public listener")
	}
}

func TestKernelAcceleration_IsolationAndLifecycle(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_KERNEL") != "1" {
		t.Skip("set NTWIRE_TEST_KERNEL=1 on a Linux kernel with WireGuard, namespaces and nftables")
	}
	for _, network := range []struct {
		cidr, serverIP, peerIP string
	}{{"100.64.0.0/24", "100.64.0.1", "100.64.0.2"}, {"fd25:abcd::/64", "fd25:abcd::1", "fd25:abcd::2"}} {
		t.Run(network.cidr, func(t *testing.T) {
			s := New(Config{Acceleration: AccelerationConfig{Mode: "required", EBPF: true}}, nil)
			s.Config.Network.TunnelCIDR = network.cidr
			s.Config.Listen.WireGuard = "127.0.0.1:0"
			if err := s.StartDataPlane(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			k := s.data.stack.(*kernelStack)
			if _, err := netlink.LinkByName(kernelInterface); err == nil {
				t.Fatal("private WireGuard interface visible in the original namespace")
			}
			// Ensure peer listeners and accepted sockets come from the private
			// namespace, then leave both open for the shutdown assertion below.
			ln, err := k.Listen("tcp", net.JoinHostPort(network.serverIP, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var raw net.Listener
			if err := k.ns.call(func() error {
				var err error
				raw, err = net.Listen("tcp", net.JoinHostPort(network.serverIP, "0"))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			accept := make(chan net.Conn, 1)
			go func() {
				serverConn, err := ln.Accept()
				if err == nil {
					accept <- serverConn
				}
			}()
			client, err := wgnet.New(wgnet.Config{Addresses: []netip.Addr{netip.MustParseAddr(network.peerIP)}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			hostBits := netip.MustParseAddr(network.peerIP).BitLen()
			if err := k.AddPeer(wgnet.Endpoint{PublicKey: client.PublicKey(), Address: fmt.Sprintf("%s/%d", network.peerIP, hostBits)}); err != nil {
				t.Fatal(err)
			}
			if err := client.AddPeer(wgnet.Endpoint{PublicKey: k.PublicKey(), Address: fmt.Sprintf("%s@127.0.0.1:%d", network.cidr, k.bridge.boundPort)}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var accepted net.Conn
			select {
			case accepted = <-accept:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer accepted.Close()
			if ip, _, _ := net.SplitHostPort(accepted.RemoteAddr().String()); ip != network.peerIP {
				t.Fatalf("peer source = %s", ip)
			}
			denied, cancelDenied := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancelDenied()
			if conn, err := client.DialContext(denied, "tcp", raw.Addr().String()); err == nil {
				conn.Close()
				t.Fatal("client dial reached an unregistered socket")
			}
			var metrics bytes.Buffer
			s.writeAccelerationMetrics(&metrics)
			for _, name := range []string{"backend=\"kernel\"", "ntwire_acceleration_bridge_mappings"} {
				if !bytes.Contains(metrics.Bytes(), []byte(name)) {
					t.Fatalf("missing %q in metrics:\n%s", name, &metrics)
				}
			}
			const nftDropMetric = "ntwire_acceleration_nftables_dropped_packets_total "
			_, line, _ := strings.Cut(metrics.String(), nftDropMetric)
			value, _, _ := strings.Cut(line, "\n")
			if dropped, _ := strconv.Atoi(value); dropped < 1 {
				t.Fatalf("missing nftables drop: %s", &metrics)
			}
			if k.ebpfMode == "attached" {
				for _, direction := range []string{"ingress", "egress"} {
					prefix := fmt.Sprintf("ntwire_acceleration_ebpf_packets_total{direction=%q,size_bucket=\"0-127\"} ", direction)
					_, line, _ := strings.Cut(metrics.String(), prefix)
					value, _, _ := strings.Cut(line, "\n")
					if packets, _ := strconv.Atoi(value); packets < 1 {
						t.Fatalf("missing %s eBPF packets: %s", direction, &metrics)
					}
				}
			} else if os.Getenv("NTWIRE_TEST_EBPF") == "1" {
				t.Fatalf("eBPF did not attach: %s", &metrics)
			}
			s.Close()
			if err := k.Close(); err != nil {
				t.Fatalf("closing an already stopped backend: %v", err)
			}
			if _, err := accepted.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("accepted socket survived Close: %v", err)
			}
		})
	}
}

func TestKernelAcceleration_RestrictedStartup(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_RESTRICTED") != "1" {
		t.Skip("set NTWIRE_TEST_RESTRICTED=1 in a Linux container without SYS_ADMIN")
	}
	for _, mode := range []string{"required", "off", "auto"} {
		t.Run(mode, func(t *testing.T) {
			s := New(Config{Acceleration: AccelerationConfig{Mode: mode, AllowAuto: true}}, nil)
			s.Config.Network.TunnelCIDR = "100.64.0.0/24"
			s.Config.Listen.WireGuard = "127.0.0.1:0"
			err := s.StartDataPlane()
			defer s.Close()
			if mode == "required" {
				if err == nil || !strings.Contains(err.Error(), "create private network namespace") || s.data != nil {
					t.Fatalf("required startup should fail cleanly: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			status := s.acceleration.Load()
			reason := map[string]string{"off": "disabled", "auto": "kernel_setup_failed"}[mode]
			if status.backend != "userspace" || status.reason != reason {
				t.Fatalf("unexpected startup status: %+v", status)
			}
		})
	}
}

func TestKernelAcceleration_BindFailureRollsBack(t *testing.T) {
	if os.Getenv("NTWIRE_TEST_KERNEL") != "1" {
		t.Skip("set NTWIRE_TEST_KERNEL=1 on a privileged Linux test worker")
	}
	processSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer processSocket.Close()
	config := Config{Acceleration: AccelerationConfig{Mode: "required"}}
	config.Network.TunnelCIDR = "100.64.0.0/24"
	config.Listen.WireGuard = processSocket.LocalAddr().String()
	s := New(config, nil)
	err = s.StartDataPlane()
	if err == nil || !strings.Contains(err.Error(), "open public WireGuard transport") || errors.Is(err, errAccelerationCleanup) || s.data != nil {
		t.Fatalf("expected a clean rollback after the public port conflict, got %v", err)
	}
	if err := processSocket.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.StartDataPlane(); err != nil {
		t.Fatalf("next attempt after rollback: %v", err)
	}
	defer s.Close()
	config.Listen.WireGuard = "127.0.0.1:0"
	other := New(config, nil)
	if err := other.StartDataPlane(); err != nil {
		t.Fatalf("second kernel instance with the same tunnel network: %v", err)
	}
	defer other.Close()
	config.Acceleration.Mode = "off"
	portable := New(config, nil)
	if err := portable.StartDataPlane(); err != nil {
		t.Fatal(err)
	}
	defer portable.Close()
	if portable.acceleration.Load().backend != "userspace" {
		t.Fatal("off did not select the userspace backend on privileged Linux")
	}
}
