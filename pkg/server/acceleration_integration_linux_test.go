//go:build linux

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/vishvananda/netlink"
)

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
			s := New(Config{Acceleration: AccelerationConfig{Mode: mode}}, nil)
			s.Config.Network.TunnelCIDR = "100.64.0.0/24"
			s.Config.Listen.WireGuard = "127.0.0.1:0"
			err := s.startSelectedDataPlane(true)
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
