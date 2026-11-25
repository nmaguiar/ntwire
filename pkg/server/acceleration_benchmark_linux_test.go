//go:build linux

package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// Run with NTWIRE_TEST_KERNEL=1 on an isolated Linux worker. A single echo
// round trip accounts for both directions and keeps the workload comparable.
func BenchmarkAccelerationTunnel(b *testing.B) {
	for _, mode := range []string{"off", "required"} {
		if mode == "required" && os.Getenv("NTWIRE_TEST_KERNEL") != "1" {
			continue
		}
		for _, transport := range []string{"direct", "udp-relay", "wss"} {
			for _, size := range []int{256, 1 << 20} {
				b.Run(fmt.Sprintf("%s/%s/%d", mode, transport, size), func(b *testing.B) {
					benchmarkAccelerationTunnel(b, mode, transport, size)
				})
			}
		}
	}
}

func benchmarkAccelerationTunnel(b *testing.B, mode, transport string, size int) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	s, identity, _ := newTestServer(b, []TunnelConfig{{Name: "echo", VirtualPort: 18080, Target: echo.Addr().String(), Allow: []string{"*"}}})
	s.Config.Acceleration.Mode = mode
	s.Config.Network.TunnelCIDR = "100.66.0.0/16"
	s.Config.Listen.WireGuard = fmt.Sprintf("127.0.0.1:%d", findFreeUDPPortForTest(b))
	if transport == "direct" {
		s.Config.Network.AdvertisedEndpoint = s.Config.Listen.WireGuard
	}
	if transport == "udp-relay" {
		s.Config.Relay.Enabled = true
		s.Config.Transport.Force = "udp-relay"
	}
	if err := s.StartDataPlane(); err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	if transport == "udp-relay" {
		agent, addr, _ := startUDPRelayFixture(b)
		s.EnableUDPRelay(agent, addr)
	}
	https := httptest.NewTLSServer(s.Handler())
	defer https.Close()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	local := reservation.Addr().(*net.TCPAddr)
	_ = reservation.Close()
	connection, err := client.ConnectWithOptions(https.URL, identity, protocol.ClientInfo{OS: "linux"}, client.Options{
		Insecure: true, NoWebUI: true, StatusFile: filepath.Join(b.TempDir(), "status.json"),
		UseWebSocket: transport == "wss", Ports: map[string]int{"echo": local.Port},
		DirectUpgradeTiming: &client.DirectUpgradeTiming{InitialDelay: 100 * time.Millisecond, RetryInterval: 500 * time.Millisecond},
	})
	if err != nil {
		b.Fatal(err)
	}
	defer connection.Close()
	if transport == "udp-relay" {
		if err := connection.SetTransport("udp-relay"); err != nil {
			b.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for !connection.TransportInfo().ForcedEffective && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if !connection.TransportInfo().ForcedEffective {
			b.Fatalf("UDP relay did not activate: %+v", connection.TransportDetails())
		}
	}
	c, err := net.DialTimeout("tcp", local.String(), 5*time.Second)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	request, response := make([]byte, size), make([]byte, size)
	writeDone := make(chan error, 1)
	roundTrip := func() {
		if size <= 4096 {
			if _, err := c.Write(request); err != nil {
				b.Fatal(err)
			}
		} else {
			if err := c.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
				b.Fatal(err)
			}
			go func() { _, err := c.Write(request); writeDone <- err }()
		}
		if _, err := io.ReadFull(c, response); err != nil {
			b.Fatal(err)
		}
		if size > 4096 {
			if err := <-writeDone; err != nil {
				b.Fatal(err)
			}
		}
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	roundTrip()
	b.SetBytes(int64(2 * size))
	latencies := make([]time.Duration, 4096)
	i := 0
	startCPU := busyCPUTicks()
	for b.Loop() {
		start := time.Now()
		roundTrip()
		latencies[i%len(latencies)] = time.Since(start)
		i++
	}
	if stopCPU := busyCPUTicks(); startCPU > 0 && stopCPU >= startCPU {
		gib := float64(b.N) * float64(2*size) / (1 << 30)
		b.ReportMetric(float64(stopCPU-startCPU)/gib, "busy-ticks/GiB")
	}
	latencies = latencies[:min(i, len(latencies))]
	slices.Sort(latencies)
	b.ReportMetric(float64(latencies[(len(latencies)-1)*95/100].Microseconds()), "p95-us")
	if transport == "udp-relay" && !connection.TransportInfo().ForcedEffective {
		b.Fatal("UDP relay left the selected path during measurement")
	}
}

// The aggregate CPU line includes system, IRQ and softirq time. Run on a
// dedicated worker and measure idle busy ticks separately for release data.
func busyCPUTicks() uint64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 9 || fields[0] != "cpu" {
		return 0
	}
	var busy uint64
	for _, field := range []int{1, 2, 3, 6, 7, 8} {
		count, err := strconv.ParseUint(fields[field], 10, 64)
		if err != nil {
			return 0
		}
		busy += count
	}
	return busy
}

// BenchmarkAccelerationUDPOffloads isolates the per-socket options on the
// private loopback path. The production bridge uses conventional batching.
func BenchmarkAccelerationUDPOffloads(b *testing.B) {
	for _, options := range []struct {
		label    string
		gso, gro bool
	}{{"batch", false, false}, {"gro", false, true}, {"gso", true, false}, {"gso-gro", true, true}} {
		b.Run(options.label, func(b *testing.B) {
			receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			defer receiver.Close()
			if options.gro {
				raw, err := receiver.SyscallConn()
				if err != nil {
					b.Fatal(err)
				}
				var sockErr error
				if err := raw.Control(func(fd uintptr) {
					sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
				}); err != nil {
					b.Fatal(err)
				}
				if sockErr != nil {
					b.Skipf("UDP_GRO unavailable: %v", sockErr)
				}
			}
			sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
			if err != nil {
				b.Fatal(err)
			}
			defer sender.Close()
			const segmentSize, segments = 512, 8
			group := make([]byte, segmentSize*segments)
			buffer := make([]byte, len(group))
			oob := make([]byte, unix.CmsgSpace(4))
			messages := make([]ipv4.Message, segments)
			for i := range messages {
				messages[i].Buffers = [][]byte{group[i*segmentSize : (i+1)*segmentSize]}
			}
			packetConn := ipv4.NewPacketConn(sender)
			segmentControl := make([]byte, unix.CmsgSpace(2))
			header := (*unix.Cmsghdr)(unsafe.Pointer(&segmentControl[0]))
			header.Level, header.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
			header.SetLen(unix.CmsgLen(2))
			binary.NativeEndian.PutUint16(segmentControl[unix.CmsgLen(0):], segmentSize)
			send := func() error {
				if options.gso {
					_, _, err := sender.WriteMsgUDP(group, segmentControl, nil)
					return err
				}
				n, err := packetConn.WriteBatch(messages, 0)
				if n != len(messages) && err == nil {
					return io.ErrShortWrite
				}
				return err
			}
			receive := func() {
				for total := 0; total < len(group); {
					n, oobLen, flags, _, err := receiver.ReadMsgUDP(buffer, oob)
					if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n%segmentSize != 0 || n == 0 || total+n > len(group) {
						b.Fatalf("read offload group: length=%d flags=%d err=%v", n, flags, err)
					}
					if n > segmentSize {
						control, err := unix.ParseSocketControlMessage(oob[:oobLen])
						if err != nil || len(control) != 1 || control[0].Header.Type != unix.UDP_GRO ||
							control[0].Header.Level != unix.IPPROTO_UDP || len(control[0].Data) < 4 ||
							binary.NativeEndian.Uint32(control[0].Data) != segmentSize {
							b.Fatalf("unexpected UDP_GRO segment metadata: %v, %v", control, err)
						}
					}
					total += n
				}
			}
			_ = receiver.SetReadDeadline(time.Now().Add(2 * time.Minute))
			if err := send(); err != nil {
				if options.gso {
					b.Skipf("UDP_SEGMENT unavailable: %v", err)
				}
				b.Fatal(err)
			}
			receive()
			b.SetBytes(int64(len(group)))
			for b.Loop() {
				if err := send(); err != nil {
					b.Fatal(err)
				}
				receive()
			}
		})
	}
}
