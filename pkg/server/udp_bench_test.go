package server

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
)

type benchmarkUDPInput struct {
	net.PacketConn
	remaining int
	source    net.Addr
}

func (p *benchmarkUDPInput) ReadFrom(buf []byte) (int, net.Addr, error) {
	if p.remaining == 0 {
		return 0, nil, io.EOF
	}
	p.remaining--
	buf[0] = 1
	return 1, p.source, nil
}

// Use an ungranted source to isolate receive-loop allocations from socket I/O,
// dialing, and per-flow work.
func BenchmarkUDPReceive(b *testing.B) {
	source := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	for _, socks := range []bool{false, true} {
		name := "fixed"
		if socks {
			name = "socks"
		}
		b.Run(name, func(b *testing.B) {
			s := New(Config{}, slog.New(slog.DiscardHandler))
			pc := &benchmarkUDPInput{remaining: b.N, source: source}
			b.ReportAllocs()
			b.ResetTimer()
			if socks {
				s.proxySocksUDP(pc, DataPlanePrincipal{}, TunnelConfig{Socks: &SocksConfig{}}, nil, nil)
			} else {
				s.proxyUDP(&tunnelListener{}, pc)
			}
		})
	}
}

func BenchmarkTunnelPrincipalLookup(b *testing.B) {
	for _, count := range []int{1, 100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			s := New(Config{}, slog.New(slog.DiscardHandler))
			const ip = "100.64.0.2"
			s.sessions.Create(CreateParams{TunnelIP: ip, TTL: time.Hour, Tunnels: []protocol.Tunnel{{Name: "test"}}})
			for i := 1; i < count; i++ {
				s.sessions.Create(CreateParams{TunnelIP: fmt.Sprintf("fd00::%x", i), TTL: time.Hour})
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, ok := s.principalForIP(ip); !ok {
					b.Fatal("missing session principal")
				}
			}
		})
	}
}
