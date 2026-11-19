package client

import (
	"io"
	"net"
	"testing"
)

type benchmarkUDPInput struct {
	net.PacketConn
	remaining int
}

func (p *benchmarkUDPInput) ReadFrom(buf []byte) (int, net.Addr, error) {
	if p.remaining == 0 {
		return 0, nil, io.EOF
	}
	p.remaining--
	buf[0] = 1
	return 1, nil, nil
}

// Isolate receive-loop allocations with no active WireGuard stack.
func BenchmarkUDPReceive(b *testing.B) {
	c := &Connection{}
	tunnel := &localTunnel{}
	pc := &benchmarkUDPInput{remaining: b.N}
	b.ReportAllocs()
	b.ResetTimer()
	c.forwardUDP(tunnel, pc, "", 0)
}
