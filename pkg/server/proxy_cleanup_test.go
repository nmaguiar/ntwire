package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
)

func TestRelayCountedClosesOnClientEOFWithoutHalfClose(t *testing.T) {
	in, client := net.Pipe()
	out, target := net.Pipe()
	defer target.Close()
	var count atomic.Uint64
	done := make(chan struct{})
	go func() { localproxy.RelayCounted(in, out, &count, nil); close(done) }()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("copy did not stop")
	}
	_ = target.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := target.Read(make([]byte, 1)); err == nil {
		t.Fatal("target remained open")
	}
}
