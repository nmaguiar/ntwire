package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestCopyToTargetClosesOnClientEOFWithoutHalfClose(t *testing.T) {
	in, client := net.Pipe()
	out, target := net.Pipe()
	defer target.Close()
	var count atomic.Uint64
	done := make(chan struct{})
	go func() { copyToTarget(out, in, &count); close(done) }()
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
