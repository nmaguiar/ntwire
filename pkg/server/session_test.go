package server

import (
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"testing"
	"time"
)

func TestSessionsExpireAndCount(t *testing.T) {
	s := NewSessions()
	s.Create("fp", "wg", "100.64.0.2", []protocol.Tunnel{{Name: "a"}}, time.Millisecond)
	if s.CountFingerprint("fp") != 1 {
		t.Fatal("count")
	}
	time.Sleep(2 * time.Millisecond)
	if len(s.Reap()) != 1 {
		t.Fatal("reap")
	}
}
