package server

import (
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"testing"
	"time"
)

func TestSessionsExpireAndCount(t *testing.T) {
	s := NewSessions()
	s.Create(CreateParams{Method: "ssh", Identity: "fp", Fingerprint: "fp", WireGuardPublicKey: "wg", TunnelIP: "100.64.0.2", Tunnels: []protocol.Tunnel{{Name: "a"}}, TTL: time.Millisecond})
	if s.CountIdentity("ssh", "fp") != 1 {
		t.Fatal("count")
	}
	time.Sleep(2 * time.Millisecond)
	if len(s.Reap()) != 1 {
		t.Fatal("reap")
	}
}
