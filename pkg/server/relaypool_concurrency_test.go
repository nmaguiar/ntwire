package server

import (
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestRelayPoolConcurrentFailoverPublishesLatestSelection(t *testing.T) {
	p, err := NewRelayPool(RelayConfig{Name: "test", IdentityFile: "unused", Endpoints: []RelayEndpoint{{URL: "wss://a.example:8444"}, {URL: "wss://b.example:8444"}, {URL: "wss://c.example:8444"}}}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	a, b, c := p.members[0], p.members[1], p.members[2]
	p.update(a, true, protocol.RelayRegisterResponse{Domain: "example", ReflectAddr: "a:1", UDPRelayAddr: "a:2"})
	p.update(b, true, protocol.RelayRegisterResponse{Domain: "example", ReflectAddr: "b:1", UDPRelayAddr: "b:2"})
	p.update(c, true, protocol.RelayRegisterResponse{Domain: "example", ReflectAddr: "c:1", UDPRelayAddr: "c:2"})
	entered, resume, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	p.OnReflectAddr = func(addr string) {
		if addr == "b:1" {
			close(entered)
			<-resume
		}
	}
	var mu sync.Mutex
	var applied string
	p.OnUDPRelayAddr = func(_ *RelayAgent, addr string) { mu.Lock(); applied = addr; mu.Unlock() }
	go func() { defer close(finished); p.update(a, false, protocol.RelayRegisterResponse{}) }()
	<-entered
	secondDone := make(chan struct{})
	go func() { defer close(secondDone); p.update(b, false, protocol.RelayRegisterResponse{}) }()
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		selected := p.preferred == c
		p.mu.Unlock()
		if selected {
			break
		}
		if time.Now().After(deadline) {
			close(resume)
			t.Fatal("second update did not select C")
		}
		time.Sleep(time.Millisecond)
	}
	close(resume)
	<-finished
	<-secondDone
	if !p.Healthy() || p.preferred != c {
		t.Fatal("expected healthy relay C selected")
	}
	mu.Lock()
	got := applied
	mu.Unlock()
	if got != "c:2" {
		t.Fatalf("pool selected healthy relay C, but final UDP callback reinstalls disconnected relay %q", got)
	}
}

func TestRelayPoolCloseClearsAndRejectsLateCallbacks(t *testing.T) {
	p, err := NewRelayPool(RelayConfig{Name: "test", IdentityFile: "unused", URL: "wss://relay.example:8444"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var applied string
	var calls int
	p.OnUDPRelayAddr = func(_ *RelayAgent, addr string) { _ = p.Healthy(); applied = addr; calls++ }
	response := protocol.RelayRegisterResponse{Domain: "example", UDPRelayAddr: "relay:2"}
	p.update(p.members[0], true, response)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p.update(p.members[0], true, response)
	if applied != "" || calls != 2 || p.Healthy() {
		t.Fatalf("closed pool: applied=%q calls=%d healthy=%v", applied, calls, p.Healthy())
	}
}
