package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

type blockedUDPAllocator struct {
	fakeUDPAllocator
	entered chan struct{}
	resume  chan struct{}
}

func (f *blockedUDPAllocator) AllocateUDPSession(context.Context) (string, string, error) {
	f.mu.Lock()
	f.allocateN++
	f.mu.Unlock()
	f.entered <- struct{}{}
	<-f.resume // Deliberately model a reply arriving after cancellation.
	return "late-token", "127.0.0.1:9999", nil
}

func TestUDPRelayConcurrentAllocation(t *testing.T) {
	fa := &blockedUDPAllocator{entered: make(chan struct{}, 32), resume: make(chan struct{})}
	u := newTestUDPRelay(t, &fakeUDPAllocator{})
	u.agent = fa
	defer u.stopAll()
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	const clients = 20
	results := make(chan protocol.UDPRelayResponse, clients)
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- u.sessionFor(context.Background(), key.Public, false, false, nil) }()
	}
	<-fa.entered
	close(fa.resume)
	wg.Wait()
	close(results)
	for response := range results {
		if response.Token != "late-token" {
			t.Fatalf("allocation failed: %+v", response)
		}
	}
	if got := fa.allocations(); got != 1 {
		t.Fatalf("allocated %d relay ports for one client", got)
	}
}

func TestUDPRelayLateAllocationAfterTeardown(t *testing.T) {
	for _, stopAll := range []bool{false, true} {
		t.Run(map[bool]string{false: "release", true: "stop_all"}[stopAll], func(t *testing.T) {
			fa := &blockedUDPAllocator{entered: make(chan struct{}, 1), resume: make(chan struct{})}
			u := newTestUDPRelay(t, &fakeUDPAllocator{})
			u.agent = fa
			defer u.stopAll()
			key, err := wgnet.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := u.stack.AddPeer(wgnet.Endpoint{PublicKey: key.Public, Address: "100.70.0.2/32"}); err != nil {
				t.Fatal(err)
			}
			done := make(chan protocol.UDPRelayResponse, 1)
			go func() { done <- u.sessionFor(context.Background(), key.Public, false, false, nil) }()
			<-fa.entered
			if stopAll {
				u.stopAll()
			} else {
				u.release(key.Public)
			}
			close(fa.resume)
			select {
			case response := <-done:
				if response.Token != "" {
					t.Fatal("late allocation resurrected a session")
				}
			case <-time.After(time.Second):
				t.Fatal("allocation did not finish")
			}
			endpoint, _, err := u.stack.PeerEndpoint(key.Public)
			if err != nil {
				t.Fatal(err)
			}
			if endpoint != "" {
				t.Fatalf("late allocation changed peer endpoint to %q", endpoint)
			}
			fa.mu.Lock()
			defer fa.mu.Unlock()
			if len(fa.released) != 1 || fa.released[0] != "late-token" {
				t.Fatalf("late token not released: %v", fa.released)
			}
		})
	}
}

func TestUDPRelayCanceledWaiterDoesNotCancelOwner(t *testing.T) {
	fa := &blockedUDPAllocator{entered: make(chan struct{}, 1), resume: make(chan struct{})}
	u := newTestUDPRelay(t, &fakeUDPAllocator{})
	u.agent = fa
	defer u.stopAll()
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan protocol.UDPRelayResponse, 1)
	go func() { done <- u.sessionFor(context.Background(), key.Public, false, false, nil) }()
	<-fa.entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if response := u.sessionFor(ctx, key.Public, false, false, nil); response.Token != "" {
		t.Fatal("canceled waiter received allocation")
	}
	close(fa.resume)
	if response := <-done; response.Token != "late-token" {
		t.Fatal("waiter canceled owner")
	}
}

func TestUDPRelayStoppedTierDoesNotAllocate(t *testing.T) {
	fa := &fakeUDPAllocator{token: "token", serverAddr: "127.0.0.1:9999"}
	u := newTestUDPRelay(t, fa)
	u.stopAll()
	response := u.sessionFor(context.Background(), "peer", false, false, nil)
	if response.Token != "" || fa.allocations() != 0 {
		t.Fatal("stopped tier started another allocation")
	}
}

func TestUDPRelayIncompleteAllocationReleasesToken(t *testing.T) {
	fa := &fakeUDPAllocator{token: "orphan"}
	u := newTestUDPRelay(t, fa)
	defer u.stopAll()
	response := u.sessionFor(context.Background(), "peer", false, false, nil)
	if response.Token != "" {
		t.Fatal("incomplete allocation accepted")
	}
	fa.mu.Lock()
	defer fa.mu.Unlock()
	if len(fa.released) != 1 || fa.released[0] != "orphan" {
		t.Fatalf("incomplete allocation leaked token: %v", fa.released)
	}
}
