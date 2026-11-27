package wstransport

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestQUICAdmission_DropsOnlyUnacceptedSuffixAtDeadline(t *testing.T) {
	wait := MaxQUICSendWait
	b, err := NewQUICBind(&wait)
	if err != nil {
		t.Fatal(err)
	}
	p := &quicPeer{out: make(chan []byte, 1)}
	first := []byte{1}
	if err := b.admitBatch(t.Context(), nil, p, [][]byte{first, {2}, {3}}); err != nil {
		t.Fatal(err)
	}
	first[0] = 42
	if data := <-p.out; data[0] != 1 {
		t.Fatal("the caller still owns admitted ciphertext")
	}
	if stats := b.Stats(); stats.SendDrops != 2 || stats.WaitEvents != 1 || stats.WaitNS < uint64(wait) {
		t.Fatalf("unexpected admission accounting: %+v", stats)
	}
}

func TestQUICAdmission_SaturatedPeerDoesNotHoldOtherLaneOrTeardown(t *testing.T) {
	// Extend the fake queue deadline so the test can trigger admission
	// credit and cancellation deterministically. Constructors reject it.
	b := &QUICBind{sendWait: time.Minute}
	stalled := &quicPeer{out: make(chan []byte, 1)}
	stalled.out <- []byte{1}
	healthy := &quicPeer{out: make(chan []byte, 1)}
	done := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			close(done)
		}
	})
	sent := make(chan error, 1)
	go func() { sent <- b.admitBatch(t.Context(), done, stalled, [][]byte{{2}, {3}}) }()
	deadline := time.Now().Add(time.Second)
	for b.Stats().WaitEvents == 0 {
		if time.Now().After(deadline) {
			t.Fatal("full peer never waited")
		}
		time.Sleep(time.Millisecond)
	}
	if err := b.admitBatch(t.Context(), nil, healthy, [][]byte{{4}}); err != nil {
		t.Fatal(err)
	}
	if len(healthy.out) != 1 {
		t.Fatal("healthy lane did not receive independent admission")
	}
	if err := b.admitBatch(t.Context(), nil, stalled, [][]byte{{5}}); err != nil || b.Stats().SendDrops != 1 {
		t.Fatalf("second stalled sender did not drop instead of waiting: %v / %+v", err, b.Stats())
	}
	// Make room for one datagram while the peer is still attached.
	<-stalled.out
	select {
	case next := <-stalled.out:
		if next[0] != 2 {
			t.Fatalf("queued successor was %v", next)
		}
	case <-time.After(time.Second):
		t.Fatal("returned queue credit did not wake the sender")
	}
	select {
	case err := <-sent:
		if err != nil || len(stalled.out) != 1 {
			t.Fatalf("released batch did not finish: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("batch did not finish after both queue credits")
	}
	go func() { sent <- b.admitBatch(t.Context(), done, stalled, [][]byte{{6}}) }()
	deadline = time.Now().Add(time.Second)
	for b.Stats().WaitEvents < 2 {
		if time.Now().After(deadline) {
			t.Fatal("teardown test sender never waited")
		}
		time.Sleep(time.Millisecond)
	}
	close(done)
	select {
	case err := <-sent:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("teardown error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("teardown did not wake admission")
	}
}
