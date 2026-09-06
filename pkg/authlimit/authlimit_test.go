package authlimit

import (
	"fmt"
	"testing"
	"time"
)

func TestNonceCacheRejectsReplayAndEmpty(t *testing.T) {
	c := NewNonceCache(time.Minute, 0)
	if c.Use("") {
		t.Fatal("an empty nonce must never be accepted")
	}
	if !c.Use("n1") {
		t.Fatal("a fresh nonce should be accepted")
	}
	if c.Use("n1") {
		t.Fatal("a replayed nonce should be rejected")
	}
}

// TestNonceCacheExpiresEntries checks the documented window is exact: an entry
// past its TTL is treated as absent rather than lingering until a sweep.
func TestNonceCacheExpiresEntries(t *testing.T) {
	c := NewNonceCache(20*time.Millisecond, 0)
	if !c.Use("n1") {
		t.Fatal("first use should succeed")
	}
	time.Sleep(40 * time.Millisecond)
	if !c.Use("n1") {
		t.Fatal("a nonce past its TTL should be usable again")
	}
}

// TestNonceCacheStaysBounded is the property the server previously lacked: the
// map had no cap, so entries accepted within one window grew without limit.
func TestNonceCacheStaysBounded(t *testing.T) {
	const max = 128
	c := NewNonceCache(time.Hour, max)
	for i := 0; i < max*10; i++ {
		c.Use(fmt.Sprintf("nonce-%d", i))
	}
	if got := c.Len(); got > max {
		t.Fatalf("cache grew to %d entries, want <= %d", got, max)
	}
}

func TestSourceLimiterCountsPerSource(t *testing.T) {
	l := NewSourceLimiter(3, time.Minute, 0)
	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("the fourth request within the window should be refused")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("a different source has its own bucket")
	}
}

// TestSourceLimiterZeroLimitDisables covers how callers express "unlimited" in
// configuration.
func TestSourceLimiterZeroLimitDisables(t *testing.T) {
	l := NewSourceLimiter(0, time.Minute, 0)
	for i := 0; i < 1000; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatal("a non-positive limit should disable the limiter")
		}
	}
	if l.Len() != 0 {
		t.Fatal("a disabled limiter should not track sources")
	}
}

func TestSourceLimiterWindowResets(t *testing.T) {
	l := NewSourceLimiter(1, 20*time.Millisecond, 0)
	if !l.Allow("1.2.3.4") || l.Allow("1.2.3.4") {
		t.Fatal("limit of one should allow exactly one per window")
	}
	time.Sleep(40 * time.Millisecond)
	if !l.Allow("1.2.3.4") {
		t.Fatal("a new window should allow again")
	}
}

// TestSourceLimiterStaysBounded is the property both open-coded limiters
// lacked: a source rotating addresses (trivial over IPv6) grew the table
// without limit, and each call swept the whole map.
func TestSourceLimiterStaysBounded(t *testing.T) {
	const max = 256
	l := NewSourceLimiter(5, time.Hour, max)
	for i := 0; i < max*10; i++ {
		l.Allow(fmt.Sprintf("2001:db8::%x", i))
	}
	if got := l.Len(); got > max {
		t.Fatalf("table grew to %d sources, want <= %d", got, max)
	}
}

// TestSourceLimiterEvictionDoesNotDenyOthers checks the eviction policy: an
// attacker able to fill the table must relax the limit, never deny service to
// everyone else.
func TestSourceLimiterEvictionDoesNotDenyOthers(t *testing.T) {
	l := NewSourceLimiter(5, time.Hour, 64)
	for i := 0; i < 1000; i++ {
		l.Allow(fmt.Sprintf("2001:db8::%x", i))
	}
	if !l.Allow("198.51.100.7") {
		t.Fatal("a new source must still be allowed once the table is full")
	}
}

func TestSourceLimiterConcurrentUse(t *testing.T) {
	l := NewSourceLimiter(1000000, time.Minute, 0)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				l.Allow(fmt.Sprintf("10.0.%d.%d", n, j%256))
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
