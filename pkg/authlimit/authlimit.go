// Package authlimit bounds what an unauthenticated caller can make a server
// allocate: a replay-nonce cache and a per-source request limiter.
//
// Both were previously open-coded once per package (pkg/server, pkg/relay) and
// both had the same two defects: an unbounded map, and a full sweep of that map
// on every call, which makes cost quadratic in entries accepted per window.
// Sharing one implementation keeps the two from drifting apart again, which is
// how the server came to consume a nonce before verifying a signature while the
// relay -- with the same protocol shape -- did not.
package authlimit

import (
	"sync"
	"time"
)

// DefaultMaxNonces bounds a NonceCache when the caller does not pick a size.
// It backstops the ordinary TTL expiry for the case where a peer presents an
// unusual number of distinct nonces inside one window.
const DefaultMaxNonces = 4096

// DefaultMaxSources bounds a SourceLimiter's tracked sources. It is large
// enough for any real client population and small enough that an attacker
// rotating source addresses (trivial over IPv6) cannot grow it without bound.
const DefaultMaxSources = 65536

// NonceCache remembers recently accepted nonces so a signed request cannot be
// replayed inside its freshness window.
//
// Callers must consume a nonce only *after* authenticating the request that
// carries it. Recording nonces for unauthenticated requests lets anyone who can
// reach the endpoint churn the cache without ever presenting a valid key.
type NonceCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	max  int
	seen map[string]time.Time
}

// NewNonceCache returns a cache remembering nonces for ttl, holding at most max
// entries. Non-positive values fall back to five minutes and DefaultMaxNonces.
func NewNonceCache(ttl time.Duration, max int) *NonceCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if max <= 0 {
		max = DefaultMaxNonces
	}
	return &NonceCache{ttl: ttl, max: max, seen: make(map[string]time.Time)}
}

// Use records n as seen and reports whether it was fresh. An empty nonce is
// always rejected; so is one already recorded within the TTL.
func (c *NonceCache) Use(n string) bool {
	if n == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	// An entry past its TTL is treated as absent and overwritten below, so the
	// documented window is exact rather than "until the next sweep".
	if at, ok := c.seen[n]; ok && now.Sub(at) <= c.ttl {
		return false
	}
	// Sweeping only at capacity keeps the common path O(1); the whole-map scan
	// the previous implementations did on every call is what made cost
	// quadratic in accepted nonces per window.
	if len(c.seen) >= c.max {
		c.sweepLocked(now)
	}
	c.seen[n] = now
	return true
}

// Len reports the number of retained entries. It exists for tests asserting
// the cache stays bounded.
func (c *NonceCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// sweepLocked drops expired entries and, if the cache is still at capacity
// afterwards, the single oldest survivor.
func (c *NonceCache) sweepLocked(now time.Time) {
	var oldestKey string
	var oldestAt time.Time
	haveOldest := false
	for k, at := range c.seen {
		if now.Sub(at) > c.ttl {
			delete(c.seen, k)
			continue
		}
		if !haveOldest || at.Before(oldestAt) {
			oldestKey, oldestAt, haveOldest = k, at, true
		}
	}
	if len(c.seen) >= c.max && haveOldest {
		delete(c.seen, oldestKey)
	}
}

// SourceLimiter caps how many times one source (normally an IP address) may
// perform an action within a rolling window.
//
// It is a coarse abuse control, not an accounting system: eviction under
// pressure resets a source's counter rather than denying it, because an
// attacker able to fill the table must not thereby be able to lock out
// everyone else.
type SourceLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	max     int
	sources map[string]*sourceState
	sweepAt time.Time
}

type sourceState struct {
	n     int
	since time.Time
}

// NewSourceLimiter allows limit actions per source per window, tracking at most
// max sources. Non-positive window and max fall back to one minute and
// DefaultMaxSources. A non-positive limit disables the limiter entirely, which
// is how callers express "unlimited" in configuration.
func NewSourceLimiter(limit int, window time.Duration, max int) *SourceLimiter {
	if window <= 0 {
		window = time.Minute
	}
	if max <= 0 {
		max = DefaultMaxSources
	}
	return &SourceLimiter{limit: limit, window: window, max: max, sources: make(map[string]*sourceState)}
}

// Allow records one action by source and reports whether it may proceed.
func (l *SourceLimiter) Allow(source string) bool {
	if l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	// Amortized: at most one sweep per window, plus one when at capacity.
	if now.After(l.sweepAt) || len(l.sources) >= l.max {
		l.sweepLocked(now)
		l.sweepAt = now.Add(l.window)
	}
	s := l.sources[source]
	if s == nil || now.Sub(s.since) > l.window {
		l.sources[source] = &sourceState{n: 1, since: now}
		return true
	}
	s.n++
	return s.n <= l.limit
}

// Len reports the number of tracked sources. It exists for tests asserting the
// table stays bounded.
func (l *SourceLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sources)
}

// sweepLocked drops sources whose window has elapsed and, if the table is still
// at capacity, evicts arbitrary entries until it is comfortably under. Evicting
// only resets those sources' counters, so a table-filling attacker relaxes the
// limit for others rather than denying them service.
func (l *SourceLimiter) sweepLocked(now time.Time) {
	for k, s := range l.sources {
		if now.Sub(s.since) > l.window {
			delete(l.sources, k)
		}
	}
	target := l.max - l.max/10
	for k := range l.sources {
		if len(l.sources) <= target {
			break
		}
		delete(l.sources, k)
	}
}
