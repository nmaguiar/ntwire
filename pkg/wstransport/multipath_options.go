package wstransport

import (
	"sync"
	"time"
)

// MultipathOptions configures the bounded behaviors shared by v3 peers.
// V3 never mirrors ordinary tunnel traffic merely to sample a standby path.
type MultipathOptions struct {
	DuplicateRateBytesPerSec int
}

const defaultDuplicateRateBytesPerSec = 262144 // 256 KB/s

func resolveMultipathOptions(o MultipathOptions) MultipathOptions {
	if o.DuplicateRateBytesPerSec <= 0 {
		o.DuplicateRateBytesPerSec = defaultDuplicateRateBytesPerSec
	}
	return o
}

// byteRateLimiter is the byte-rate token bucket that bounds reactive type-4
// duplication.
type byteRateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64
	last       time.Time
}

func newByteRateLimiter(bytesPerSecond int) *byteRateLimiter {
	if bytesPerSecond <= 0 {
		bytesPerSecond = defaultDuplicateRateBytesPerSec
	}
	rate := float64(bytesPerSecond)
	return &byteRateLimiter{tokens: rate, maxTokens: rate, refillRate: rate, last: time.Now()}
}

func (l *byteRateLimiter) Allow(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.refillRate
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	l.last = now
	if l.tokens < float64(n) {
		return false
	}
	l.tokens -= float64(n)
	return true
}
