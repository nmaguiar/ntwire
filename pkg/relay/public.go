package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// publicListener implements the always-relay TLS passthrough accept loop:
// peek the ClientHello's SNI, resolve it to a registered tenant, mint a
// conn_id and await the tenant's dial-back data connection, then splice raw
// bytes bidirectionally. It never terminates the client's TLS session.
type publicListener struct {
	registry *Registry
	domain   string
	limits   Limits
	rate     *rateLimiter
	log      *slog.Logger
}

func newPublicListener(registry *Registry, domain string, limits Limits, maxNewConnsPerMinute int, log *slog.Logger) *publicListener {
	if log == nil {
		log = slog.Default()
	}
	return &publicListener{registry: registry, domain: domain, limits: limits, rate: newRateLimiter(maxNewConnsPerMinute), log: log}
}

// serve mirrors the backoff net/http.Server.Serve applies to its own accept
// loop: retry indefinitely on any error other than the listener being
// closed, backing off from 5ms to a 1s cap so a run of failures (e.g.
// EMFILE) doesn't spin, and resetting once accepts succeed again. Returning
// on a transient error here would silently stop serving every tenant for
// the life of the process while the agents listener keeps accepting
// registrations -- the accept loop is the one thing that must not give up.
func (p *publicListener) serve(ln net.Listener) {
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay *= 2
			}
			if delay > time.Second {
				delay = time.Second
			}
			p.log.Warn("public listener accept error; retrying", "error", err, "retry_in", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go p.handle(c)
	}
}

func (p *publicListener) handle(c net.Conn) {
	defer c.Close()
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		host = c.RemoteAddr().String()
	}
	if !p.rate.allow(host) {
		return // silently reset; no reply, indistinguishable from any other close
	}

	_ = c.SetReadDeadline(time.Now().Add(p.limits.HandshakeTimeout))
	sni, raw, err := peekClientHello(c)
	if err != nil {
		return // not a valid TLS ClientHello, or slowloris timeout: reset, no reply
	}
	_ = c.SetReadDeadline(time.Time{})

	name, ok := resolveTenant(sni, p.domain)
	if !ok {
		return // no SNI, malformed label, or wrong domain suffix: reset, no default tenant
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.limits.DialBackTimeout)
	defer cancel()
	back, err := p.registry.Open(ctx, name, c.RemoteAddr().String(), sni)
	if err != nil {
		// Unknown/offline tenant and at-capacity are deliberately
		// indistinguishable to the client: both just reset.
		return
	}
	defer func() {
		_ = back.Close()
		p.registry.Release(name)
	}()

	if _, err := back.Write(raw); err != nil {
		return
	}
	p.log.Debug("relay connection spliced", "tenant", name, "client", host, "sni", sni)
	splice(c, back)
}

// resolveTenant validates sni against "^[a-z0-9-]+\.<domain>$" and returns
// the single leading label as the tenant name. peekClientHello already
// normalized case and a trailing dot; this additionally rejects nested
// subdomains and the empty-SNI case.
func resolveTenant(sni, domain string) (string, bool) {
	if sni == "" || domain == "" {
		return "", false
	}
	suffix := "." + domain
	if !strings.HasSuffix(sni, suffix) {
		return "", false
	}
	label := strings.TrimSuffix(sni, suffix)
	if label == "" || !validLabel(label) {
		return "", false
	}
	return label, true
}

func validLabel(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b) }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a) }()
	wg.Wait()
}

type rateState struct {
	n     int
	since time.Time
}

// rateLimiter is the relay's per-source-IP cap on new public connections,
// the same shape as pkg/server's allowSource. Unlike the server, this is
// mandatory: a valid-SNI inbound SYN forces the origin server to open an
// outbound dial-back connection, so an unbounded public listener is a
// dial-back amplification vector.
type rateLimiter struct {
	mu    sync.Mutex
	limit int
	rates map[string]*rateState
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{limit: limit, rates: map[string]*rateState{}}
}

func (r *rateLimiter) allow(host string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, v := range r.rates {
		if now.Sub(v.since) > time.Minute {
			delete(r.rates, k)
		}
	}
	v := r.rates[host]
	if v == nil || now.Sub(v.since) > time.Minute {
		r.rates[host] = &rateState{n: 1, since: now}
		return true
	}
	v.n++
	return v.n <= r.limit
}
