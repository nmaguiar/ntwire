package localproxy

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPPool belongs to one inbound HTTP connection. Each RoundTrip is attempted
// on exactly one origin connection. ClientConn has no automatic re-dial path.
type HTTPPool struct {
	mu      sync.Mutex
	closed  bool
	dial    DialFunc
	allowed func(net.Conn) bool
	entries map[string]poolEntry
}
type poolEntry struct {
	client *http.ClientConn
	conn   net.Conn
	used   time.Time
}

func NewHTTPPool(dial DialFunc, allowed func(net.Conn) bool) *HTTPPool {
	return &HTTPPool{dial: dial, allowed: allowed, entries: map[string]poolEntry{}}
}
func (p *HTTPPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, entry := range p.entries {
		_ = entry.client.Close()
	}
	clear(p.entries)
}
func (p *HTTPPool) RoundTrip(req *http.Request) (*http.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	address := net.JoinHostPort(req.URL.Hostname(), proxyPort(req.URL.Port()))
	now := time.Now()
	for key, entry := range p.entries {
		if now.Sub(entry.used) > 90*time.Second || entry.client.Err() != nil {
			_ = entry.client.Close()
			delete(p.entries, key)
		}
	}
	entry, ok := p.entries[address]
	if ok && (entry.client.Available() == 0 || !p.allowed(entry.conn)) {
		_ = entry.client.Close()
		delete(p.entries, address)
		ok = false
	}
	if !ok {
		if len(p.entries) >= 8 {
			var oldest string
			for key, item := range p.entries {
				if oldest == "" || item.used.Before(p.entries[oldest].used) {
					oldest = key
				}
			}
			_ = p.entries[oldest].client.Close()
			delete(p.entries, oldest)
		}
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		transport := &http.Transport{
			Protocols: protocols, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := p.dial(ctx, network, addr)
				entry.conn = conn
				return conn, err
			},
		}
		var err error
		entry.client, err = transport.NewClientConn(req.Context(), "http", address)
		if err != nil {
			return nil, err
		}
	}
	entry.used = now
	p.entries[address] = entry
	response, err := entry.client.RoundTrip(req)
	if err != nil {
		_ = entry.client.Close()
		delete(p.entries, address)
	}
	return response, err
}
