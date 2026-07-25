package relay

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

func TestResolveTenant(t *testing.T) {
	cases := []struct {
		name     string
		sni      string
		domain   string
		wantName string
		wantOK   bool
	}{
		{"simple match", "home.relay.example.com", "relay.example.com", "home", true},
		{"nested subdomain rejected", "foo.home.relay.example.com", "relay.example.com", "", false},
		{"empty sni", "", "relay.example.com", "", false},
		{"wrong domain suffix", "home.other.com", "relay.example.com", "", false},
		{"empty label", ".relay.example.com", "relay.example.com", "", false},
		{"exact domain, no label", "relay.example.com", "relay.example.com", "", false},
		{"uppercase not normalized here (already done upstream)", "HOME.relay.example.com", "relay.example.com", "", false},
		{"invalid characters", "home_lab.relay.example.com", "relay.example.com", "", false},
		{"valid hyphenated label", "home-lab.relay.example.com", "relay.example.com", "home-lab", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, ok := resolveTenant(tc.sni, tc.domain)
			if ok != tc.wantOK || name != tc.wantName {
				t.Fatalf("resolveTenant(%q, %q) = (%q, %v), want (%q, %v)", tc.sni, tc.domain, name, ok, tc.wantName, tc.wantOK)
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th request within the window should be rejected")
	}
	// A distinct source IP has its own independent bucket.
	if !rl.allow("5.6.7.8") {
		t.Fatal("a different source IP should not be affected by another IP's limit")
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// stubConn is a minimal net.Conn whose Read returns an immediate EOF, so
// handle() runs to completion (peekClientHello fails, handle closes and
// returns) without needing real timing or a valid TLS ClientHello.
type stubConn struct {
	closed chan struct{}
}

func (c *stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *stubConn) Close() error                     { close(c.closed); return nil }
func (c *stubConn) LocalAddr() net.Addr              { return fakeAddr("127.0.0.1:0") }
func (c *stubConn) RemoteAddr() net.Addr             { return fakeAddr("203.0.113.9:1234") }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

// sequencedListener hands out a transient accept error, then one real
// connection, then net.ErrClosed to end the loop cleanly.
type sequencedListener struct {
	mu   sync.Mutex
	step int
	conn net.Conn
}

func (l *sequencedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.step++
	switch l.step {
	case 1:
		return nil, &net.OpError{Op: "accept", Err: fmt.Errorf("transient failure")}
	case 2:
		return l.conn, nil
	default:
		return nil, net.ErrClosed
	}
}
func (l *sequencedListener) Close() error   { return nil }
func (l *sequencedListener) Addr() net.Addr { return fakeAddr("127.0.0.1:0") }

// TestPublicListener_SurvivesTransientAcceptError is the regression test for
// serve returning on any accept error: before the fix, a single transient
// failure (EMFILE, ECONNABORTED, ...) permanently stopped the public
// listener from serving every tenant for the life of the process, with only
// a Warn log to show for it. serve must retry instead, exactly as
// net/http.Server.Serve does for its own accept loop.
func TestPublicListener_SurvivesTransientAcceptError(t *testing.T) {
	reg := NewRegistry(nil, testLimits())
	pl := newPublicListener(reg, "relay.example.com", testLimits(), 60, slog.Default())

	conn := &stubConn{closed: make(chan struct{})}
	ln := &sequencedListener{conn: conn}

	done := make(chan struct{})
	go func() {
		pl.serve(ln)
		close(done)
	}()

	select {
	case <-conn.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("connection accepted after a transient error was never handled: the accept loop likely returned instead of retrying")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after the listener reported closed")
	}
}
