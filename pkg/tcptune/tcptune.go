// Package tcptune applies opt-in TCP socket tuning to ntwire's TLS/WebSocket
// listeners and dialers. The zero Options value is a strict no-op: no socket
// option is read or written, so default deployments behave exactly as
// before.
package tcptune

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"
)

// Options is the YAML-configurable tuning block.
type Options struct {
	// Congestion selects the kernel congestion-control algorithm for each
	// socket (TCP_CONGESTION), for example "bbr". Empty keeps the system
	// default. Linux only.
	Congestion string `yaml:"congestion"`
	// NotSentLowat caps unsent bytes queued in the kernel per socket
	// (TCP_NOTSENT_LOWAT), which bounds the latency a full WebSocket send
	// buffer can add. Zero keeps the system default. Linux only.
	NotSentLowat int `yaml:"notsent_lowat"`
}

// Enabled reports whether any tuning is requested.
func (o Options) Enabled() bool { return o.Congestion != "" || o.NotSentLowat != 0 }

// Validate rejects values that can never be applied on any platform.
func (o Options) Validate() error {
	if o.NotSentLowat < 0 {
		return fmt.Errorf("notsent_lowat must not be negative")
	}
	for _, r := range o.Congestion {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') || len(o.Congestion) > 15 {
			return fmt.Errorf("congestion %q is not a valid algorithm name", o.Congestion)
		}
	}
	return nil
}

// warnOnce keeps a misconfigured or unsupported option from logging per
// accepted connection.
var warnOnce sync.Map

func warn(key, msg string, args ...any) {
	if _, loaded := warnOnce.LoadOrStore(key, true); !loaded {
		slog.Warn(msg, args...)
	}
}

// control returns a net.ListenConfig/net.Dialer Control hook, or nil when no
// tuning is requested. Accepted sockets inherit TCP_CONGESTION and
// TCP_NOTSENT_LOWAT from the listening socket on Linux.
func (o Options) control() func(network, address string, c syscall.RawConn) error {
	if !o.Enabled() {
		return nil
	}
	return func(network, _ string, c syscall.RawConn) error {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil
		}
		var applyErr error
		if err := c.Control(func(fd uintptr) { applyErr = apply(fd, o) }); err != nil {
			warn("control", "TCP tuning could not access socket; continuing untuned", "error", err)
			return nil
		}
		if applyErr != nil {
			warn("apply:"+applyErr.Error(), "TCP tuning not applied; continuing untuned", "error", applyErr)
		}
		return nil
	}
}

// Listen opens a TCP listener with o applied. With zero Options it is
// equivalent to net.Listen("tcp", addr).
func Listen(o Options, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: o.control()}
	return lc.Listen(context.Background(), "tcp", addr)
}

// DialContext returns a dial function with o applied, suitable for
// http.Transport.DialContext. With zero Options it returns nil so callers
// keep the transport's default dialer.
func DialContext(o Options) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if !o.Enabled() {
		return nil
	}
	d := &net.Dialer{Control: o.control()}
	return d.DialContext
}
