// Package localproxy implements the shared local mixed proxy frontend.
package localproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/socks"
)

const HeaderTimeout = 10 * time.Second

type DialFunc func(context.Context, string, string) (net.Conn, error)

// Dispatch preserves the bytes consumed by protocol detection.
func Dispatch(in net.Conn, http, socks func(net.Conn)) {
	br := bufio.NewReader(in)
	_ = in.SetReadDeadline(time.Now().Add(HeaderTimeout))
	isHTTP, err := IsHTTP(br)
	if err != nil {
		return
	}
	_ = in.SetReadDeadline(time.Time{})
	buffered := &BufferedConn{Conn: in, Reader: br}
	if isHTTP {
		if http != nil {
			http(buffered)
		}
	} else if socks != nil {
		socks(buffered)
	}
}

// BufferedConn preserves sniffed and pipelined bytes and TCP half-closes.
type BufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (c *BufferedConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func (c *BufferedConn) CloseWrite() error          { return CloseWrite(c.Conn) }
func CloseWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// Peek through the method token without consuming bytes needed by either protocol.
func IsHTTP(br *bufio.Reader) (bool, error) {
	for n := 1; ; n++ {
		b, err := br.Peek(n)
		if err != nil {
			return false, err
		}
		c := b[n-1]
		if c == ' ' {
			return n > 1, nil
		}
		// HTTP methods use the RFC token grammar, including extension methods.
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false, nil
		}
	}
}

// Serve must remain alive after its first Accept, including during hijacks.
type proxySingleListener struct {
	conn     net.Conn
	accepted bool
	done     chan struct{}
	once     sync.Once
}

func (l *proxySingleListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *proxySingleListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *proxySingleListener) Addr() net.Addr { return l.conn.LocalAddr() }

type proxyInboundConn struct {
	net.Conn
	closed func()
}

func (c *proxyInboundConn) Close() error      { err := c.Conn.Close(); c.closed(); return err }
func (c *proxyInboundConn) CloseWrite() error { return CloseWrite(c.Conn) }

// ServeHTTP serves one inbound connection, including its keep-alive and upgrades.
func ServeHTTP(parent context.Context, in net.Conn, dial DialFunc, transport http.RoundTripper, writeError func(http.ResponseWriter, error)) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	reverse := &httputil.ReverseProxy{
		Transport: transport, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0),
		Rewrite: func(p *httputil.ProxyRequest) {
			p.Out.Host = p.Out.URL.Host
			// Forward the exact query; ReverseProxy normalizes it before Rewrite.
			p.Out.URL.RawQuery = p.In.URL.RawQuery
			if p.Out.Body != nil && len(p.In.Trailer) > 0 {
				p.Out.Body = &proxyTrailerBody{ReadCloser: p.Out.Body, source: p.In.Trailer, target: p.Out.Trailer}
			}
			p.Out.Header.Del("Proxy-Authorization")
			p.Out.Header.Del("Proxy-Authenticate")
			p.Out.Header.Del("Forwarded")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { writeError(w, err) },
	}
	listener := &proxySingleListener{done: make(chan struct{})}
	inbound := &proxyInboundConn{Conn: in, closed: func() { cancel(); listener.Close() }}
	listener.conn = inbound
	closeOnCancel := context.AfterFunc(ctx, func() { inbound.Close() })
	defer closeOnCancel()
	server := &http.Server{ReadHeaderTimeout: HeaderTimeout, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			http.Error(w, "HTTP/1.x required", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodConnect {
			if !validProxyAuthority(r.RequestURI) {
				http.Error(w, "invalid CONNECT destination", 400)
				return
			}
			out, err := dial(r.Context(), "tcp", r.RequestURI)
			if err != nil {
				writeError(w, err)
				return
			}
			defer out.Close()
			stop := context.AfterFunc(ctx, func() { _ = out.Close() })
			defer stop()
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Time{})
			if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return
			}
			if err = rw.Flush(); err != nil {
				return
			}
			Relay(out, &BufferedConn{Conn: conn, Reader: rw.Reader})
			return
		}
		if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil || r.URL.Opaque != "" || !validProxyAuthority(net.JoinHostPort(r.URL.Hostname(), proxyPort(r.URL.Port()))) {
			http.Error(w, "absolute http URL required", 400)
			return
		}
		reverse.ServeHTTP(w, r)
	})
	_ = server.Serve(listener)
	_ = server.Close()
}
func proxyPort(port string) string {
	if port == "" {
		return "80"
	}
	return port
}
func validProxyAuthority(address string) bool {
	_, err := socks.ParseDestination(address)
	return err == nil
}
func HTTPError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		status = http.StatusGatewayTimeout
	}
	http.Error(w, http.StatusText(status), status)
}

// Relay preserves write half-closes and closes both sides on copy errors.
func Relay(a, b net.Conn) {
	copyStream := func(dst, src net.Conn) {
		if _, err := io.Copy(dst, src); err == nil {
			if err := CloseWrite(dst); err == nil {
				return
			}
		}
		_ = dst.Close()
		_ = src.Close()
	}
	done := make(chan struct{})
	go func() { defer close(done); copyStream(a, b) }()
	copyStream(b, a)
	<-done
}

// Request.Clone snapshots trailer values before the body has populated them.
// Refresh the outbound map at EOF, before Transport writes the final chunk.
type proxyTrailerBody struct {
	io.ReadCloser
	source, target http.Header
}

func (b *proxyTrailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		for k, v := range b.source {
			switch http.CanonicalHeaderKey(k) {
			case "Proxy-Authorization", "Proxy-Authenticate", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
				delete(b.target, k)
			default:
				b.target[k] = v
			}
		}
	}
	return n, err
}

// WatchSetupDisconnect watches for a peer that closes during negotiation.
// A pending application byte stays buffered for the relay.
func WatchSetupDisconnect(in net.Conn, cancel context.CancelFunc) func() {
	buffered, ok := in.(*BufferedConn)
	if !ok {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := buffered.Reader.Peek(1); err != nil {
			var networkErr net.Error
			if !errors.As(err, &networkErr) || !networkErr.Timeout() {
				cancel()
			}
		}
	}()
	return func() {
		_ = in.SetReadDeadline(time.Now())
		<-done
		_ = in.SetReadDeadline(time.Time{})
	}
}
