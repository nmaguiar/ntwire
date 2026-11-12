package client

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"golang.org/x/net/proxy"
)

const proxyHeaderTimeout = 10 * time.Second
const proxySetupTimeout = 30 * time.Second

// bufferedProxyConn preserves sniffed and pipelined bytes and TCP half-closes.
type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedProxyConn) CloseWrite() error          { return proxyCloseWrite(c.Conn) }
func proxyCloseWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// Peek only enough bytes to distinguish a method from opaque passthrough.
func isHTTPProxy(br *bufio.Reader) (bool, error) {
	methods := []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH ", "PRI "}
	for n := 1; ; n++ {
		b, err := br.Peek(n)
		if err != nil {
			return false, err
		}
		candidate := false
		for _, m := range methods {
			if string(b) == m {
				return true, nil
			}
			if strings.HasPrefix(m, string(b)) {
				candidate = true
			}
		}
		if !candidate {
			return false, nil
		}
	}
}

func (c *Connection) forwardMixedProxy(t *localTunnel, in net.Conn, target string, stack *wgnet.Stack, stop chan struct{}) {
	t.connections.Add(1)
	t.active.Add(1)
	defer t.active.Add(-1)
	if stack == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-c.stop:
			cancel()
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			in.Close()
		}
	}()
	br := bufio.NewReader(in)
	_ = in.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
	httpProxy, err := isHTTPProxy(br)
	if err != nil {
		return
	}
	_ = in.SetReadDeadline(time.Time{})
	buffered := &bufferedProxyConn{Conn: in, reader: br}
	if !httpProxy {
		c.forwardSocksStream(t, buffered, target, stack, stop)
		return
	}
	c.serveHTTPProxy(ctx, buffered, t, tunnelProxyDialer{dial: stack.DialContext, target: target, lifetime: ctx})
}

type proxyDialFunc func(context.Context, string, string) (net.Conn, error)
type tunnelProxyDialer struct {
	dial     proxyDialFunc
	target   string
	lifetime context.Context
}

func (d tunnelProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
func (d tunnelProxyDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	conn, err := d.dial(ctx, "tcp", d.target)
	if err != nil {
		return nil, err
	}
	c := &lifetimeProxyConn{Conn: conn}
	c.stop = context.AfterFunc(d.lifetime, func() { conn.Close() })
	return c, nil
}

type lifetimeProxyConn struct {
	net.Conn
	stop func() bool
}

func (c *lifetimeProxyConn) Close() error      { c.stop(); return c.Conn.Close() }
func (c *lifetimeProxyConn) CloseWrite() error { return proxyCloseWrite(c.Conn) }

type countedProxyConn struct {
	net.Conn
	tunnel *localTunnel
}

func (c *countedProxyConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.tunnel.fromTunnel.Add(uint64(n))
	return n, e
}
func (c *countedProxyConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.tunnel.toTunnel.Add(uint64(n))
	return n, e
}
func (c *countedProxyConn) CloseWrite() error { return proxyCloseWrite(c.Conn) }

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
func (c *proxyInboundConn) CloseWrite() error { return proxyCloseWrite(c.Conn) }

func (c *Connection) serveHTTPProxy(parent context.Context, in net.Conn, t *localTunnel, forward tunnelProxyDialer) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	forward.lifetime = ctx
	socks, err := proxy.SOCKS5("tcp", forward.target, nil, forward)
	if err != nil {
		return
	}
	dial := func(request context.Context, network, address string) (net.Conn, error) {
		setup, done := context.WithTimeout(request, proxySetupTimeout)
		defer done()
		stop := context.AfterFunc(ctx, done)
		defer stop()
		// DialWithConn retains the underlying connection's CloseWrite method;
		// x/net's DialContext result wraps it in a net.Conn-only interface.
		conn, err := forward.DialContext(setup, "tcp", forward.target)
		if err != nil {
			return nil, err
		}
		handshake := socks.(interface {
			DialWithConn(context.Context, net.Conn, string, string) (net.Addr, error)
		})
		if _, err = handshake.DialWithConn(setup, conn, network, address); err != nil {
			conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		// Count payload once, after the internal SOCKS handshake, like SOCKS forwarding.
		return &countedProxyConn{Conn: conn, tunnel: t}, nil
	}
	transport := &http.Transport{DialContext: dial, DisableCompression: true, ResponseHeaderTimeout: proxySetupTimeout, IdleConnTimeout: 90 * time.Second, ExpectContinueTimeout: time.Second}
	defer transport.CloseIdleConnections()
	reverse := &httputil.ReverseProxy{
		Transport: transport, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0),
		Rewrite: func(p *httputil.ProxyRequest) {
			p.Out.Host = p.Out.URL.Host
			if p.Out.Body != nil && len(p.In.Trailer) > 0 {
				p.Out.Body = &proxyTrailerBody{ReadCloser: p.Out.Body, source: p.In.Trailer, target: p.Out.Trailer}
			}
			p.Out.Header.Del("Proxy-Authorization")
			p.Out.Header.Del("Proxy-Authenticate")
			p.Out.Header.Del("Forwarded")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { proxyHTTPError(w, err) },
	}
	listener := &proxySingleListener{done: make(chan struct{})}
	inbound := &proxyInboundConn{Conn: in, closed: func() { cancel(); listener.Close() }}
	listener.conn = inbound
	closeOnCancel := context.AfterFunc(ctx, func() { inbound.Close() })
	defer closeOnCancel()
	server := &http.Server{ReadHeaderTimeout: proxyHeaderTimeout, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
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
				proxyHTTPError(w, err)
				return
			}
			defer out.Close()
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
			relayProxy(out, &bufferedProxyConn{Conn: conn, reader: rw.Reader})
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
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, " /\\\t\r\n@?#") {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}
func proxyHTTPError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		status = http.StatusGatewayTimeout
	}
	http.Error(w, http.StatusText(status), status)
}
func relayProxy(a, b net.Conn) {
	var ignored atomic.Uint64
	done := make(chan struct{})
	go func() { copyClientStream(a, b, &ignored); close(done) }()
	copyClientStream(b, a, &ignored)
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
