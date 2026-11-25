package client

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/internal/localproxy"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"golang.org/x/net/proxy"
)

const proxySetupTimeout = 30 * time.Second

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
	localproxy.Dispatch(in, func(in net.Conn) {
		c.serveHTTPProxy(ctx, in, t, tunnelProxyDialer{dial: stack.DialContext, target: target, lifetime: ctx})
	}, func(in net.Conn) {
		c.forwardSocksStream(t, in, target, stack, stop)
	})
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
func (c *lifetimeProxyConn) CloseWrite() error { return localproxy.CloseWrite(c.Conn) }

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
func (c *countedProxyConn) CloseWrite() error { return localproxy.CloseWrite(c.Conn) }

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
	localproxy.ServeHTTP(ctx, in, dial, transport, localproxy.HTTPError)
}
