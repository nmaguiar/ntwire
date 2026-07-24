// Package socks implements an embedded SOCKS4/SOCKS5 CONNECT and BIND proxy
// server, re-implementing (not vendoring) the filter/feature set of
// github.com/nmaguiar/socksd -- itself a JVM/OpenAF stack, not a Go library
// -- so an ntwire tunnel can act as a governed egress proxy. See filter.go
// for the ported filter semantics and asn.go for the ASN index.
package socks

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// Config configures a Server. Only Filter is required; everything else has
// a sensible default.
type Config struct {
	Filter FilterConfig

	// ASNLookup resolves destination IPs to ASNs for Filter.ASNs. Pass an
	// *ASNIndex kept warm by ASNIndex.Refresh, or nil to disable ASN
	// filtering even if Filter.ASNs is non-empty.
	ASNLookup ASNLookup

	// DNSTimeout bounds resolution of SOCKS5 domain requests. Matches
	// socksd's DNSTIMEOUT, reinterpreted as a resolution timeout rather
	// than a JVM DNS-cache TTL (Go has no equivalent cache to size).
	// Default: 10s.
	DNSTimeout time.Duration

	// DialTimeout bounds the outbound connection to the destination.
	// Default: 10s (matching pkg/server's existing tunnel dial timeout).
	DialTimeout time.Duration

	// BindTimeout bounds how long a BIND command's listening socket waits
	// for the single inbound peer it accepts. Default: 2m.
	BindTimeout time.Duration

	Resolver *net.Resolver                                                     // default: net.DefaultResolver
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error) // default: (&net.Dialer{}).DialContext
	Logger   *slog.Logger                                                      // default: slog.Default()
}

// Server serves SOCKS4/SOCKS5 CONNECT and BIND on accepted connections,
// gating each destination through a Filter. UDP ASSOCIATE is recognized but
// refused (SOCKS4 has no UDP support upstream either); see the plan's Stage
// 3 for why it needs cross-cutting client/wgnet changes this package alone
// can't provide.
type Server struct {
	filter      *Filter
	dnsTimeout  time.Duration
	dialTimeout time.Duration
	bindTimeout time.Duration
	resolver    *net.Resolver
	dial        func(ctx context.Context, network, addr string) (net.Conn, error)
	log         *slog.Logger
}

// New builds a Server from cfg.
func New(cfg Config) (*Server, error) {
	f, err := NewFilter(cfg.Filter, cfg.ASNLookup)
	if err != nil {
		return nil, err
	}
	s := &Server{
		filter:      f,
		dnsTimeout:  cfg.DNSTimeout,
		dialTimeout: cfg.DialTimeout,
		bindTimeout: cfg.BindTimeout,
		resolver:    cfg.Resolver,
		dial:        cfg.Dial,
		log:         cfg.Logger,
	}
	if s.dnsTimeout <= 0 {
		s.dnsTimeout = 10 * time.Second
	}
	if s.dialTimeout <= 0 {
		s.dialTimeout = 10 * time.Second
	}
	if s.bindTimeout <= 0 {
		s.bindTimeout = 2 * time.Minute
	}
	if s.resolver == nil {
		s.resolver = net.DefaultResolver
	}
	if s.dial == nil {
		s.dial = (&net.Dialer{}).DialContext
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// ServeConn runs a single SOCKS session (handshake + relay) on an already
// accepted connection. It blocks until the session ends and closes conn
// before returning.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReaderSize(conn, 4096)
	ver, err := br.ReadByte()
	if err != nil {
		return
	}
	switch ver {
	case socks4Version:
		s.serveSocks4(ctx, conn, br)
	case socks5Version:
		s.serveSocks5(ctx, conn, br)
	default:
		s.log.Debug("socks: unrecognized version byte", "version", ver)
	}
}

// outcome is a protocol-neutral connect result; socks4.go/socks5.go map it
// to their respective reply codes.
type outcome int

const (
	outcomeGranted outcome = iota
	outcomeGeneralFailure
	outcomeNotAllowed
	outcomeHostUnreachable
	outcomeConnRefused
	outcomeTTLExpired
	outcomeCommandNotSupported
	outcomeAddressTypeNotSupported
)

// filterDestination resolves (if needed) and filters a client-supplied
// destination. hostname is set for SOCKS5 domain requests and empty
// otherwise, in which case ip must already be valid. This backs CONNECT,
// and also BIND: upstream (java-socks-proxy-server's getClientCommand)
// filters a BIND request's DST.ADDR/DST.PORT exactly like a CONNECT
// destination before dispatching, since it names the remote host the
// session expects to accept a connection back from.
func (s *Server) filterDestination(ctx context.Context, hostname string, ip netip.Addr, port uint16) (netip.Addr, outcome) {
	resolved := ip
	if !resolved.IsValid() {
		rctx, cancel := context.WithTimeout(ctx, s.dnsTimeout)
		addrs, err := s.resolver.LookupNetIP(rctx, "ip", hostname)
		cancel()
		if err != nil || len(addrs) == 0 {
			s.log.Debug("socks: dns resolution failed", "hostname", hostname, "error", err)
			return netip.Addr{}, outcomeHostUnreachable
		}
		resolved = addrs[0]
	}

	allowed := s.filter.Allowed(hostname, resolved)
	s.logDecision(allowed, hostname, resolved, port)
	if !allowed {
		return resolved, outcomeNotAllowed
	}
	return resolved, outcomeGranted
}

// connect resolves, filters, and dials the requested destination.
func (s *Server) connect(ctx context.Context, hostname string, ip netip.Addr, port uint16) (net.Conn, outcome) {
	resolved, o := s.filterDestination(ctx, hostname, ip, port)
	if o != outcomeGranted {
		return nil, o
	}

	target := netip.AddrPortFrom(resolved.Unmap(), port).String()
	dctx, cancel := context.WithTimeout(ctx, s.dialTimeout)
	defer cancel()
	out, err := s.dial(dctx, "tcp", target)
	if err != nil {
		s.log.Debug("socks: dial failed", "target", target, "error", err)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, outcomeTTLExpired
		}
		return nil, outcomeGeneralFailure
	}
	return out, outcomeGranted
}

// bindListener is the ephemeral, real-network TCP listener a BIND command
// opens: unlike CONNECT, BIND traffic isn't reachable over the WireGuard
// tunnel -- the remote host named by the client's DST.ADDR is expected to
// dial back to this listener over the ordinary network, so it must be a
// real host-network socket. There is no NAT traversal here, matching
// upstream: the reported address is whatever the OS bound to.
type bindListener struct {
	ln   net.Listener
	addr netip.Addr
	port uint16
}

// startBind opens a BIND listener on an OS-chosen port.
func (s *Server) startBind() (*bindListener, outcome) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		s.log.Debug("socks: bind failed to open listener", "error", err)
		return nil, outcomeGeneralFailure
	}
	a, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		ln.Close()
		return nil, outcomeGeneralFailure
	}
	addr, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		ln.Close()
		return nil, outcomeGeneralFailure
	}
	return &bindListener{ln: ln, addr: addr.Unmap(), port: uint16(a.Port)}, outcomeGranted
}

// acceptBind waits for the single peer connection a BIND command relays,
// bounded by s.bindTimeout, and always closes the listener before
// returning -- matching upstream's one-shot ServerSocket.accept().
func (s *Server) acceptBind(bl *bindListener) (net.Conn, outcome) {
	defer bl.ln.Close()
	if tl, ok := bl.ln.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(s.bindTimeout))
	}
	c, err := bl.ln.Accept()
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, outcomeTTLExpired
		}
		return nil, outcomeGeneralFailure
	}
	return c, outcomeGranted
}

func remoteAddrParts(c net.Conn) (netip.Addr, uint16) {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap(), uint16(a.Port)
		}
	}
	return netip.IPv4Unspecified(), 0
}

func (s *Server) logDecision(allowed bool, hostname string, ip netip.Addr, port uint16) {
	dest := hostname
	if dest == "" {
		dest = ip.String()
	}
	if allowed {
		s.log.Info("socks connect allowed", "destination", dest, "resolved_ip", ip.String(), "port", port)
	} else {
		s.log.Warn("socks connect denied", "destination", dest, "resolved_ip", ip.String(), "port", port, "reason", "filtered")
	}
}

// relay proxies bytes bidirectionally between the client (read via
// clientReader, written via client) and target. Unlike a plain "copy one
// direction in a goroutine, block on the other" loop, each direction
// half-closes (or, failing that, fully closes) its destination as soon as
// its source reaches EOF, propagating the hangup instead of leaving the
// other, still-blocked io.Copy waiting on a peer that will never speak
// again -- otherwise a client that stops sending (with no more data
// in-flight from the destination either) leaks the relay forever.
func (s *Server) relay(client net.Conn, clientReader io.Reader, target net.Conn) {
	defer target.Close()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		io.Copy(target, clientReader)
		closeWrite(target)
		close(done)
	}()
	io.Copy(client, target)
	closeWrite(client)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if cw.CloseWrite() == nil {
			return
		}
	}
	_ = c.Close()
}
