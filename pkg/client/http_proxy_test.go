package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/socks"
)

func startLocalHTTPProxy(t *testing.T, dial proxyDialFunc, target string) (string, context.CancelFunc, *localTunnel) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stats := &localTunnel{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			in, e := ln.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer in.Close()
				(&Connection{}).serveHTTPProxy(ctx, in, stats, tunnelProxyDialer{dial: dial, target: target})
			}()
		}
	}()
	t.Cleanup(func() { cancel(); ln.Close(); wg.Wait() })
	return ln.Addr().String(), cancel, stats
}
func proxyTestClient(address string) *http.Client {
	u, _ := url.Parse("http://" + address)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}
}

func TestHTTPProxy_ForwardStreamingTrailersAndKeepAlive(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Forwarded-For", "Forwarded", "X-Hop"} {
			if r.Header.Get(h) != "" {
				t.Errorf("leaked %s", h)
			}
		}
		if r.Header.Get("Accept-Encoding") != "" {
			t.Error("compression unexpectedly enabled")
		}
		body, _ := io.ReadAll(r.Body)
		if r.Trailer.Get("X-Upload") != "done" {
			t.Error("missing upload trailer")
		}
		w.Header().Set("Trailer", "X-Download")
		w.Write(body)
		w.Header().Set("X-Download", "done")
	}))
	defer upstream.Close()
	second := httptest.NewServer(upstream.Config.Handler)
	defer second.Close()
	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()
	addr, _, stats := startLocalHTTPProxy(t, (&net.Dialer{}).DialContext, socksServer.Addr())
	client := proxyTestClient(addr)
	defer client.CloseIdleConnections()
	client.Transport.(*http.Transport).DisableCompression = true
	for _, destination := range []string{upstream.URL, second.URL, upstream.URL} {
		req, _ := http.NewRequest("POST", destination, strings.NewReader(strings.Repeat("stream", 10000)))
		req.ContentLength = -1
		req.Trailer = http.Header{"X-Upload": []string{"done"}}
		req.Header.Set("Proxy-Authorization", "Basic secret")
		req.Header.Set("Connection", "X-Hop")
		req.Header.Set("X-Hop", "secret")
		req.Header.Set("Forwarded", "for=secret")
		req.Header.Set("X-Forwarded-For", "secret")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(b) != 60000 || resp.Trailer.Get("X-Download") != "done" {
			t.Fatalf("response bytes=%d trailer=%v err=%v", len(b), resp.Trailer, err)
		}
	}
	if socksServer.RequestCount() != 2 {
		t.Fatalf("no upstream reuse: %d", socksServer.RequestCount())
	}
	if stats.toTunnel.Load() < 120000 || stats.fromTunnel.Load() < 120000 {
		t.Fatal("missing byte accounting")
	}
}

func TestHTTPProxy_PreservesMethodAndRawQuery(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Method+" "+r.RequestURI)
	}))
	defer origin.Close()
	socksServer := startTestSOCKS5Server(t, "", "")
	defer socksServer.Close()
	addr, _, _ := startLocalHTTPProxy(t, (&net.Dialer{}).DialContext, socksServer.Addr())
	client := proxyTestClient(addr)
	defer client.CloseIdleConnections()
	for _, method := range []string{"GET", "PROPFIND", "MKCOL", "LOCK", "custom-method"} {
		t.Run(method, func(t *testing.T) {
			const path = "/?value=one;two&sig=abc&escaped=%2f%3B&duplicate=1&duplicate=2"
			req, err := http.NewRequest(method, origin.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK || string(body) != method+" "+path {
				t.Fatalf("status=%d body=%q err=%v", resp.StatusCode, body, err)
			}
		})
	}
}

func TestHTTPProxy_ValidationAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name, request string
		status        int
	}{
		{"origin", "GET / HTTP/1.1\r\nHost: example.com\r\n", 400},
		{"scheme", "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n", 400},
		{"port", "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n", 400},
		{"badPort", "CONNECT example.com:99999 HTTP/1.1\r\nHost: example.com\r\n", 400},
		{"unavailable", "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n", 502},
		{"oversized", "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Large: " + strings.Repeat("a", 70<<10) + "\r\n", 431},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, _, _ := startLocalHTTPProxy(t, func(context.Context, string, string) (net.Conn, error) {
				return nil, fmt.Errorf("private-address:123 secret")
			}, "captured:123")
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(conn, tc.request+"Connection: close\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.status || strings.Contains(string(body), "secret") {
				t.Fatalf("%d %s", resp.StatusCode, body)
			}
		})
	}
}

func TestHTTPProxy_TimeoutAndPendingDialCancellation(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			entered := make(chan struct{})
			exited := make(chan struct{})
			addr, cancel, _ := startLocalHTTPProxy(t, func(ctx context.Context, _, address string) (net.Conn, error) {
				if address != "captured:123" {
					t.Errorf("dial escaped tunnel: %s", address)
				}
				close(entered)
				defer close(exited)
				if timeout {
					return nil, context.DeadlineExceeded
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}, "captured:123")
			client := proxyTestClient(addr)
			defer client.CloseIdleConnections()
			done := make(chan struct{})
			go func() {
				defer close(done)
				resp, err := client.Get("http://destination.invalid/")
				if timeout {
					if err != nil {
						t.Error(err)
					} else {
						defer resp.Body.Close()
						if resp.StatusCode != 504 {
							t.Errorf("status %d", resp.StatusCode)
						}
					}
				}
			}()
			<-entered
			if !timeout {
				cancel()
			}
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("dial not canceled")
			}
			<-done
		})
	}
}

func TestHTTPProxy_CONNECTBufferedAndHalfClose(t *testing.T) {
	// A real SOCKS server verifies the relay's EOF behavior end to end.
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		conn, e := origin.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		b, _ := io.ReadAll(conn)
		conn.Write(append([]byte("reply:"), b...))
	}()
	srv, err := socks.New(socks.Config{Filter: socks.FilterConfig{AllowAll: true, AllowLocalEgress: true}, Authorize: func(context.Context, string, netip.Addr, uint16, string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()
	go func() {
		conn, e := sl.Accept()
		if e == nil {
			srv.ServeConn(context.Background(), conn)
		}
	}()
	addr, _, _ := startLocalHTTPProxy(t, (&net.Dialer{}).DialContext, sl.Addr().String())
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\npayload", origin.Addr(), origin.Addr())
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	conn.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(br)
	if err != nil || string(b) != "reply:payload" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestHTTPProxy_SniffFragmented(t *testing.T) {
	for _, input := range []string{"CONNECT ", "GET ", "POST ", "PROPFIND ", "MKCOL ", "LOCK ", "custom-method ", "\x05", "\x04", "opaque\x00", " "} {
		a, b := net.Pipe()
		go func() {
			defer a.Close()
			for _, c := range []byte(input) {
				if _, e := a.Write([]byte{c}); e != nil {
					return
				}
			}
		}()
		br := bufio.NewReader(b)
		got, err := isHTTPProxy(br)
		want := len(input) > 1 && strings.HasSuffix(input, " ")
		if err != nil || got != want {
			t.Fatalf("%q: %v %v", input, got, err)
		}
		first, _ := br.ReadByte()
		if first != input[0] {
			t.Fatal("sniff consumed input")
		}
		b.Close()
	}
}

func BenchmarkProxyDispatch(b *testing.B) {
	for _, input := range []string{"\x05\x01\x00", "CONNECT example.com:443 HTTP/1.1\r\n"} {
		b.Run(fmt.Sprintf("first_%d", input[0]), func(b *testing.B) {
			reader := strings.NewReader(input)
			br := bufio.NewReader(reader)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reader.Reset(input)
				br.Reset(reader)
				isHTTPProxy(br)
			}
		})
	}
}

func TestHTTPProxy_MixedWireGuardListener(t *testing.T) {
	serverStack, clientStack, serverIP := peeredClientServerStacks(t)
	target := net.JoinHostPort(serverIP.String(), "9101")
	ln, err := serverStack.Listen("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var denied atomic.Int32
	srv, err := socks.New(socks.Config{Filter: socks.FilterConfig{AllowAll: true, AllowLocalEgress: true}, Authorize: func(_ context.Context, _ string, _ netip.Addr, port uint16, _ string) bool {
		if port == 1 {
			denied.Add(1)
			return false
		}
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go srv.ServeConn(context.Background(), conn)
		}
	}()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	stop := make(chan struct{})
	defer close(stop)
	c := &Connection{Stack: clientStack, dataStop: stop}
	tunnel := &localTunnel{socks: true}
	go c.forward(tunnel, local, target)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "through WireGuard") }))
	defer origin.Close()
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "encrypted") }))
	defer tlsOrigin.Close()
	hc := proxyTestClient(local.Addr().String())
	defer hc.CloseIdleConnections()
	hc.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	for _, destination := range []string{origin.URL, tlsOrigin.URL, "http://127.0.0.1:1/"} {
		resp, e := hc.Get(destination)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		want := 200
		if strings.HasSuffix(destination, ":1/") {
			want = 502
		}
		if resp.StatusCode != want {
			t.Fatalf("%s: %d", destination, resp.StatusCode)
		}
	}
	d, _ := proxy.SOCKS5("tcp", local.Addr().String(), nil, proxy.Direct)
	conn, err := d.Dial("tcp", strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || denied.Load() != 1 {
		t.Fatalf("status=%d denied=%d", resp.StatusCode, denied.Load())
	}
	if tunnel.connections.Load() != 3 {
		t.Fatalf("accepted connections = %d", tunnel.connections.Load())
	}
}

func TestHTTPProxy_UpgradeAndDisconnect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw)
	}))
	defer origin.Close()
	s := startTestSOCKS5Server(t, "", "")
	defer s.Close()
	addr, cancel, _ := startLocalHTTPProxy(t, (&net.Dialer{}).DialContext, s.Addr())
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: ignored\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", origin.URL)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatal(resp.Status)
	}
	io.WriteString(conn, "hello")
	b := make([]byte, 5)
	if _, err = io.ReadFull(br, b); err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
	cancel()
	if _, err = br.ReadByte(); err == nil {
		t.Fatal("upgrade survived cancellation")
	}
}

func TestHTTPProxy_RemoteAuthority(t *testing.T) {
	for _, authority := range []string{"remote.invalid", "[2001:db8::7]:8080", "192.0.2.7:81"} {
		t.Run(authority, func(t *testing.T) {
			requested := make(chan string, 1)
			dial := func(ctx context.Context, _, address string) (net.Conn, error) {
				if address != "captured:123" {
					t.Errorf("unexpected tunnel address %q", address)
				}
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					buf := make([]byte, 3)
					io.ReadFull(b, buf)
					b.Write([]byte{5, 0})
					h := make([]byte, 4)
					io.ReadFull(b, h)
					var host string
					switch h[3] {
					case 1:
						buf = make([]byte, 4)
						io.ReadFull(b, buf)
						host = net.IP(buf).String()
					case 4:
						buf = make([]byte, 16)
						io.ReadFull(b, buf)
						host = net.IP(buf).String()
					case 3:
						io.ReadFull(b, buf[:1])
						n := int(buf[0])
						buf = make([]byte, n)
						io.ReadFull(b, buf)
						host = string(buf)
					}
					port := make([]byte, 2)
					io.ReadFull(b, port)
					requested <- net.JoinHostPort(host, fmt.Sprint(int(port[0])*256+int(port[1])))
					b.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
				}()
				return a, nil
			}
			addr, _, _ := startLocalHTTPProxy(t, dial, "captured:123")
			client := proxyTestClient(addr)
			defer client.CloseIdleConnections()
			resp, err := client.Get("http://" + authority + "/")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 502 {
				t.Fatal(resp.Status)
			}
			want := authority
			if authority == "remote.invalid" {
				want += ":80"
			}
			if got := <-requested; got != want {
				t.Fatalf("got %s want %s", got, want)
			}
		})
	}
}

func TestHTTPProxy_DisconnectIdleAndStreaming(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ready"))
				if streaming {
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}
			}))
			defer origin.Close()
			s := startTestSOCKS5Server(t, "", "")
			defer s.Close()
			addr, cancel, _ := startLocalHTTPProxy(t, (&net.Dialer{}).DialContext, s.Addr())
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: ignored\r\n\r\n", origin.URL)
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !streaming {
				io.ReadAll(resp.Body)
			}
			cancel()
			io.ReadAll(resp.Body)
			resp.Body.Close()
			if _, err := br.ReadByte(); err == nil {
				t.Fatal("connection survived cancellation")
			}
		})
	}
}

// Compare identical loopback SOCKS relays with and without sniffing, and HTTP
// CONNECT backed by the same SOCKS server. One-byte runs measure setup;
// 1 MiB runs reuse an established connection to measure sustained relay throughput.
// Use -benchtime=100x for setup runs to avoid exhausting ephemeral TCP ports.
func BenchmarkProxyRelay(b *testing.B) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			c, e := origin.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	srv, _ := socks.New(socks.Config{Filter: socks.FilterConfig{AllowAll: true, AllowLocalEgress: true}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer sl.Close()
	go func() {
		for {
			c, e := sl.Accept()
			if e != nil {
				return
			}
			go srv.ServeConn(context.Background(), c)
		}
	}()
	for _, mode := range []string{"socks_baseline", "socks_dispatch", "http_connect"} {
		for _, size := range []int{1, 1 << 20} {
			b.Run(fmt.Sprintf("%s/%d", mode, size), func(b *testing.B) {
				ln, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					b.Fatal(e)
				}
				defer ln.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() {
					for {
						in, e := ln.Accept()
						if e != nil {
							return
						}
						go func() {
							defer in.Close()
							br := bufio.NewReader(in)
							if mode != "socks_baseline" {
								isHTTPProxy(br)
							}
							buffered := &bufferedProxyConn{Conn: in, reader: br}
							if mode == "http_connect" {
								(&Connection{}).serveHTTPProxy(ctx, buffered, &localTunnel{}, tunnelProxyDialer{dial: (&net.Dialer{}).DialContext, target: sl.Addr().String()})
								return
							}
							out, e := net.Dial("tcp", sl.Addr().String())
							if e != nil {
								return
							}
							defer out.Close()
							relayProxy(out, buffered)
						}()
					}
				}()

				dialProxy := func() (net.Conn, io.Reader) {
					var conn net.Conn
					var reader io.Reader
					var err error
					if mode == "http_connect" {
						conn, err = net.Dial("tcp", ln.Addr().String())
						if err == nil {
							fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Addr(), origin.Addr())
							br := bufio.NewReader(conn)
							var response *http.Response
							response, err = http.ReadResponse(br, nil)
							if err == nil && response.StatusCode != 200 {
								err = fmt.Errorf("CONNECT: %s", response.Status)
							}
							reader = br
						}
					} else {
						d, _ := proxy.SOCKS5("tcp", ln.Addr().String(), nil, proxy.Direct)
						conn, err = d.Dial("tcp", origin.Addr().String())
						reader = conn
					}
					if err != nil {
						b.Fatal(err)
					}
					return conn, reader
				}
				var stream net.Conn
				var streamReader io.Reader
				if size > 1 {
					stream, streamReader = dialProxy()
					defer stream.Close()
				}
				payload := make([]byte, size)
				receive := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					conn, reader := stream, streamReader
					if size == 1 {
						conn, reader = dialProxy()
					}
					written := make(chan error, 1)
					go func() { _, e := conn.Write(payload); written <- e }()
					if _, e := io.ReadFull(reader, receive); e != nil {
						b.Fatal(e)
					}
					if e := <-written; e != nil {
						b.Fatal(e)
					}
					if size == 1 {
						conn.Close()
					}
				}
			})
		}
	}
}

func TestHTTPProxy_ReconnectUsesNewStack(t *testing.T) {
	oldServer, oldClient, oldIP := peeredClientServerStacks(t)
	newServer, newClient, newIP := peeredClientServerStacks(t)
	oldTarget, newTarget := net.JoinHostPort(oldIP.String(), "9120"), net.JoinHostPort(newIP.String(), "9121")
	oldListener, err := oldServer.Listen("tcp", oldTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer oldListener.Close()
	newListener, err := newServer.Listen("tcp", newTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer newListener.Close()
	var oldCalls, newCalls atomic.Int32
	for _, endpoint := range []struct {
		listener net.Listener
		calls    *atomic.Int32
	}{{oldListener, &oldCalls}, {newListener, &newCalls}} {
		srv, err := socks.New(socks.Config{Filter: socks.FilterConfig{AllowAll: true, AllowLocalEgress: true}, Authorize: func(context.Context, string, netip.Addr, uint16, string) bool { endpoint.calls.Add(1); return true }})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				conn, e := endpoint.listener.Accept()
				if e != nil {
					return
				}
				go srv.ServeConn(context.Background(), conn)
			}
		}()
	}
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	c := &Connection{Stack: oldClient, dataStop: make(chan struct{})}
	defer func() { close(c.dataStop) }()
	tunnel := &localTunnel{socks: true, target: oldTarget}
	go c.forward(tunnel, local, oldTarget)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	conn, err := net.Dial("tcp", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: ignored\r\n\r\n", origin.URL)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c.mu.Lock()
	close(c.dataStop)
	c.dataStop = make(chan struct{})
	c.Stack = newClient
	tunnel.target = newTarget
	c.mu.Unlock()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("old connection survived reconnect")
	}
	client := proxyTestClient(local.Addr().String())
	defer client.CloseIdleConnections()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(origin.URL)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != 200 {
				t.Error(resp.Status)
			}
		}()
	}
	wg.Wait()
	if oldCalls.Load() != 1 || newCalls.Load() == 0 {
		t.Fatalf("old/new SOCKS calls: %d/%d", oldCalls.Load(), newCalls.Load())
	}
}
