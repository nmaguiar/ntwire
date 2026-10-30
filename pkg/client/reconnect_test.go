package client

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
)

func TestReconnectRestoresForwardedTraffic(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		oldUDP, newUDP, oldMP, newMP bool
	}{
		{"udp", true, true, false, false},
		{"websocket", false, false, false, false},
		{"udp_to_websocket", true, false, false, false},
		{"websocket_to_udp", false, true, false, false},
		{"enable_multipath", true, true, false, true},
		{"disable_multipath", true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReconnectFixture(t)
			first := f.startServer("100.70.0.0/24", 18080, tc.oldUDP, tc.oldMP)
			f.current.Store(first)
			c := f.connect()
			oldStack, oldKey, oldStop := c.Stack, c.Stack.PublicKey(), c.dataStop
			addresses := append([]string(nil), c.LocalAddresses...)
			tcpRoundTrip(t, addresses[0])
			udp, err := net.Dial("udp", addresses[1])
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			udpRoundTrip(t, udp)
			first.Close()
			second := f.startServer("100.70.1.0/24", 19080, tc.newUDP, tc.newMP)
			f.current.Store(second)
			if err := c.renew(); err == nil {
				t.Fatal("replacement server accepted old session")
			}
			if err := c.reconnect(); err != nil {
				t.Fatal(err)
			}
			if c.Stack == oldStack {
				t.Fatal("stale stack retained")
			}
			if c.Stack.PublicKey() != oldKey {
				t.Fatal("client identity changed")
			}
			select {
			case <-oldStop:
			default:
				t.Fatal("old transport generation still active")
			}
			if len(c.LocalAddresses) != 2 || c.LocalAddresses[0] != addresses[0] || c.LocalAddresses[1] != addresses[1] {
				t.Fatalf("listener addresses changed: %v", c.LocalAddresses)
			}
			if c.Response.TunnelIP != "100.70.1.2" {
				t.Fatalf("wrong new address: %s", c.Response.TunnelIP)
			}
			if _, found, err := c.Stack.PeerEndpoint(c.Response.ServerPublicKey); err != nil || !found {
				t.Fatalf("new server peer absent: %v", err)
			}
			tcpRoundTrip(t, addresses[0])
			udpRoundTrip(t, udp)
			// Reauthentication without changed network state preserves live flows.
			stable := c.Stack
			if err := c.reconnect(); err != nil {
				t.Fatal(err)
			}
			if c.Stack != stable {
				t.Fatal("unchanged network unnecessarily replaced")
			}
			tcpRoundTrip(t, addresses[0])
			udpRoundTrip(t, udp)
		})
	}
}

func TestReconnectFailureDoesNotPublishIncompleteState(t *testing.T) {
	f := newReconnectFixture(t)
	f.current.Store(f.startServer("100.70.0.0/24", 18080, true, false))
	c := f.connect()
	old, token := c.Stack, c.token
	response := c.Response
	response.TunnelIP, response.Token = "invalid", "uncommitted"
	if err := c.applyReconnectedSession(authResult{response: response, method: "ssh"}); err == nil {
		t.Fatal("invalid network accepted")
	}
	if c.Stack != old || c.token != token {
		t.Fatal("failed rebuild published new state")
	}
	tcpRoundTrip(t, c.LocalAddresses[0])
}

type reconnectRoundTripper struct {
	base             http.RoundTripper
	entered, release chan struct{}
}

func (r *reconnectRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/v1/auth" {
		close(r.entered)
		<-r.release
	}
	return r.base.RoundTrip(req)
}

func TestReconnectCannotRestoreStateAfterClose(t *testing.T) {
	f := newReconnectFixture(t)
	f.current.Store(f.startServer("100.70.0.0/24", 18080, true, false))
	c := f.connect()
	transport := &reconnectRoundTripper{base: c.http.Transport, entered: make(chan struct{}), release: make(chan struct{})}
	c.http.Transport = transport
	done := make(chan error, 1)
	go func() { done <- c.reconnect() }()
	<-transport.entered
	c.Close()
	close(transport.release)
	if err := <-done; err == nil {
		t.Fatal("reconnect after close succeeded")
	}
	if c.State().Connected || len(c.State().Tunnels) != 0 {
		t.Fatal("closed connection was resurrected")
	}
}

func TestReconnectReconcilesTunnelGrants(t *testing.T) {
	f := newReconnectFixture(t)
	f.current.Store(f.startServer("100.70.0.0/24", 18080, true, false))
	c := f.connect()
	oldTCP, oldUDP := c.LocalAddresses[0], c.LocalAddresses[1]
	response := c.Response
	// Keep the UDP listener, remove TCP, and create a new granted listener.
	response.Tunnels = []protocol.Tunnel{response.Tunnels[1], {Name: "added", VirtualPort: 18080}}
	if err := c.applyReconnectedSession(authResult{response: response, method: "ssh"}); err != nil {
		t.Fatal(err)
	}
	if c.LocalAddresses[0] != oldUDP {
		t.Fatal("unchanged UDP listener moved")
	}
	if conn, err := net.DialTimeout("tcp", oldTCP, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("removed listener remains open")
	}
	tcpRoundTrip(t, c.LocalAddresses[1])
	// A protocol change retains the requested local address on the other protocol.
	address := c.LocalAddresses[1]
	response.Tunnels[1].Protocol = "udp"
	response.Tunnels[1].VirtualPort = 18081
	if err := c.applyReconnectedSession(authResult{response: response, method: "ssh"}); err != nil {
		t.Fatal(err)
	}
	if c.LocalAddresses[1] != address {
		t.Fatal("protocol change moved local address")
	}
	udp, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpRoundTrip(t, udp)
}

type reconnectFixture struct {
	t                                       *testing.T
	current                                 atomic.Pointer[server.Server]
	http                                    *httptest.Server
	key, keysDir, dir, tcpTarget, udpTarget string
}

func newReconnectFixture(t *testing.T) *reconnectFixture {
	t.Helper()
	f := &reconnectFixture{t: t, dir: t.TempDir(), keysDir: t.TempDir()}
	f.key = filepath.Join(f.dir, "identity")
	if _, err := sshkey.GenerateIdentityFile(f.key); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(f.key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.keysDir, "test.pub"), pub, 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.tcpTarget = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.udpTarget = pc.LocalAddr().String()
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], addr)
		}
	}()
	f.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.current.Load().Handler().ServeHTTP(w, r) }))
	t.Cleanup(f.http.Close)
	return f
}

func (f *reconnectFixture) startServer(cidr string, port int, udp, multipath bool) *server.Server {
	f.t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	address := pc.LocalAddr().String()
	_ = pc.Close()
	cfg := server.Config{}
	cfg.Auth.AuthorizedKeysDir, cfg.Auth.SessionTTL = f.keysDir, time.Hour
	cfg.Network.TunnelCIDR, cfg.Listen.WireGuard = cidr, address
	if udp {
		cfg.Network.AdvertisedEndpoint = address
	}
	cfg.Transport.Multipath = &multipath
	cfg.Tunnels = []server.TunnelConfig{
		{Name: "tcp", Target: f.tcpTarget, VirtualPort: port, Allow: []string{"*"}},
		{Name: "udp", Target: f.udpTarget, VirtualPort: port + 1, Protocol: "udp", Allow: []string{"*"}},
	}
	s := server.New(cfg, slog.New(slog.DiscardHandler))
	if err := s.StartDataPlane(); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(s.Close)
	return s
}

func (f *reconnectFixture) connect() *Connection {
	f.t.Helper()
	c, err := ConnectWithOptions(f.http.URL, f.key, protocol.ClientInfo{}, Options{NoWebUI: true, NoDirectUpgrade: true, NoSystemProxy: true, StatusFile: filepath.Join(f.dir, "status.json"), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(c.Close)
	return c
}

func tcpRoundTrip(t *testing.T, address string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("reconnect-" + strconv.FormatInt(time.Now().UnixNano(), 10))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("TCP response %q", got)
	}
}

func udpRoundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("udp-reconnect-" + strconv.FormatInt(time.Now().UnixNano(), 10))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2048)
	n, err := c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:n], msg) {
		t.Fatalf("UDP response %q", b[:n])
	}
}
