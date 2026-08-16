package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

func TestSelectTransport(t *testing.T) {
	cases := []struct {
		name     string
		explicit bool
		udp      string
		ws       string
		wantWS   bool
		wantErr  bool
	}{
		{"direct server, UDP only", false, "vpn.example:51820", "", false, false},
		{"direct server, both endpoints, UDP preferred", false, "vpn.example:51820", "wss://vpn.example/v1/wg", false, false},
		{"relay-only server auto-selects websocket", false, "", "wss://home.relay.example/v1/wg", true, false},
		{"explicit --websocket overrides UDP availability", true, "vpn.example:51820", "wss://vpn.example/v1/wg", true, false},
		{"explicit --websocket with no websocket endpoint errors", true, "vpn.example:51820", "", false, true},
		{"neither endpoint advertised errors", false, "", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectTransport(tc.explicit, tc.udp, tc.ws)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantWS {
				t.Fatalf("useWS = %v, want %v", got, tc.wantWS)
			}
		})
	}
}

func TestValidateAuthResponseCapabilities(t *testing.T) {
	if err := validateAuthResponseCapabilities(protocol.AuthResponse{TransportCapabilities: []string{"future-transport"}}); err != nil {
		t.Fatalf("unknown optional transport capability should be ignored: %v", err)
	}
	if err := validateAuthResponseCapabilities(protocol.AuthResponse{RequiredTransportCapabilities: []string{"future-transport"}}); err == nil {
		t.Fatal("unknown required transport capability should fail")
	}
}

func TestInitialTransport(t *testing.T) {
	cases := []struct {
		name  string
		useWS bool
		udp   string
		want  string
	}{
		{"direct UDP", false, "vpn.example:51820", "UDP direct"},
		{"WebSocket fallback", true, "vpn.example:51820", "WSS fallback"},
		{"relay WebSocket", true, "", "WSS through relay"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := initialTransport(tc.useWS, tc.udp).String(); got != tc.want {
				t.Fatalf("initialTransport(%t, %q) = %q, want %q", tc.useWS, tc.udp, got, tc.want)
			}
		})
	}
}

func TestInitialTransportState(t *testing.T) {
	cases := []struct {
		name  string
		useWS bool
		udp   string
		want  transportState
	}{
		{"direct UDP", false, "vpn.example:51820", transportStateDirect},
		{"WebSocket fallback", true, "vpn.example:51820", transportStateWSSFallback},
		{"relay WebSocket", true, "", transportStateWSSRelay},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := initialTransportState(tc.useWS, tc.udp); got != tc.want {
				t.Fatalf("initialTransportState(%t, %q) = %v, want %v", tc.useWS, tc.udp, got, tc.want)
			}
		})
	}
}

func TestTransportStateTransitions(t *testing.T) {
	cases := []struct {
		name           string
		current        transportState
		event          transportTransition
		relayAvailable bool
		want           transportState
	}{
		{"upgrade WSS to UDP relay", transportStateWSSRelay, transportUDPRelayEstablished, false, transportStateUDPRelay},
		{"upgrade WSS directly when relay tier unavailable", transportStateWSSRelay, transportDirectEstablished, false, transportStateDirectViaRelayReflector},
		{"upgrade UDP relay to direct", transportStateUDPRelay, transportDirectEstablished, true, transportStateDirectViaRelayReflector},
		{"UDP relay loss falls back to WSS", transportStateUDPRelay, transportUDPRelayLost, false, transportStateWSSRelay},
		{"direct loss steps down to warm UDP relay", transportStateDirectViaRelayReflector, transportDirectLost, true, transportStateUDPRelay},
		{"direct loss falls back to WSS", transportStateDirectViaRelayReflector, transportDirectLost, false, transportStateWSSRelay},
		{"control reconnect preserves direct route", transportStateDirect, transportControlReconnected, true, transportStateDirect},
		{"shutdown clears route", transportStateUDPRelay, transportShutdown, true, transportStateStopped},
		{"invalid direct loss from WSS is ignored", transportStateWSSRelay, transportDirectLost, false, transportStateWSSRelay},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextTransportState(tc.current, tc.event, tc.relayAvailable); got != tc.want {
				t.Fatalf("nextTransportState(%v, %v, %t) = %v, want %v", tc.current, tc.event, tc.relayAvailable, got, tc.want)
			}
		})
	}
}

func TestProxyFunc(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://server.example/v1/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := proxyFunc(Options{HTTPSProxy: "https://proxy.example:8443"})
	if err != nil {
		t.Fatalf("proxyFunc() error = %v", err)
	}
	u, err := proxy(req)
	if err != nil || u.String() != "https://proxy.example:8443" {
		t.Fatalf("explicit proxy = %v, %v", u, err)
	}

	proxy, err = proxyFunc(Options{HTTPSProxy: "https://proxy.example:8443", NoSystemProxy: true})
	if err != nil {
		t.Fatalf("proxyFunc(explicit, no system) error = %v", err)
	}
	u, err = proxy(req)
	if err != nil || u == nil {
		t.Fatalf("explicit proxy did not take precedence: %v, %v", u, err)
	}

	proxy, err = proxyFunc(Options{NoSystemProxy: true})
	if err != nil {
		t.Fatalf("proxyFunc(no system) error = %v", err)
	}
	if proxy != nil {
		t.Fatal("no-system-proxy returned a proxy function")
	}
}

func TestProxyFuncRejectsInvalidProxyURL(t *testing.T) {
	for _, proxy := range []string{"proxy.example:8080", "socks5://proxy.example:1080", "https:///missing-host"} {
		if _, err := proxyFunc(Options{HTTPSProxy: proxy}); err == nil {
			t.Errorf("proxyFunc(%q) accepted an invalid proxy URL", proxy)
		}
	}
}

func TestResolveServerTunnelIP(t *testing.T) {
	cases := []struct {
		name           string
		serverTunnelIP string
		clientIP       string
		want           string
		wantErr        bool
	}{
		{"field present, IPv4", "100.64.0.1", "100.64.0.5", "100.64.0.1", false},
		{"field present, IPv6", "fd00:ac1d::1", "fd00:ac1d::5", "fd00:ac1d::1", false},
		{"field present but invalid", "not-an-ip", "100.64.0.5", "", true},
		{"field absent, IPv4 falls back to legacy host-.1 derivation", "", "100.64.0.5", "100.64.0.1", false},
		{"field absent, IPv6 has no legacy fallback", "", "fd00:ac1d::5", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientIP, err := netip.ParseAddr(tc.clientIP)
			if err != nil {
				t.Fatalf("test setup: invalid clientIP %q: %v", tc.clientIP, err)
			}
			got, err := resolveServerTunnelIP(tc.serverTunnelIP, clientIP)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tc.want {
				t.Fatalf("resolveServerTunnelIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAllowedIPsForFamily(t *testing.T) {
	cases := []struct {
		clientIP string
		want     string
	}{
		{"100.64.0.5", "0.0.0.0/0"},
		{"fd00:ac1d::5", "::/0"},
	}
	for _, tc := range cases {
		clientIP, err := netip.ParseAddr(tc.clientIP)
		if err != nil {
			t.Fatalf("test setup: invalid clientIP %q: %v", tc.clientIP, err)
		}
		if got := allowedIPsForFamily(clientIP); got != tc.want {
			t.Fatalf("allowedIPsForFamily(%q) = %q, want %q", tc.clientIP, got, tc.want)
		}
	}
}

func TestTrustServerPersistsPin(t *testing.T) {
	path := t.TempDir() + "/known_servers"
	if err := TrustServer(path, "server.example:8443", "SHA256:example"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "server.example:8443") || !strings.Contains(string(b), "SHA256:example") {
		t.Fatalf("pin was not persisted: %s", b)
	}
}

func TestReplacePortSwitchesLocalListener(t *testing.T) {
	old, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit loopback listeners")
		}
		t.Fatal(err)
	}
	defer old.Close()
	c := &Connection{
		Stack:          &wgnet.Stack{},
		tunnels:        []*localTunnel{{name: "database", listener: old, localAddr: old.Addr().String()}},
		LocalAddresses: []string{old.Addr().String()},
		statusFile:     t.TempDir() + "/status.json",
		bindAddr:       "127.0.0.1",
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	got, err := c.ReplacePort("database", port)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, ":"+strconv.Itoa(port)) || c.LocalAddresses[0] != got {
		t.Fatalf("replacement address = %q, addresses = %#v", got, c.LocalAddresses)
	}
	if _, err := net.Dial("tcp", got); err != nil {
		t.Fatalf("new listener is not accepting: %v", err)
	}
	if _, err := net.Dial("tcp", old.Addr().String()); err == nil {
		t.Fatal("old listener still accepts connections")
	}
	_ = c.tunnels[0].listener.Close()
}

// TestReplaceListenerHostOnlyChangeIsNotANoOp guards against ReplaceListener
// treating a host-only change as a no-op because it only compared ports:
// an empty host must default to the tunnel's *current* bound host, not
// c.bindAddr, and a same-port different-host request must actually rebind.
func TestReplaceListenerHostOnlyChangeIsNotANoOp(t *testing.T) {
	old, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit loopback listeners")
		}
		t.Fatal(err)
	}
	defer old.Close()
	port := old.Addr().(*net.TCPAddr).Port
	c := &Connection{
		Stack:          &wgnet.Stack{},
		tunnels:        []*localTunnel{{name: "database", listener: old, localAddr: old.Addr().String()}},
		LocalAddresses: []string{old.Addr().String()},
		statusFile:     t.TempDir() + "/status.json",
		// A non-loopback bindAddr that must NOT leak into the replacement
		// when host is left empty -- otherwise a port-only change would
		// silently relocate the tunnel back to this address.
		bindAddr: "0.0.0.0",
	}

	// Same port, no host given: must be a true no-op against the tunnel's
	// actual current host (127.0.0.1), not bindAddr.
	got, err := c.ReplaceListener("database", "", port)
	if err != nil {
		t.Fatal(err)
	}
	if got != old.Addr().String() {
		t.Fatalf("no-op replacement = %q, want unchanged %q", got, old.Addr().String())
	}

	// Same port number, different address family (::1 instead of
	// 127.0.0.1): must actually rebind, not be mistaken for a no-op
	// because the port half of localAddr matches.
	got, err = c.ReplaceListener("database", "::1", port)
	if err != nil {
		t.Fatal(err)
	}
	want := net.JoinHostPort("::1", strconv.Itoa(port))
	if got != want {
		t.Fatalf("host-only replacement = %q, want %q", got, want)
	}
	if _, err := net.Dial("tcp", got); err != nil {
		t.Fatalf("new listener is not accepting after host-only replacement: %v", err)
	}
	if _, err := net.Dial("tcp", old.Addr().String()); err == nil {
		t.Fatal("old 127.0.0.1 listener still accepts connections after a host-only replacement")
	}
	_ = c.tunnels[0].listener.Close()
}

func TestResolveBindAddress(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty defaults to loopback", in: "", want: "127.0.0.1"},
		{name: "wildcard", in: "0.0.0.0", want: "0.0.0.0"},
		{name: "specific interface", in: "192.168.1.5", want: "192.168.1.5"},
		{name: "ipv6 loopback", in: "::1", want: "::1"},
		{name: "ipv6 wildcard", in: "::", want: "::"},
		{name: "hostname rejected", in: "localhost", wantErr: true},
		{name: "garbage rejected", in: "not-an-ip", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveBindAddress(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("resolveBindAddress(%q) = %q, nil; want an error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveBindAddress(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("resolveBindAddress(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestResolveTunnelHost(t *testing.T) {
	cases := []struct {
		name            string
		serverLocalHost string
		hosts           map[string]string
		explicitBind    bool
		bindAddr        string
		wantHost        string
		wantSoft        bool
		wantRejected    string
	}{
		{
			name:     "no overrides, no server suggestion: bindAddr default",
			bindAddr: "127.0.0.1",
			wantHost: "127.0.0.1", wantSoft: true,
		},
		{
			name:            "server local_host wins over bindAddr default",
			serverLocalHost: "127.70.0.1",
			bindAddr:        "127.0.0.1",
			wantHost:        "127.70.0.1", wantSoft: true,
		},
		{
			name:         "explicit --bind wins over server local_host",
			explicitBind: true,
			bindAddr:     "0.0.0.0",
			wantHost:     "0.0.0.0", wantSoft: false,
		},
		{
			name:            "explicit client host wins over --bind and server local_host",
			hosts:           map[string]string{"db": "127.71.0.1"},
			serverLocalHost: "127.70.0.1",
			explicitBind:    true,
			bindAddr:        "0.0.0.0",
			wantHost:        "127.71.0.1", wantSoft: true,
		},
		{
			name:            "non-loopback server local_host is rejected and falls back to bindAddr",
			serverLocalHost: "10.0.0.5",
			bindAddr:        "127.0.0.1",
			wantHost:        "127.0.0.1", wantSoft: true,
			wantRejected: "10.0.0.5",
		},
		{
			name:            "server local_host that fails to parse is rejected",
			serverLocalHost: "not-an-ip",
			bindAddr:        "127.0.0.1",
			wantHost:        "127.0.0.1", wantSoft: true,
			wantRejected: "not-an-ip",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, soft, rejected := resolveTunnelHost("db", c.serverLocalHost, c.hosts, c.explicitBind, c.bindAddr)
			if host != c.wantHost || soft != c.wantSoft || rejected != c.wantRejected {
				t.Fatalf("resolveTunnelHost() = (%q, %v, %q), want (%q, %v, %q)",
					host, soft, rejected, c.wantHost, c.wantSoft, c.wantRejected)
			}
		})
	}
}

func TestListenLocalUsesConfiguredPortAndFallsBackWhenOccupied(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit loopback listeners")
		}
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	l, firstErr, err := listenLocal("127.0.0.1", port, false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if firstErr != nil {
		t.Fatalf("firstErr = %v, want nil for an unoccupied configured port", firstErr)
	}
	if got := l.Addr().(*net.TCPAddr).Port; got != port {
		t.Fatalf("configured port = %d, want %d", got, port)
	}
	_ = l.Close()

	occupied, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	l, firstErr, err = listenLocal("127.0.0.1", port, false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if firstErr == nil {
		t.Fatal("firstErr = nil, want the occupied-port error to be reported for logging")
	}
	if got := l.Addr().(*net.TCPAddr).Port; got == port {
		t.Fatalf("fallback retained occupied port %d", port)
	}
}

// TestListenLocalHardPortDoesNotFallBack checks that a strict (client
// --port) port mapping never falls back to an ephemeral port: its failure
// must abort the connect, not silently move the tunnel.
func TestListenLocalHardPortDoesNotFallBack(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit loopback listeners")
		}
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	l, _, err := listenLocal("127.0.0.1", port, false, false, nil)
	if err == nil {
		_ = l.Close()
		t.Fatal("listenLocal(softPort=false) on an occupied port = nil error, want the bind error returned as-is")
	}
}

// TestListenLocalSoftHostFallsBackToLoopback exercises the platform-
// independent half of the fallback chain that a real CI machine can't:
// binding a non-127.0.0.1 loopback alias (e.g. 127.70.0.1) only works on
// Linux, so this injects a listen func that rejects any other address and
// delegates to the real net.Listen for 127.0.0.1, letting each step of the
// chain be forced deterministically by occupying (or freeing) real ports.
func TestListenLocalSoftHostFallsBackToLoopback(t *testing.T) {
	onlyLoopback := func(network, address string) (net.Listener, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if host != "127.0.0.1" {
			return nil, fmt.Errorf("simulated: cannot assign requested address")
		}
		return net.Listen(network, address)
	}

	t.Run("soft host, soft port falls back past an occupied fallback port to 127.0.0.1:0", func(t *testing.T) {
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skip("sandbox does not permit loopback listeners")
			}
			t.Fatal(err)
		}
		defer occupied.Close()
		port := occupied.Addr().(*net.TCPAddr).Port

		l, firstErr, err := listenLocal("127.70.0.1", port, true, true, onlyLoopback)
		if err != nil {
			t.Fatalf("listenLocal() error = %v", err)
		}
		defer l.Close()
		if firstErr == nil {
			t.Fatal("firstErr = nil, want the initial 127.70.0.1 failure reported")
		}
		addr := l.Addr().(*net.TCPAddr)
		if addr.IP.String() != "127.0.0.1" {
			t.Fatalf("bound host = %q, want 127.0.0.1", addr.IP)
		}
		if addr.Port == port {
			t.Fatalf("bound port = %d, want a different (ephemeral) port since %d was occupied on 127.0.0.1 too", addr.Port, port)
		}
	})

	t.Run("soft host, hard port keeps the exact port on the fallback host", func(t *testing.T) {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()

		l, firstErr, err := listenLocal("127.70.0.1", port, true, false, onlyLoopback)
		if err != nil {
			t.Fatalf("listenLocal() error = %v", err)
		}
		defer l.Close()
		if firstErr == nil {
			t.Fatal("firstErr = nil, want the initial 127.70.0.1 failure reported")
		}
		addr := l.Addr().(*net.TCPAddr)
		if addr.IP.String() != "127.0.0.1" || addr.Port != port {
			t.Fatalf("bound = %s, want 127.0.0.1:%d (host softened, port held exact)", addr, port)
		}
	})

	t.Run("hard port with no free fallback host:port fails outright", func(t *testing.T) {
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		port := occupied.Addr().(*net.TCPAddr).Port

		_, _, err = listenLocal("127.70.0.1", port, true, false, onlyLoopback)
		if err == nil {
			t.Fatal("listenLocal() = nil error, want failure: the hard port is occupied on the only fallback host too")
		}
	})

	t.Run("hard host does not fall back", func(t *testing.T) {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()

		_, _, err = listenLocal("127.70.0.1", port, false, true, onlyLoopback)
		if err == nil {
			t.Fatal("listenLocal(softHost=false) = nil error, want the 127.70.0.1 failure returned as-is")
		}
	})
}

func TestStatusRoundTrip(t *testing.T) {
	path := t.TempDir() + "/status.json"
	want := Status{PID: 42, Server: "https://server.example", UIURL: "http://127.0.0.1:1234/?token=x", LocalAddresses: []string{"127.0.0.1:2345"}}
	if err := writeStatus(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != want.PID || got.Server != want.Server || len(got.LocalAddresses) != 1 {
		t.Fatalf("unexpected status: %#v", got)
	}
}

func TestCountingWriterUpdatesTunnelStatsWhileStreaming(t *testing.T) {
	tunnel := &localTunnel{}
	var outgoing, incoming bytes.Buffer
	if _, err := (countingWriter{w: &outgoing, counter: &tunnel.toTunnel}).Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if _, err := (countingWriter{w: &incoming, counter: &tunnel.fromTunnel}).Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	got := tunnel.stats()
	if got.BytesToTunnel != uint64(len("request")) || got.BytesFromTunnel != uint64(len("response")) {
		t.Fatalf("stats = %#v, want request and response byte counts", got)
	}
}

// Local listeners keep their creation order while Connection.Response is
// replaced wholesale on renew, so status and instructions must be paired with
// their grant by name: pairing by position would show one tunnel the setup
// commands -- and the loopback port -- of another.
func TestWebViewsPairGrantsByNameNotPosition(t *testing.T) {
	c := &Connection{
		Response: protocol.AuthResponse{
			TunnelIP:       "10.90.0.7",
			ServerTunnelIP: "10.90.0.1",
			// Reverse order, as a renew that dropped and re-added a grant leaves it.
			Tunnels: []protocol.Tunnel{
				{Name: "reports", Description: "reporting", DocsURL: "https://example.com/reports",
					Instructions: "run `curl http://{{.LocalHost}}:{{.LocalPort}}/`"},
				{Name: "database", Description: "postgres", DocsURL: "javascript:alert(1)"},
			},
		},
		tunnels: []*localTunnel{
			{name: "database", virtualPort: 15432, localAddr: "127.0.0.1:55432"},
			{name: "reports", virtualPort: 18080, localAddr: "127.0.0.1:58080"},
		},
		base: "https://ntwire.example:8443",
	}
	status := c.webStatus()
	if status.Tunnels[0].Description != "postgres" || status.Tunnels[1].Description != "reporting" {
		t.Fatalf("descriptions paired by position: %+v", status.Tunnels)
	}

	got := c.webInstructions().Tunnels
	// database has no instructions and an unusable docs_url, so it is omitted.
	if len(got) != 1 || got[0].Name != "reports" {
		t.Fatalf("instructions = %+v, want only reports", got)
	}
	if got[0].DocsURL != "https://example.com/reports" {
		t.Fatalf("docs URL = %q", got[0].DocsURL)
	}
	if len(got[0].Blocks) != 1 || len(got[0].Blocks[0].Spans) != 2 {
		t.Fatalf("blocks = %+v", got[0].Blocks)
	}
	if code := got[0].Blocks[0].Spans[1]; code.Text != "curl http://127.0.0.1:58080/" {
		t.Fatalf("rendered command = %q, want the reports listener's port", code.Text)
	}
}

// A tunnel started with --bind pointed at a wildcard address reports that
// literal address (e.g. 0.0.0.0:58080) in its status, but instructions must
// still render a dialable loopback address -- 0.0.0.0 is not something a
// copy-pasted curl command can connect to, and is an outright invalid
// connect target on Windows.
func TestWebInstructionsSubstituteLoopbackForWildcardBind(t *testing.T) {
	c := &Connection{
		Response: protocol.AuthResponse{
			Tunnels: []protocol.Tunnel{
				{Name: "reports", Instructions: "run `curl http://{{.LocalHost}}:{{.LocalPort}}/ via {{.LocalAddress}}`"},
			},
		},
		tunnels: []*localTunnel{{name: "reports", virtualPort: 18080, localAddr: "0.0.0.0:58080"}},
		base:    "https://ntwire.example:8443",
	}
	got := c.webInstructions().Tunnels
	if len(got) != 1 {
		t.Fatalf("instructions = %+v, want one tunnel", got)
	}
	if len(got[0].Blocks) != 1 || len(got[0].Blocks[0].Spans) != 2 {
		t.Fatalf("blocks = %+v", got[0].Blocks)
	}
	want := "curl http://127.0.0.1:58080/ via 127.0.0.1:58080"
	if code := got[0].Blocks[0].Spans[1]; code.Text != want {
		t.Fatalf("rendered command = %q, want %q (wildcard bind substituted with loopback)", code.Text, want)
	}
}

// A renewal response repeats neither the tunnel address nor the server key --
// the session keeps the ones it already has -- so renew() must not zero them
// out of Connection.Response, which the status UI and instruction templates
// read the client's addressing from.
func TestRenewKeepsAddressingFromPreviousResponse(t *testing.T) {
	renewed := protocol.AuthResponse{SessionID: "s2", Token: "t2", TTLSeconds: 900,
		Tunnels: []protocol.Tunnel{{Name: "reports", VirtualPort: 18080}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/renew" {
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(renewed)
	}))
	defer srv.Close()

	c := &Connection{
		Response: protocol.AuthResponse{SessionID: "s1", Token: "t1",
			TunnelIP: "10.90.0.7", ServerTunnelIP: "10.90.0.1", ServerPublicKey: "abc="},
		base: srv.URL, http: srv.Client(),
	}
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	if c.Response.SessionID != "s2" || c.token != "t2" {
		t.Fatalf("renewal not applied: %+v", c.Response)
	}
	if c.Response.TunnelIP != "10.90.0.7" || c.Response.ServerTunnelIP != "10.90.0.1" || c.Response.ServerPublicKey != "abc=" {
		t.Fatalf("addressing lost on renew: %+v", c.Response)
	}
}

func TestDisplayNameFallsBackToHostPortWhenServerNameUnset(t *testing.T) {
	c := &Connection{base: "https://localhost:8443"}
	if got := c.DisplayName(); got != "localhost:8443" {
		t.Fatalf("DisplayName() = %q, want host:port fallback", got)
	}
	c.Response.ServerName = "home"
	if got := c.DisplayName(); got != "home" {
		t.Fatalf("DisplayName() = %q, want configured server name", got)
	}
}

// TestStatusMatchesWebStatus checks that the exported Status accessor --
// added so a caller on another goroutine, such as a GUI, has a race-free way
// to read a Connection's live state instead of reading Response/
// LocalAddresses directly -- returns exactly what the unexported webStatus
// (served at GET /status) does.
func TestStatusMatchesWebStatus(t *testing.T) {
	c := &Connection{
		Response: protocol.AuthResponse{TTLSeconds: 42},
		base:     "https://ntwire.example:8443",
	}
	if got, want := c.Status(), c.webStatus(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Status() = %+v, want %+v (webStatus())", got, want)
	}
}

func TestWebStatusReportsLiveConnectionTransport(t *testing.T) {
	c := &Connection{}
	c.transport.Store(uint32(transportUDPRelayReflector))
	if got := c.webStatus().ConnectionType; got != "UDP direct via relay reflector" {
		t.Fatalf("ConnectionType = %q", got)
	}
}

// TestInstructionsMatchesWebInstructions is Instructions' equivalent of
// TestStatusMatchesWebStatus.
func TestInstructionsMatchesWebInstructions(t *testing.T) {
	c := &Connection{
		Response: protocol.AuthResponse{Tunnels: []protocol.Tunnel{
			{Name: "reports", DocsURL: "https://example.com/reports"},
		}},
		tunnels: []*localTunnel{{name: "reports", virtualPort: 18080, localAddr: "127.0.0.1:58080"}},
	}
	got, want := c.Instructions(), c.webInstructions()
	if len(got.Tunnels) != len(want.Tunnels) || len(got.Tunnels) != 1 || got.Tunnels[0].Name != want.Tunnels[0].Name {
		t.Fatalf("Instructions() = %+v, want %+v (webInstructions())", got, want)
	}
}

// TestRenewLoopFiresEvents drives a real renewLoop against a mock control
// plane that fails once, then succeeds, and checks that Options.OnEvent
// observes exactly the transitions a subscriber (a GUI connection manager)
// needs to render "reconnecting" -> "reconnected" state: a failed renewal
// enters backoff (EventReconnecting), the retry that recovers announces both
// that it recovered (EventReconnected) and that the session was renewed
// (EventRenewed, which also fires on every routine renewal with no failures
// at all -- not exercised by the failure path alone).
func TestRenewLoopFiresEvents(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.AuthResponse{Token: "t2", TTLSeconds: 900})
	}))
	defer srv.Close()

	events := make(chan Event, 8)
	c := &Connection{
		Response: protocol.AuthResponse{Token: "t1", TTLSeconds: 1},
		base:     srv.URL,
		http:     srv.Client(),
		stop:     make(chan struct{}),
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		options:  Options{OnEvent: func(e Event) { events <- e }},
	}
	go c.renewLoop()
	defer close(c.stop)

	var got []EventKind
	deadline := time.After(10 * time.Second)
	for len(got) < 3 {
		select {
		case e := <-events:
			got = append(got, e.Kind)
		case <-deadline:
			t.Fatalf("timed out waiting for events; got so far: %v", got)
		}
	}
	want := []EventKind{EventReconnecting, EventReconnected, EventRenewed}
	if len(got) != len(want) {
		t.Fatalf("event sequence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event sequence = %v, want %v", got, want)
		}
	}
}

// TestFireEventWithNilOnEventDoesNotPanic checks the documented contract
// that OnEvent is optional: a Connection built without one (every existing
// caller, since this field is new) must not panic when a lifecycle
// transition occurs.
func TestFireEventWithNilOnEventDoesNotPanic(t *testing.T) {
	c := &Connection{}
	c.fireEvent(Event{Kind: EventRenewed})
}

func TestCloseBoundsDisconnectAndIsIdempotent(t *testing.T) {
	oldTimeout := closeDisconnectTimeout
	closeDisconnectTimeout = 20 * time.Millisecond
	t.Cleanup(func() { closeDisconnectTimeout = oldTimeout })

	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer srv.Close()
	c := &Connection{base: srv.URL, token: "token", http: srv.Client(), stop: make(chan struct{})}
	startedAt := time.Now()
	c.Close()
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("Close blocked for %s", elapsed)
	}
	c.Close() // idempotent even after all owned state has been released
}

func TestRenewCannotRestoreStateAfterClose(t *testing.T) {
	renewStarted := make(chan struct{})
	allowRenew := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/renew":
			close(renewStarted)
			<-allowRenew
			_ = json.NewEncoder(w).Encode(protocol.AuthResponse{Token: "new-token", TTLSeconds: 60})
		case "/v1/disconnect":
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c := &Connection{Response: protocol.AuthResponse{Token: "old-token", TTLSeconds: 60}, base: srv.URL, token: "old-token", http: srv.Client(), stop: make(chan struct{})}
	errCh := make(chan error, 1)
	go func() { errCh <- c.renew() }()
	<-renewStarted
	c.Close()
	close(allowRenew)
	if err := <-errCh; err == nil {
		t.Fatal("renew succeeded after Close")
	}
	if c.Response.Token != "old-token" || c.token != "old-token" {
		t.Fatalf("closed connection state was restored: response=%q token=%q", c.Response.Token, c.token)
	}
}
