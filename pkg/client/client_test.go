package client

import (
	"bytes"
	"encoding/json"
	"errors"
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

	l, err := listenLocal(port, true)
	if err != nil {
		t.Fatal(err)
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
	l, err = listenLocal(port, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if got := l.Addr().(*net.TCPAddr).Port; got == port {
		t.Fatalf("fallback retained occupied port %d", port)
	}
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
