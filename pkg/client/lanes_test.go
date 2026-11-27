package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/socks"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

func TestLaneConn_ConcurrentCloseReleasesOnce(t *testing.T) {
	first, second := net.Pipe()
	defer second.Close()
	network := &connectionNetwork{activeFlows: 1}
	connection := &Connection{}
	socket := &laneConn{Conn: first, lane: flowLane{owner: connection, network: network}}
	var closes sync.WaitGroup
	for range 8 {
		closes.Go(func() { _ = socket.Close() })
	}
	closes.Wait()
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if network.activeFlows != 0 {
		t.Fatalf("flow count after concurrent closes = %d", network.activeFlows)
	}
}

func connectMultiLaneFixture(t testing.TB, f *reconnectFixture, cfg server.Config, configure ...func(*Options)) (*Connection, *httptest.Server) {
	t.Helper()
	cfg.Auth.MaxSessionsPerKey = 4
	s := server.New(cfg, slog.New(slog.DiscardHandler))
	if err := s.StartUserspaceDataPlane(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	h := httptest.NewTLSServer(s.Handler())
	t.Cleanup(h.Close)
	ca := filepath.Join(f.dir, "server.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	options := Options{
		AdaptiveCarrier: true, NoDirectUpgrade: true, NoWebUI: true, NoSystemProxy: true, CAFile: ca,
		StatusFile: filepath.Join(f.dir, "multilane.json"), Logger: slog.New(slog.DiscardHandler), renewInterval: time.Hour,
	}
	for _, update := range configure {
		update(&options)
	}
	c, err := ConnectWithOptions(h.URL, f.key, protocol.ClientInfo{}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, h
}

func TestAdaptiveMultiLane_AlternateUDPChildRecoversWithoutMovingFlow(t *testing.T) {
	f := newReconnectFixture(t)
	primary, alternate := reserveAdaptiveUDPTestPorts(t)
	cfg := f.serverConfig("100.77.6.0/24", 18270, true, server.TransportConfig{
		Adaptive: true, AdaptiveMaxLanes: 2, AdaptiveUDPPort: primary, AdaptiveUDPAltPort: alternate, AdaptiveTunnelMTU: 1280,
	})
	c, _ := connectMultiLaneFixture(t, f, cfg, func(o *Options) {
		o.NoDirectUpgrade, o.IPVersion = false, "4"
	})
	anchor := c.network.adaptive
	if !c.Response.Adaptive.LaneCarriers || !anchor.beginExploration(time.Now()) {
		t.Fatal("child datagram carriers are unavailable")
	}
	defer anchor.exploration.Store(false)
	first := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, first, "anchor WSS")
	path := protocol.CarrierAlternateUDP
	if err := anchor.qualifyUDP(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	if err := anchor.selectPrimary(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	child, err := c.openAdaptiveLane(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	a := child.adaptive
	if current, _, _ := a.bind.LaneState(a.lane); current != path || !a.bind.HasQualifiedPath(a.lane, path) {
		t.Fatalf("child did not qualify its own alternate UDP route: %s", current)
	}
	second := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, second, "child alternate UDP")
	assertLaneFlows(t, c, child, 1, 1)
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	echoLaneTest(t, second, "child UDP after renewal")
	if err := a.altUDP.socket.Close(); err != nil {
		t.Fatal(err)
	}
	echoLaneTest(t, second, "child recovered onto WSS")
	assertLaneFlows(t, c, child, 1, 1)
	if current, _, _ := a.bind.LaneState(a.lane); current != protocol.CarrierWSS {
		t.Fatalf("child path after failover = %q", current)
	}
	waitCarrier(t, c, path)
	echoLaneTest(t, first, "anchor kept its independent UDP route")
}

func TestAdaptiveMultiLane_SharedParentLifecycle(t *testing.T) {
	f := newReconnectFixture(t)
	cfg := f.serverConfig("100.77.0.0/24", 18210, true, server.TransportConfig{Adaptive: true, AdaptiveMaxLanes: 2})
	c, h := connectMultiLaneFixture(t, f, cfg)
	addresses := slices.Clone(c.LocalAddresses)
	anchor := c.network.adaptive
	info, bearer, _ := anchor.credentials()
	if info.MaxLanes != 2 {
		t.Fatalf("negotiated lane cap = %d", info.MaxLanes)
	}
	anchorFlow := dialLaneTest(t, "tcp", addresses[0])
	echoLaneTest(t, anchorFlow, "anchor before creating a child")

	child, err := c.openAdaptiveLane(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lane := child.response.Adaptive.LaneID
	if child.stack.PublicKey() == c.Stack.PublicKey() || child.clientIP == c.network.clientIP || !slices.Equal(addresses, c.LocalAddresses) {
		t.Fatal("child reused the anchor peer or modified the local listeners")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	target := netip.AddrPortFrom(child.serverIP, uint16(c.Response.Tunnels[0].VirtualPort))
	flow, err := child.stack.DialContext(ctx, "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	echo := func() {
		t.Helper()
		msg := []byte("persistent child flow")
		_ = flow.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := flow.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(flow, buf); err != nil || !bytes.Equal(buf, msg) {
			t.Fatalf("child echo = %q / %v", buf, err)
		}
	}
	echo()
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := newLaneRequest(info.AuthGeneration, key.Public)
	if err != nil {
		t.Fatal(err)
	}
	control := func(method, path, token string, body []byte, want int) {
		t.Helper()
		var out protocol.LaneList
		err := anchor.controlRequest(t.Context(), method, h.URL+path, token, body, &out)
		var status *carrierHTTPError
		if !errors.As(err, &status) || status.status != want {
			t.Fatalf("%s %s: %v, want %d", method, path, err, want)
		}
	}
	control(http.MethodPost, "/v1/session/lanes", bearer, body, http.StatusTooManyRequests)
	other, err := authenticateSSH(h.Client(), h.URL, f.key, protocol.ClientInfo{}, key.Public, Options{AdaptiveCarrier: true})
	if err != nil {
		t.Fatal(err)
	}
	control(http.MethodGet, "/v1/transport/lanes/"+lane+"/candidates", other.Token, nil, http.StatusNotFound)
	postSessionDisconnect(h.Client(), h.URL, other.Token)
	if _, err := authenticateSSH(h.Client(), h.URL, f.key, protocol.ClientInfo{}, child.stack.PublicKey(), Options{}); err == nil {
		t.Fatal("fresh authentication reclaimed the child key")
	}
	before, _, err := child.stack.LastHandshake(c.Response.ServerPublicKey)
	if err != nil || before.Unix() <= 0 {
		t.Fatalf("child handshake unavailable: %v, %v", before, err)
	}
	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	control(http.MethodGet, "/v1/session/lanes", bearer, nil, http.StatusUnauthorized)
	next, newBearer, _ := child.adaptive.credentials()
	if next.AuthGeneration != info.AuthGeneration+1 || newBearer == bearer {
		t.Fatal("child did not inherit renewal")
	}
	echo()
	after, _, err := child.stack.LastHandshake(c.Response.ServerPublicKey)
	if err != nil || !after.Equal(before) {
		t.Fatalf("renewal replaced child peer: %v -> %v, %v", before, after, err)
	}
	_ = flow.Close()
	if err := c.retireAdaptiveLane(t.Context(), lane); err != nil {
		t.Fatal(err)
	}
	control(http.MethodGet, "/v1/transport/lanes/"+lane+"/candidates", newBearer, nil, http.StatusNotFound)
	echoLaneTest(t, anchorFlow, "anchor after child renewal and retirement")
	fresh := dialLaneTest(t, "tcp", addresses[0])
	echoLaneTest(t, fresh, "new flow after child retirement")
	if _, err := c.openAdaptiveLane(t.Context()); err != nil {
		t.Fatalf("retired lane did not release the slot: %v", err)
	}
	if err := anchor.controlRequest(t.Context(), http.MethodPost, h.URL+"/v1/disconnect", newBearer, nil, nil); err != nil {
		t.Fatal(err)
	}
	control(http.MethodGet, "/v1/session/lanes", newBearer, nil, http.StatusUnauthorized)
}

func TestAdaptiveMultiLane_LocalFlowsDrainWithoutMigration(t *testing.T) {
	f := newReconnectFixture(t)
	cfg := f.serverConfig("100.77.1.0/24", 18220, true, server.TransportConfig{Adaptive: true, AdaptiveMaxLanes: 2})
	cfg.Tunnels[1].UDPIdleTimeout = 4 * time.Second
	c, _ := connectMultiLaneFixture(t, f, cfg)
	addresses := slices.Clone(c.LocalAddresses)
	first := dialLaneTest(t, "tcp", addresses[0])
	echoLaneTest(t, first, "anchor before scale")
	child, err := c.openAdaptiveLane(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second := dialLaneTest(t, "tcp", addresses[0])
	echoLaneTest(t, second, "child after scale")
	assertLaneFlows(t, c, child, 1, 1)
	third := dialLaneTest(t, "tcp", addresses[0])
	echoLaneTest(t, third, "balanced anchor flow")
	udp := dialLaneTest(t, "udp", addresses[1])
	echoLaneTest(t, udp, "child UDP association")
	assertLaneFlows(t, c, child, 2, 2)

	id := child.response.Adaptive.LaneID
	if err := c.retireAdaptiveLane(t.Context(), id); !errors.Is(err, errLaneDraining) {
		t.Fatalf("busy child retirement: %v", err)
	}
	lanes := c.TransportDetails().Lanes
	if len(lanes) != 2 || !lanes[0].Anchor || lanes[1].State != "draining" || lanes[1].ActiveFlows != 2 {
		t.Fatalf("unexpected drain diagnostics: %+v", lanes)
	}
	echoLaneTest(t, udp, "existing UDP association survives drain")
	// Closing the local UDP socket has no FIN. Let its lease expire while
	// the child still carries TCP, independently of control-plane timing.
	_ = udp.Close()
	waitLaneFlows(t, c, child, 1, 8*time.Second)

	if err := c.renew(); err != nil {
		t.Fatal(err)
	}
	fresh := dialLaneTest(t, "tcp", addresses[0])
	echoLaneTest(t, fresh, "new flow skips draining child")
	echoLaneTest(t, first, "original anchor survives")
	echoLaneTest(t, second, "original child survives")
	assertLaneFlows(t, c, child, 3, 1)
	_ = second.Close()
	for deadline := time.Now().Add(6 * time.Second); ; {
		err := c.retireAdaptiveLane(t.Context(), id)
		if err == nil {
			break
		}
		if !errors.Is(err, errLaneDraining) || time.Now().After(deadline) {
			t.Fatalf("child did not retire after the TCP close and UDP idle timeout: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	echoLaneTest(t, fresh, "anchor survives peer removal")
	if !slices.Equal(c.LocalAddresses, addresses) {
		t.Fatal("lane scaling or renewal changed the local listeners")
	}
}

func TestAdaptiveMultiLane_ProxyPreparationAndHTTPPool(t *testing.T) {
	f := newReconnectFixture(t)
	cfg := f.serverConfig("100.77.2.0/24", 18230, true, server.TransportConfig{Adaptive: true, AdaptiveMaxLanes: 2})
	cfg.Tunnels = append(cfg.Tunnels, server.TunnelConfig{Name: "proxy", Target: "socks", VirtualPort: 18232, Allow: []string{"*"},
		Socks: &server.SocksConfig{AllowAll: true, AllowLocalEgress: true}})
	c, _ := connectMultiLaneFixture(t, f, cfg)
	anchor := dialLaneTest(t, "tcp", c.LocalAddresses[0])
	echoLaneTest(t, anchor, "hold anchor")
	child, err := c.openAdaptiveLane(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.SOCKSEgress("proxy")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := grant.(egressrouter.PreparableEgress).Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	assertLaneFlows(t, c, child, 1, 1)
	dst, err := socks.ParseDestination(f.tcpTarget)
	if err != nil {
		t.Fatal(err)
	}
	out, err := prepared.DialDestination(t.Context(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	echoLaneTest(t, out, "prepared Smart Proxy stream")
	_ = out.Close()
	assertLaneFlows(t, c, child, 1, 0)

	association, err := grant.(egressrouter.UDPEgress).AssociateUDP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer association.Close()
	frame := socks.DatagramFrame(netip.MustParseAddrPort(f.udpTarget), []byte("Smart Proxy datagram"))
	echoLaneTest(t, association, string(frame))
	assertLaneFlows(t, c, child, 1, 1)
	_ = association.Close()
	assertLaneFlows(t, c, child, 1, 0)

	localSOCKS := dialLaneTest(t, "tcp", c.LocalAddresses[2])
	_ = localSOCKS.SetDeadline(time.Now().Add(8 * time.Second))
	setup, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	err = socks.Connect(setup, localSOCKS, f.tcpTarget)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	echoLaneTest(t, localSOCKS, "local SOCKS uses child")
	assertLaneFlows(t, c, child, 1, 1)
	_ = localSOCKS.Close()
	waitLaneIdle(t, c, child)

	connect := dialLaneTest(t, "tcp", c.LocalAddresses[2])
	_ = connect.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := fmt.Fprintf(connect, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", f.tcpTarget, f.tcpTarget); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(connect), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response: %v (%v)", resp, err)
	}
	echoLaneTest(t, connect, "CONNECT uses child")
	assertLaneFlows(t, c, child, 1, 1)
	_ = connect.Close()
	waitLaneIdle(t, c, child)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "HTTP through leased peer")
	}))
	t.Cleanup(origin.Close)
	h := proxyTestClient(c.LocalAddresses[2])
	h.Timeout = 15 * time.Second
	defer h.CloseIdleConnections()
	request := func() {
		t.Helper()
		resp, err := h.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || err != nil || strings.TrimSpace(string(body)) != "HTTP through leased peer" {
			t.Fatalf("proxied response %d: %s (%v)", resp.StatusCode, body, err)
		}
	}
	request()
	request()
	assertLaneFlows(t, c, child, 1, 1)
	id := child.response.Adaptive.LaneID
	if err := c.retireAdaptiveLane(t.Context(), id); !errors.Is(err, errLaneDraining) {
		t.Fatalf("idle HTTP pool did not retain its lease: %v", err)
	}
	request()
	assertLaneFlows(t, c, child, 2, 0)
	if err := c.retireAdaptiveLane(t.Context(), id); err != nil {
		t.Fatalf("idle HTTP pool did not release the drained peer: %v", err)
	}
	request()
}

func waitLaneIdle(t *testing.T, c *Connection, lane *connectionNetwork) {
	t.Helper()
	waitLaneFlows(t, c, lane, 0, 8*time.Second)
}

func waitLaneFlows(t *testing.T, c *Connection, lane *connectionNetwork, want int, timeout time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(timeout); ; {
		c.mu.Lock()
		active := lane.activeFlows
		c.mu.Unlock()
		if active == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lane has %d active flows, want %d", active, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertLaneFlows(t testing.TB, c *Connection, child *connectionNetwork, anchor, extra int) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.network.activeFlows != anchor || child.activeFlows != extra {
		t.Fatalf("flow ownership anchor=%d child=%d, want %d/%d", c.network.activeFlows, child.activeFlows, anchor, extra)
	}
}

func dialLaneTest(t testing.TB, network, address string) net.Conn {
	t.Helper()
	socket, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

func echoLaneTest(t testing.TB, socket net.Conn, data string) {
	t.Helper()
	_ = socket.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(socket, data); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, len(data))
	if _, err := io.ReadFull(socket, p); err != nil || string(p) != data {
		t.Fatalf("echo %q: %v", p, err)
	}
}
