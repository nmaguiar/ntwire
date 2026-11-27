package relay

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.zx2c4.com/wireguard/conn"
)

type observedCarrier struct {
	conn.Bind
	packets atomic.Uint64
}

func (c *observedCarrier) Send(bufs [][]byte, ep conn.Endpoint) error {
	if err := c.Bind.Send(bufs, ep); err != nil {
		return err
	}
	c.packets.Add(uint64(len(bufs)))
	return nil
}

func TestAdaptiveCarrier_PreservesWireGuardTCPAcrossUDPAlternateRelayAndWSS(t *testing.T) {
	const serverIP = "100.70.0.1"
	const clientIP = "100.70.0.2"
	const outerMax = 1452
	type peer struct {
		bind     *wstransport.AdaptiveBind
		lane     *wstransport.LaneEndpoint
		stack    *wgnet.Stack
		udp, wss *observedCarrier
		alt      *observedCarrier
	}
	makePeer := func(ip string, ws *wstransport.Bind, alternate bool) peer {
		t.Helper()
		p := peer{
			udp: &observedCarrier{Bind: wstransport.NewUDPBind(0, nil)},
			wss: &observedCarrier{Bind: ws},
		}
		carriers := []wstransport.Carrier{
			{Name: "udp", Bind: p.udp, DatagramMax: 1500},
			{Name: "wss", Bind: p.wss, DatagramMax: 1500},
		}
		if alternate {
			p.alt = &observedCarrier{Bind: wstransport.NewUDPBind(0, nil)}
			carriers = append(carriers, wstransport.Carrier{Name: "alt", Bind: p.alt, DatagramMax: 1500})
		}
		var err error
		p.bind, err = wstransport.NewAdaptiveBind(1, carriers...)
		if err != nil {
			t.Fatal(err)
		}
		p.lane, err = p.bind.RegisterLane("anchor", outerMax)
		if err != nil {
			t.Fatal(err)
		}
		p.stack, err = wgnet.New(wgnet.Config{Addresses: []netip.Addr{netip.MustParseAddr(ip)}, Bind: p.bind})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.stack.Close() })
		return p
	}
	port := func(p peer, carrier string) string {
		t.Helper()
		n, ok := p.bind.CarrierPort(carrier)
		if !ok || n == 0 {
			t.Fatalf("carrier %s is not listening", carrier)
		}
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(n)))
	}
	parse := func(b conn.Bind, address string) conn.Endpoint {
		t.Helper()
		ep, err := b.ParseEndpoint(address)
		if err != nil {
			t.Fatal(err)
		}
		return ep
	}
	attach := func(p peer, candidate, carrier string, ep conn.Endpoint) {
		t.Helper()
		_, epoch, _ := p.bind.LaneState(p.lane)
		err := p.bind.InstallQualifiedPath(p.lane, epoch, wstransport.QualifiedPath{
			ID: candidate, Carrier: carrier, Endpoint: ep,
			SendMax: outerMax, ReceiveMax: outerMax, ValidUntil: time.Now().Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	commit := func(p peer, candidate string) {
		t.Helper()
		_, epoch, _ := p.bind.LaneState(p.lane)
		if _, err := p.bind.CommitPath(p.lane, candidate, epoch); err != nil {
			t.Fatal(err)
		}
	}

	serverWS := wstransport.NewServer()
	serverReady := make(chan struct{}, 1)
	serverWS.OnPeerConnected = func(string, conn.Endpoint) { serverReady <- struct{}{} }
	server := makePeer(serverIP, serverWS, true)
	https := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = serverWS.ServeHTTP(w, r, "fixture-session")
	}))
	defer https.Close()
	clientWS := wstransport.NewClient("wss"+strings.TrimPrefix(https.URL, "https"), https.Client(),
		http.Header{"Authorization": {"Bearer fixture"}})
	clientWS.DisableRedial()
	client := makePeer(clientIP, clientWS, false)
	// Close the client carrier before the HTTP fixture waits for its handler.
	defer client.stack.Close()
	select {
	case <-serverReady:
	case <-time.After(3 * time.Second):
		t.Fatal("authenticated WebSocket peer did not attach")
	}
	for _, side := range []struct {
		p       peer
		ws      *wstransport.Bind
		session string
	}{
		{server, serverWS, "fixture-session"},
		{client, clientWS, "remote"},
	} {
		ep, err := side.ws.CarrierEndpoint(side.session)
		if err != nil {
			t.Fatal(err)
		}
		attach(side.p, "wss", "wss", ep)
	}
	attach(client, "direct", "udp", parse(client.udp, port(server, "udp")))
	attach(server, "direct", "udp", parse(server.udp, port(client, "udp")))
	attach(client, "alternate", "udp", parse(client.udp, port(server, "alt")))
	// The same client source uses both server ports. The local carrier
	// identity keeps the two return sockets distinct throughout the switch.
	attach(server, "alternate", "alt", parse(server.alt, port(client, "udp")))

	table, front, _ := newTestDatagramRelay(t)
	token, relayServerAddr, err := table.Allocate("adaptive-test")
	if err != nil {
		t.Fatal(err)
	}
	relayToClient := parse(client.udp, front.LocalAddr().String())
	relayToServer := parse(server.udp, relayServerAddr)
	bind := [][]byte{wstransport.EncodeControlFrame(wstransport.FrameRelayBind, []byte(token))}
	if err := client.udp.Send(bind, relayToClient); err != nil {
		t.Fatal(err)
	}
	if err := server.udp.Send(bind, relayToServer); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if s, ok := table.LookupByClientAddr(netip.MustParseAddrPort(port(client, "udp"))); ok {
			_, serverBound, _, _ := s.legs()
			if serverBound {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("real relay did not authorize both bind frames")
		}
		time.Sleep(time.Millisecond)
	}
	attach(client, "relay", "udp", relayToClient)
	attach(server, "relay", "udp", relayToServer)
	commit(client, "direct")
	commit(server, "direct")
	if err := client.stack.AddPeer(wgnet.Endpoint{PublicKey: server.stack.PublicKey(), Address: serverIP + "/32@" + client.lane.DstToString()}); err != nil {
		t.Fatal(err)
	}
	if err := server.stack.AddPeer(wgnet.Endpoint{PublicKey: client.stack.PublicKey(), Address: clientIP + "/32@" + server.lane.DstToString()}); err != nil {
		t.Fatal(err)
	}

	service, err := server.stack.Listen("tcp", serverIP+":18080")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	go func() {
		socket, err := service.Accept()
		if err != nil {
			return
		}
		defer socket.Close()
		_, _ = io.Copy(socket, socket)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := client.stack.DialContext(ctx, "tcp", serverIP+":18080")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	echo := func(label string) {
		t.Helper()
		_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.WriteString(stream, label); err != nil {
			t.Fatalf("%s write: %v", label, err)
		}
		buf := make([]byte, len(label))
		if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != label {
			t.Fatalf("%s echo = %q, %v", label, buf, err)
		}
	}
	echo("initial direct UDP")
	handshake, found, err := client.stack.LastHandshake(server.stack.PublicKey())
	if err != nil || !found || handshake.Unix() <= 0 {
		t.Fatalf("initial WireGuard handshake = %v, %v, %v", handshake, found, err)
	}
	for _, step := range []struct {
		name   string
		tx, rx *observedCarrier
	}{
		{"alternate", client.udp, server.alt},
		{"relay", client.udp, server.udp},
		{"wss", client.wss, server.wss},
		{"direct", client.udp, server.udp},
	} {
		commit(server, step.name)
		commit(client, step.name)
		tx, rx := step.tx.packets.Load(), step.rx.packets.Load()
		echo("after switch to " + step.name)
		if step.tx.packets.Load() <= tx || step.rx.packets.Load() <= rx {
			t.Fatalf("%s did not carry traffic in both directions", step.name)
		}
	}
	final, _, err := client.stack.LastHandshake(server.stack.PublicKey())
	if err != nil || final != handshake {
		t.Fatalf("carrier switch required a fresh WireGuard handshake: %v -> %v (%v)", handshake, final, err)
	}
}
