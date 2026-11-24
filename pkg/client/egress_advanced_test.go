package client

import (
	"context"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/egressattach"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/socks"
)

func TestSmartProxyUDPAndPreparationThroughPublisher(t *testing.T) {
	for _, tc := range []struct {
		name     string
		denyText bool
	}{{"equivalent encodings", false}, {"cached numeric flow cannot bypass suffix policy", true}} {
		t.Run(tc.name, func(t *testing.T) { testSmartProxyUDPAndPreparation(t, tc.denyText) })
	}
}

func testSmartProxyUDPAndPreparation(t *testing.T, denyText bool) {
	t.Helper()
	f := newReconnectFixture(t)
	startEgressServer(f, "direct-udp", false, false)
	if denyText {
		srv := f.current.Load()
		cfg := srv.Config
		cfg.Tunnels = append([]server.TunnelConfig(nil), cfg.Tunnels...)
		cfg.Tunnels[0].Socks = &server.SocksConfig{AllowLocalEgress: true, ReverseFilters: true, DomainFilters: []string{".0.1"}}
		srv.Reload(cfg)
	}
	owner := f.connect()
	root := filepath.Join(t.TempDir(), "egress")
	path, _ := egressattach.ProfilePath(root, "publisher")
	publisher, err := egressattach.Start(path, owner.EgressCandidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(publisher.Close)
	member := egressrouter.Member{ProfileID: "publisher", Tunnel: "internet", ExpectedServer: f.http.URL}
	registry := egressattach.NewRegistry(root)
	registry.Refresh(t.Context(), []egressrouter.Member{member})
	candidate := registry.Candidate(member)
	if candidate.Dialer == nil || !candidate.Preparation || !candidate.UDP || !candidate.NumericDomain {
		t.Fatalf("missing publisher capability: %s", candidate.Reason)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	ready, err := candidate.Dialer.(egressrouter.PreparableEgress).Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	host, portText, _ := net.SplitHostPort(f.tcpTarget)
	port, _ := strconv.ParseUint(portText, 10, 16)
	encoding := byte(3)
	if denyText {
		encoding = 1
	}
	stream, err := ready.DialDestination(ctx, egressrouter.Destination{Host: host, Port: uint16(port), AddressType: encoding})
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(stream, "prepared"); err != nil {
		stream.Close()
		t.Fatal(err)
	}
	var echoed [8]byte
	if _, err = io.ReadFull(stream, echoed[:]); err != nil || string(echoed[:]) != "prepared" {
		stream.Close()
		t.Fatalf("prepared reply %q: %v", echoed, err)
	}
	stream.Close()

	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listen.Addr().String()
	listen.Close()
	udpTarget, err := net.ResolveUDPAddr("udp", f.udpTarget)
	if err != nil {
		t.Fatal(err)
	}
	group := egressrouter.New(registry.Candidate)
	defer group.Close()
	if err = group.Apply(egressrouter.Config{
		Enabled: true, Listen: address, Egress: egressrouter.Membership{Members: []egressrouter.Member{member}},
		Routing: egressrouter.Routing{UDPAssociate: true, Rules: []egressrouter.Rule{{Ports: []uint16{uint16(udpTarget.Port)}}}},
	}, nil); err != nil {
		t.Fatal(err)
	}
	control, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	relay, err := socks.Associate(ctx, control)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	header := []byte{0, 0, 0, 1, 127, 0, 0, 1}
	blocked := uint16(udpTarget.Port) + 1
	if blocked == 0 {
		blocked = 1
	}
	msg := binary.BigEndian.AppendUint16(append([]byte(nil), header...), blocked)
	msg = append(msg, []byte("filtered")...)
	if _, err = packet.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = packet.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 128)
	if _, err = packet.Read(buf); err == nil {
		t.Fatal("blocked UDP received a reply")
	}
	msg = binary.BigEndian.AppendUint16(append([]byte(nil), header...), uint16(udpTarget.Port))
	msg = append(msg, []byte("datagram")...)
	_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = packet.Write(msg); err != nil {
		t.Fatal(err)
	}
	size, err := packet.Read(buf)
	if err != nil {
		t.Fatalf("UDP read: %v; status %+v", err, group.Status())
	}
	_, offset, err := socks.DatagramDestination(buf[:size])
	if err != nil || string(buf[offset:size]) != "datagram" {
		t.Fatalf("invalid SOCKS echo %x: %v", buf[:size], err)
	}
	owner.mu.Lock()
	before := owner.Response.SessionID
	owner.mu.Unlock()
	if err := owner.renew(); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	after := owner.Response.SessionID
	owner.mu.Unlock()
	if after == "" || after == before {
		t.Fatal("renewal did not rotate the session ID")
	}
	_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = packet.Write(msg); err != nil {
		t.Fatal(err)
	}
	size, err = packet.Read(buf)
	if err != nil {
		t.Fatalf("existing UDP association after renewal: %v", err)
	}
	_, offset, err = socks.DatagramDestination(buf[:size])
	if err != nil || string(buf[offset:size]) != "datagram" {
		t.Fatalf("invalid post-renewal SOCKS echo %x: %v", buf[:size], err)
	}
	// The domain-form datagram uses the same approved destination and flow.
	domainFrame := append([]byte{0, 0, 0, 3, byte(len(host))}, host...)
	domainFrame = binary.BigEndian.AppendUint16(domainFrame, uint16(udpTarget.Port))
	domainFrame = append(domainFrame, "literally"...)
	if _, err = packet.Write(domainFrame); err != nil {
		t.Fatal(err)
	}
	received := uint64(16)
	if denyText {
		_ = packet.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err = packet.Read(buf); err == nil {
			t.Fatal("domain-form datagram reused a cached binary flow despite suffix policy")
		}
	} else {
		size, err = packet.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		_, offset, err = socks.DatagramDestination(buf[:size])
		if err != nil || string(buf[offset:size]) != "literally" {
			t.Fatalf("invalid domain-form SOCKS echo %x: %v", buf[:size], err)
		}
		received += 9
	}
	spoof, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer spoof.Close()
	if _, err = spoof.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = spoof.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err = spoof.Read(buf); err == nil {
		t.Fatal("a second local sender used the pinned association")
	}
	stats := group.Status().Members[0]
	if stats.Sent != 25 || stats.Received != received {
		t.Fatalf("UDP counters include non-relayed traffic: sent=%d received=%d", stats.Sent, stats.Received)
	}
}

func TestSmartProxyEnrollmentRequiresVerifiedCurrentClass(t *testing.T) {
	f := newReconnectFixture(t)
	startEgressServer(f, "direct-udp", false, true)
	configured := f.current.Load().Config
	configured.Tunnels[0].EgressClass = "internet-v1"
	f.current.Load().Reload(configured)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.current.Load().Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(ca, cert, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ConnectWithOptions(server.URL, f.key, protocol.ClientInfo{}, Options{
		CAFile: ca, NoWebUI: true, NoBrowser: true, NoSystemProxy: true, StatusFile: filepath.Join(t.TempDir(), "status.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	entry := egressrouter.Enrollment{ProfileID: "publisher", ExpectedServer: server.URL, EgressClass: "internet-v1"}
	root := filepath.Join(t.TempDir(), "egress")
	path, _ := egressattach.ProfilePath(root, "publisher")
	local, err := egressattach.StartWithDiscovery(path, c.EgressCandidate, nil, c.DiscoverEgress)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	registry := egressattach.NewRegistry(root)
	registry.Refresh(t.Context(), nil, entry)
	if names := registry.Discover(entry); len(names) != 1 || names[0] != "internet" {
		t.Fatalf("unexpected enrollment: %v", names)
	}
	bound := registry.Candidate(entry.Member("internet"))
	if bound.Dialer == nil {
		t.Fatal(bound.Reason)
	}
	wrong := entry
	wrong.EgressClass = "office"
	if names := c.DiscoverEgress(wrong); len(names) != 0 {
		t.Fatalf("other classes enrolled: %v", names)
	}
	configured.Tunnels[0].EgressClass = ""
	f.current.Load().Reload(configured)
	if err = c.renew(); err != nil {
		t.Fatal(err)
	}
	if names := c.DiscoverEgress(entry); len(names) != 0 {
		t.Fatalf("removed class enrolled: %v", names)
	}
	original, err := bound.Dialer.DialDestination(t.Context(), egressrouter.Destination{Host: "unreachable.invalid", Port: 443})
	if err == nil {
		original.Close()
		t.Fatal("stale enrolled member could dial")
	}
}
