package client

import (
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/internal/egressattach"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/server"
)

func TestEgressHostnameBindingThroughAttachment(t *testing.T) {
	f := newReconnectFixture(t)
	startEgressServerWithFaults(f, "direct-udp", false, false, nil, func(c *server.Config) {
		options := c.Tunnels[0].Socks
		options.AllowDestinationBinding = true
		options.AllowAll = false
		options.DomainFilters = []string{"localhost"}
	})
	client := f.connect()
	id := egressrouter.Member{ProfileID: "binding", Tunnel: "internet", ExpectedServer: f.http.URL}
	root := filepath.Join(t.TempDir(), "egress")
	path, err := egressattach.ProfilePath(root, id.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := egressattach.Start(path, client.EgressCandidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	registry := egressattach.NewRegistry(root)
	registry.Refresh(ctx, []egressrouter.Member{id})
	candidate := registry.Candidate(id)
	binder, ok := candidate.Dialer.(egressrouter.BindableEgress)
	if !ok || !candidate.DestinationBinding {
		t.Fatalf("candidate %+v", candidate)
	}
	_, port, err := net.SplitHostPort(f.tcpTarget)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.ParseUint(port, 10, 16)
	dst := egressrouter.Destination{Host: "localhost", Port: uint16(n)}
	offer, err := binder.OfferDestination(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer offer.Close()
	ip := netip.MustParseAddr("127.0.0.1")
	if !slices.Contains(offer.Addresses(), ip) {
		t.Fatal("authorized IPv4 answer missing")
	}
	conn, err := offer.ConnectAddress(ctx, ip)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("pinned")); err != nil {
		t.Fatal(err)
	}
	var reply [6]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "pinned" {
		t.Fatalf("reply %q, error %v", reply, err)
	}
	if conn, err := offer.ConnectAddress(ctx, ip); err == nil {
		_ = conn.Close()
		t.Fatal("offer was reusable")
	}
	dst.Host = ip.String()
	if offer, err := binder.OfferDestination(ctx, dst); err == nil {
		_ = offer.Close()
		t.Fatal("numeric offer bypassed hostname filter")
	}
}
