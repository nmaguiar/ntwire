package server

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"golang.org/x/net/dns/dnsmessage"
)

type fakePacketConn struct {
	net.PacketConn
	sent [][]byte
	to   []net.Addr
}

func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	f.sent = append(f.sent, cp)
	f.to = append(f.to, addr)
	return len(p), nil
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (f *fakePacketConn) Close() error { return nil }

func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("100.64.0.1"), Port: 53}
}

func newTestServerForDNS() *Server {
	c := Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	c.Tunnels = []TunnelConfig{
		{
			Name:        "reports",
			Target:      "reports.internal:8080",
			Description: "Reporting service",
			VirtualPort: 18080,
			LocalPort:   58080,
		},
		{
			Name:        "db",
			Target:      "db.internal:5432",
			Description: "Database service",
			VirtualPort: 15432,
			LocalPort:   55432,
		},
		{
			Name:        "admin-secret",
			Target:      "admin.internal:9090",
			Description: "Secret admin service",
			VirtualPort: 19090,
			LocalPort:   59090,
		},
	}
	c.NativeWireGuard.Enabled = true
	c.NativeWireGuard.Peers = []NativeWireGuardPeer{
		{
			Name:      "alice",
			PublicKey: "alice-pubkey-123456789012345678901234",
			TunnelIP:  "100.64.0.2",
			Tunnels:   []string{"reports", "db"},
		},
		{
			Name:      "bob",
			PublicKey: "bob-pubkey-12345678901234567890123456",
			TunnelIP:  "100.64.0.3",
			Tunnels:   []string{"admin-secret"},
		},
	}
	return New(c, slog.Default())
}

func buildDNSQuery(id uint16, name string, qType dnsmessage.Type) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(name),
				Type:  qType,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	packed, _ := msg.Pack()
	return packed
}

func unpackDNSResponse(t *testing.T, raw []byte) dnsmessage.Message {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	return msg
}

func forwardingTestServer(t *testing.T) (*Server, *fakePacketConn, *dataPlane, *int) {
	t.Helper()
	s := newTestServerForDNS()
	s.Config.Network.DNS.Forwarding = DNSForwardingConfig{Enabled: true, Upstreams: []string{"192.0.2.53:53", "192.0.2.54:53"}}
	conn := &fakePacketConn{}
	d := &dataPlane{serverIP: netip.MustParseAddr("100.64.0.1"), dnsConn: conn, stop: make(chan struct{})}
	calls := 0
	s.dnsForward = func(query []byte, upstreams []string) ([]byte, error) {
		calls++
		var req dnsmessage.Message
		if err := req.Unpack(query); err != nil {
			return nil, err
		}
		resp := dnsmessage.Message{Header: dnsmessage.Header{ID: req.ID, Response: true, RecursionAvailable: true}, Questions: req.Questions}
		if len(req.Questions) > 0 && req.Questions[0].Type == dnsmessage.TypeA {
			resp.Answers = append(resp.Answers, dnsARecord(req.Questions[0].Name, netip.MustParseAddr("203.0.113.9")))
		}
		return resp.Pack()
	}
	return s, conn, d, &calls
}

func TestDNS_ForwardingAuthorizedExternalQuery(t *testing.T) {
	s, conn, d, calls := forwardingTestServer(t)
	s.handleDNS(d, buildDNSQuery(9301, "example.com.", dnsmessage.TypeA), &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53000})
	if *calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", *calls)
	}
	if len(conn.sent) != 1 {
		t.Fatalf("responses = %d, want 1", len(conn.sent))
	}
	resp := unpackDNSResponse(t, conn.sent[0])
	if !resp.RecursionAvailable || resp.Authoritative || len(resp.Answers) != 1 {
		t.Fatalf("forwarded response = %+v, want non-authoritative recursive answer", resp.Header)
	}
}

func TestDNS_ForwardingNeverLeaksUnauthorizedOrLocalNames(t *testing.T) {
	tests := []struct {
		name   string
		client string
		query  string
		want   dnsmessage.RCode
	}{
		{"unknown peer", "100.64.0.99", "example.com.", dnsmessage.RCodeRefused},
		{"unauthorized tunnel", "100.64.0.2", "admin-secret.ntwire.", dnsmessage.RCodeNameError},
		{"unknown local name", "100.64.0.2", "does-not-exist.ntwire.", dnsmessage.RCodeNameError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, conn, d, calls := forwardingTestServer(t)
			s.handleDNS(d, buildDNSQuery(9302, tt.query, dnsmessage.TypeA), &net.UDPAddr{IP: net.ParseIP(tt.client), Port: 53000})
			if *calls != 0 {
				t.Fatalf("upstream calls = %d, want 0", *calls)
			}
			resp := unpackDNSResponse(t, conn.sent[0])
			if resp.RCode != tt.want {
				t.Fatalf("RCode = %v, want %v", resp.RCode, tt.want)
			}
		})
	}
}

func TestDNS_ForwardingDisabledKeepsLocalNXDOMAIN(t *testing.T) {
	s := newTestServerForDNS()
	conn := &fakePacketConn{}
	d := &dataPlane{serverIP: netip.MustParseAddr("100.64.0.1"), dnsConn: conn, stop: make(chan struct{})}
	calls := 0
	s.dnsForward = func([]byte, []string) ([]byte, error) { calls++; return nil, nil }
	s.handleDNS(d, buildDNSQuery(9303, "example.com.", dnsmessage.TypeA), &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53000})
	if calls != 0 {
		t.Fatalf("upstream calls = %d, want 0", calls)
	}
	if got := unpackDNSResponse(t, conn.sent[0]).RCode; got != dnsmessage.RCodeNameError {
		t.Fatalf("RCode = %v, want NXDOMAIN", got)
	}
}

func dnsForwardingResponse(t *testing.T, query []byte, rcode dnsmessage.RCode, truncated bool) []byte {
	t.Helper()
	var req dnsmessage.Message
	if err := req.Unpack(query); err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: req.ID, Response: true, RCode: rcode, Truncated: truncated}, Questions: req.Questions}
	response, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestDNSForwarderFailoverAndNXDOMAIN(t *testing.T) {
	s := newTestServerForDNS()
	query := buildDNSQuery(9401, "example.com.", dnsmessage.TypeA)
	originalUDP := forwardDNSUDPExchange
	originalTCP := forwardDNSTCPExchange
	t.Cleanup(func() { forwardDNSUDPExchange, forwardDNSTCPExchange = originalUDP, originalTCP })
	calls := 0
	forwardDNSUDPExchange = func(query []byte, upstream string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("timeout")
		}
		return dnsForwardingResponse(t, query, dnsmessage.RCodeSuccess, false), nil
	}
	if _, err := s.forwardDNS(query, []string{"192.0.2.53:53", "192.0.2.54:53"}); err != nil || calls != 2 {
		t.Fatalf("failover result err=%v calls=%d, want second upstream success", err, calls)
	}
	calls = 0
	forwardDNSUDPExchange = func(query []byte, upstream string) ([]byte, error) {
		calls++
		return dnsForwardingResponse(t, query, dnsmessage.RCodeNameError, false), nil
	}
	response, err := s.forwardDNS(query, []string{"192.0.2.53:53", "192.0.2.54:53"})
	if err != nil || calls != 1 || unpackDNSResponse(t, response).RCode != dnsmessage.RCodeNameError {
		t.Fatalf("NXDOMAIN err=%v calls=%d; it must return without failover", err, calls)
	}
}

func TestDNSForwarderRetriesTruncatedUDPOverTCP(t *testing.T) {
	s := newTestServerForDNS()
	query := buildDNSQuery(9402, "example.com.", dnsmessage.TypeA)
	originalUDP := forwardDNSUDPExchange
	originalTCP := forwardDNSTCPExchange
	t.Cleanup(func() { forwardDNSUDPExchange, forwardDNSTCPExchange = originalUDP, originalTCP })
	tcpCalls := 0
	forwardDNSUDPExchange = func(query []byte, upstream string) ([]byte, error) {
		return dnsForwardingResponse(t, query, dnsmessage.RCodeSuccess, true), nil
	}
	forwardDNSTCPExchange = func(query []byte, upstream string) ([]byte, error) {
		tcpCalls++
		return dnsForwardingResponse(t, query, dnsmessage.RCodeSuccess, false), nil
	}
	response, err := s.forwardDNS(query, []string{"192.0.2.53:53"})
	if err != nil || tcpCalls != 1 || unpackDNSResponse(t, response).Truncated {
		t.Fatalf("TCP fallback err=%v tcpCalls=%d", err, tcpCalls)
	}
}

func TestDNS_TunnelAQuery(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}

	// 1. Query "reports.ntwire."
	query := buildDNSQuery(1001, "reports.ntwire.", dnsmessage.TypeA)
	s.handleDNS(d, query, clientAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}

	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.ID != 1001 {
		t.Errorf("resp.ID = %d, want 1001", resp.ID)
	}
	if resp.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("resp.RCode = %v, want Success", resp.RCode)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("len(resp.Answers) = %d, want 1", len(resp.Answers))
	}
	aRec, ok := resp.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("expected AResource body, got %T", resp.Answers[0].Body)
	}
	if net.IP(aRec.A[:]).String() != "100.64.0.1" {
		t.Errorf("resolved IP = %v, want 100.64.0.1", net.IP(aRec.A[:]))
	}

	// 2. Query "reports.tunnel." (alias)
	fakeConn.sent = nil
	query2 := buildDNSQuery(1002, "reports.tunnel.", dnsmessage.TypeA)
	s.handleDNS(d, query2, clientAddr)
	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}
	resp2 := unpackDNSResponse(t, fakeConn.sent[0])
	if resp2.RCode != dnsmessage.RCodeSuccess || len(resp2.Answers) != 1 {
		t.Errorf("resp2 = %+v, want Success with 1 answer", resp2)
	}
}

func TestDNS_ServiceDiscoverySRV(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	// Alice has access to "reports" (port 18080) and "db" (port 15432)
	clientAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}
	query := buildDNSQuery(2001, "_ntwire._tcp.ntwire.", dnsmessage.TypeSRV)
	s.handleDNS(d, query, clientAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}

	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("resp.RCode = %v, want Success", resp.RCode)
	}
	if len(resp.Answers) != 2 {
		t.Fatalf("len(resp.Answers) = %d, want 2 (reports, db)", len(resp.Answers))
	}

	ports := map[uint16]string{}
	for _, ans := range resp.Answers {
		srv, ok := ans.Body.(*dnsmessage.SRVResource)
		if !ok {
			t.Fatalf("expected SRVResource body, got %T", ans.Body)
		}
		ports[srv.Port] = srv.Target.String()
	}

	if target, ok := ports[18080]; !ok || !strings.HasPrefix(target, "reports.") {
		t.Errorf("missing reports SRV on port 18080: got ports %v", ports)
	}
	if target, ok := ports[15432]; !ok || !strings.HasPrefix(target, "db.") {
		t.Errorf("missing db SRV on port 15432: got ports %v", ports)
	}

	// Check additionals have A records
	if len(resp.Additionals) != 2 {
		t.Errorf("len(resp.Additionals) = %d, want 2", len(resp.Additionals))
	}
}

func TestDNS_ServiceDiscoveryTXT(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}
	query := buildDNSQuery(3001, "_ntwire.ntwire.", dnsmessage.TypeTXT)
	s.handleDNS(d, query, clientAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}

	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("resp.RCode = %v, want Success", resp.RCode)
	}
	if len(resp.Answers) != 2 {
		t.Fatalf("len(resp.Answers) = %d, want 2 TXT records", len(resp.Answers))
	}
}

func TestDNS_SpecificSRV(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}

	// Query _reports._tcp.ntwire.
	query := buildDNSQuery(4001, "_reports._tcp.ntwire.", dnsmessage.TypeSRV)
	s.handleDNS(d, query, clientAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}

	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("resp = %+v, want Success with 1 answer", resp)
	}
	srv, ok := resp.Answers[0].Body.(*dnsmessage.SRVResource)
	if !ok || srv.Port != 18080 {
		t.Errorf("srv = %+v, want port 18080", srv)
	}
}

func TestDNS_AuthorizationFiltering(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	// Alice (100.64.0.2) only has "reports" and "db", NOT "admin-secret"
	aliceAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}

	query := buildDNSQuery(5001, "admin-secret.ntwire.", dnsmessage.TypeA)
	s.handleDNS(d, query, aliceAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}

	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeNameError {
		t.Errorf("Alice queried admin-secret: resp.RCode = %v, want NameError (NXDOMAIN)", resp.RCode)
	}

	// Bob (100.64.0.3) has "admin-secret"
	bobAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.3"), Port: 53124}
	fakeConn.sent = nil

	queryBob := buildDNSQuery(5002, "admin-secret.ntwire.", dnsmessage.TypeA)
	s.handleDNS(d, queryBob, bobAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response for Bob, got %d", len(fakeConn.sent))
	}
	respBob := unpackDNSResponse(t, fakeConn.sent[0])
	if respBob.RCode != dnsmessage.RCodeSuccess || len(respBob.Answers) != 1 {
		t.Errorf("Bob queried admin-secret: resp = %+v, want Success with 1 answer", respBob)
	}
}

func TestDNS_UnauthenticatedClient(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	// Unknown IP 100.64.0.99
	unknownAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.99"), Port: 53999}
	query := buildDNSQuery(6001, "reports.ntwire.", dnsmessage.TypeA)
	s.handleDNS(d, query, unknownAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}

	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeRefused {
		t.Errorf("unknown client queried DNS: resp.RCode = %v, want Refused", resp.RCode)
	}
}

func TestDNS_ReversePTR(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	aliceAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}

	// Reverse PTR for server IP (100.64.0.1 -> 1.0.64.100.in-addr.arpa.)
	query := buildDNSQuery(7001, "1.0.64.100.in-addr.arpa.", dnsmessage.TypePTR)
	s.handleDNS(d, query, aliceAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}

	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("resp = %+v, want Success with 1 answer", resp)
	}
	ptr, ok := resp.Answers[0].Body.(*dnsmessage.PTRResource)
	if !ok || !strings.HasPrefix(ptr.PTR.String(), "server.") {
		t.Errorf("ptr = %+v, want server.ntwire.", ptr)
	}

	// Reverse PTR for Alice IP (100.64.0.2 -> 2.0.64.100.in-addr.arpa.)
	fakeConn.sent = nil
	queryAlice := buildDNSQuery(7002, "2.0.64.100.in-addr.arpa.", dnsmessage.TypePTR)
	s.handleDNS(d, queryAlice, aliceAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response for Alice PTR, got %d", len(fakeConn.sent))
	}
	respAlice := unpackDNSResponse(t, fakeConn.sent[0])
	if respAlice.RCode != dnsmessage.RCodeSuccess || len(respAlice.Answers) != 1 {
		t.Fatalf("respAlice = %+v, want Success with 1 answer", respAlice)
	}
	ptrAlice, ok := respAlice.Answers[0].Body.(*dnsmessage.PTRResource)
	if !ok || !strings.HasPrefix(ptrAlice.PTR.String(), "alice.") {
		t.Errorf("ptrAlice = %+v, want alice.ntwire.", ptrAlice)
	}
}

func TestDNS_IPv6(t *testing.T) {
	c := Config{}
	c.Network.TunnelCIDR = "fd00::/64"
	c.Tunnels = []TunnelConfig{
		{
			Name:        "web",
			Target:      "web.internal:80",
			VirtualPort: 80,
		},
	}
	c.NativeWireGuard.Enabled = true
	c.NativeWireGuard.Peers = []NativeWireGuardPeer{
		{
			Name:      "user6",
			PublicKey: "user6-pubkey-1234567890123456789012345",
			TunnelIP:  "fd00::2",
			Tunnels:   []string{"web"},
		},
	}

	s := New(c, slog.Default())
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("fd00::1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("fd00::2"), Port: 53123}
	query := buildDNSQuery(8001, "web.ntwire.", dnsmessage.TypeAAAA)
	s.handleDNS(d, query, clientAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}

	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("resp = %+v, want Success with 1 answer", resp)
	}
	aaaa, ok := resp.Answers[0].Body.(*dnsmessage.AAAAResource)
	if !ok || net.IP(aaaa.AAAA[:]).String() != "fd00::1" {
		t.Errorf("aaaa = %+v, want fd00::1", aaaa)
	}
}

func TestDNS_SessionClient(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	// Create an active session with tunnel "reports"
	s.sessions.Create(CreateParams{
		Method:   "oidc",
		Identity: "carol@example.com",
		TunnelIP: "100.64.0.50",
		Tunnels: []protocol.Tunnel{
			{Name: "reports", VirtualPort: 18080},
		},
		TTL: time.Hour,
	})

	carolAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.50"), Port: 53123}

	// 1. Query reports -> Success
	query := buildDNSQuery(9001, "reports.ntwire.", dnsmessage.TypeA)
	s.handleDNS(d, query, carolAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}
	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeSuccess || len(resp.Answers) != 1 {
		t.Errorf("Carol queried reports: resp = %+v, want Success", resp)
	}

	// 2. Query db -> NameError (not granted to Carol)
	fakeConn.sent = nil
	queryDB := buildDNSQuery(9002, "db.ntwire.", dnsmessage.TypeA)
	s.handleDNS(d, queryDB, carolAddr)
	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}
	respDB := unpackDNSResponse(t, fakeConn.sent[0])
	if respDB.RCode != dnsmessage.RCodeNameError {
		t.Errorf("Carol queried db: respDB.RCode = %v, want NameError", respDB.RCode)
	}
}

func TestDNS_CustomDomain(t *testing.T) {
	c := Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	c.Network.DNS.Domain = "internal.corp"
	c.Tunnels = []TunnelConfig{
		{
			Name:        "reports",
			Target:      "reports.internal:8080",
			VirtualPort: 18080,
		},
	}
	c.NativeWireGuard.Enabled = true
	c.NativeWireGuard.Peers = []NativeWireGuardPeer{
		{
			Name:      "alice",
			PublicKey: "alice-pubkey-123456789012345678901234",
			TunnelIP:  "100.64.0.2",
			Tunnels:   []string{"reports"},
		},
	}

	s := New(c, slog.Default())
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	aliceAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}

	// Query reports.internal.corp.
	query := buildDNSQuery(9101, "reports.internal.corp.", dnsmessage.TypeA)
	s.handleDNS(d, query, aliceAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}
	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeSuccess || len(resp.Answers) != 1 {
		t.Errorf("resp = %+v, want Success with 1 answer", resp)
	}
}

func TestDNS_SpecificTunnelTXT(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	aliceAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}

	// Query TXT for reports.ntwire.
	query := buildDNSQuery(9201, "reports.ntwire.", dnsmessage.TypeTXT)
	s.handleDNS(d, query, aliceAddr)

	if len(fakeConn.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(fakeConn.sent))
	}
	resp := unpackDNSResponse(t, fakeConn.sent[0])
	if resp.RCode != dnsmessage.RCodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("resp = %+v, want Success with 1 answer", resp)
	}
	txt, ok := resp.Answers[0].Body.(*dnsmessage.TXTResource)
	if !ok || len(txt.TXT) == 0 {
		t.Fatalf("expected TXTResource with entries, got %+v", txt)
	}
	joined := strings.Join(txt.TXT, " ")
	if !strings.Contains(joined, "port=18080") || !strings.Contains(joined, "target=reports.internal:8080") {
		t.Errorf("txt content = %q, want port and target", joined)
	}
}

func TestDNS_CorruptPacket(t *testing.T) {
	s := newTestServerForDNS()
	fakeConn := &fakePacketConn{}
	d := &dataPlane{
		serverIP: netip.MustParseAddr("100.64.0.1"),
		dnsConn:  fakeConn,
		stop:     make(chan struct{}),
	}

	aliceAddr := &net.UDPAddr{IP: net.ParseIP("100.64.0.2"), Port: 53123}

	// Corrupt bytes should not panic and produce no response
	s.handleDNS(d, []byte{0x00, 0x01, 0x02}, aliceAddr)
	if len(fakeConn.sent) != 0 {
		t.Errorf("corrupt packet produced response: %v", fakeConn.sent)
	}
}
