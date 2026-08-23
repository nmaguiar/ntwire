package ipfamily

import (
	"errors"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// fakeEndpoint is a minimal conn.Endpoint for a given destination address.
type fakeEndpoint struct{ addr netip.AddrPort }

func (fakeEndpoint) ClearSrc()             {}
func (fakeEndpoint) SrcToString() string   { return "" }
func (e fakeEndpoint) DstToString() string { return e.addr.String() }
func (e fakeEndpoint) DstToBytes() []byte  { b, _ := e.addr.MarshalBinary(); return b }
func (e fakeEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (fakeEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }

// fakeBind is a minimal conn.Bind whose ParseEndpoint parses "ip:port"
// literally (no family opinion of its own) and whose single receive func
// replays a fixed queue of endpoints, one per call.
type fakeBind struct {
	queue []netip.AddrPort
	sent  []netip.AddrPort
}

func (b *fakeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	i := 0
	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if i >= len(b.queue) {
			return 0, errors.New("no more queued packets")
		}
		sizes[0] = copy(bufs[0], []byte("x"))
		eps[0] = fakeEndpoint{addr: b.queue[i]}
		i++
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, port, nil
}
func (b *fakeBind) Close() error         { return nil }
func (b *fakeBind) SetMark(uint32) error { return nil }
func (b *fakeBind) BatchSize() int       { return 1 }
func (b *fakeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.sent = append(b.sent, ep.(fakeEndpoint).addr)
	return nil
}
func (b *fakeBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return fakeEndpoint{addr: addr}, nil
}

func TestNewNoopsForEmptyOrInvalidFamily(t *testing.T) {
	base := &fakeBind{}
	for _, family := range []string{"", "5", "ipv4"} {
		if got := New(base, family); got != conn.Bind(base) {
			t.Errorf("New(base, %q) = %v, want base unchanged", family, got)
		}
	}
}

func TestSendRejectsWrongFamily(t *testing.T) {
	bind := New(&fakeBind{}, "4")
	v6, err := netip.ParseAddrPort("[::1]:51820")
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{[]byte("x")}, fakeEndpoint{addr: v6}); err == nil {
		t.Fatal("Send accepted an IPv6 endpoint on an IPv4-only bind")
	}
	v4, err := netip.ParseAddrPort("1.2.3.4:51820")
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{[]byte("x")}, fakeEndpoint{addr: v4}); err != nil {
		t.Fatalf("Send rejected a matching IPv4 endpoint: %v", err)
	}
}

func TestParseEndpointRejectsWrongFamily(t *testing.T) {
	bind := New(&fakeBind{}, "6")
	if _, err := bind.ParseEndpoint("1.2.3.4:51820"); err == nil {
		t.Fatal("ParseEndpoint accepted an IPv4 endpoint on an IPv6-only bind")
	}
	if _, err := bind.ParseEndpoint("[::1]:51820"); err != nil {
		t.Fatalf("ParseEndpoint rejected a matching IPv6 endpoint: %v", err)
	}
}

func TestOpenFiltersReceivedPacketsByFamily(t *testing.T) {
	v4 := netip.MustParseAddrPort("1.2.3.4:1000")
	v6 := netip.MustParseAddrPort("[::1]:1000")
	base := &fakeBind{queue: []netip.AddrPort{v6, v6, v4}}
	bind := New(base, "4")
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	bufs := [][]byte{make([]byte, 16)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	if !eps[0].DstIP().Is4() {
		t.Fatalf("delivered endpoint %v is not IPv4; the two IPv6 packets ahead of it should have been dropped, not delivered", eps[0].DstIP())
	}
}
