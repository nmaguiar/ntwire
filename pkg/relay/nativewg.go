package relay

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// nativeWGRelay forwards opaque WireGuard packets for one tenant-only UDP
// listener. It never has WireGuard keys or plaintext. Receiver indices are
// visible routing metadata; the bounded, expiring map only associates them
// with a source address long enough to return the server's response.
type nativeWGRelay struct {
	conn    net.PacketConn
	mu      sync.Mutex
	tokens  map[string]string // token -> tenant
	servers map[string]netip.AddrPort
	indices map[uint32]nativeWGRoute
}
type nativeWGRoute struct {
	client  netip.AddrPort
	expires time.Time
}

func newNativeWGRelay(c net.PacketConn) *nativeWGRelay {
	return &nativeWGRelay{conn: c, tokens: map[string]string{}, servers: map[string]netip.AddrPort{}, indices: map[uint32]nativeWGRoute{}}
}
func (n *nativeWGRelay) issue(tenant string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	n.mu.Lock()
	for k, v := range n.tokens {
		if v == tenant {
			delete(n.tokens, k)
		}
	}
	delete(n.servers, tenant)
	n.tokens[token] = tenant
	n.mu.Unlock()
	return token
}
func (n *nativeWGRelay) remove(tenant string) {
	n.mu.Lock()
	for k, v := range n.tokens {
		if v == tenant {
			delete(n.tokens, k)
		}
	}
	delete(n.servers, tenant)
	n.mu.Unlock()
}

func validWGPacket(b []byte) (typ uint32, receiver uint32, ok bool) {
	if len(b) < 4 {
		return 0, 0, false
	}
	typ = binary.LittleEndian.Uint32(b[:4])
	switch typ {
	case 1:
		if len(b) != 148 {
			return 0, 0, false
		}
		return typ, binary.LittleEndian.Uint32(b[4:8]), true
	case 2:
		if len(b) != 92 {
			return 0, 0, false
		}
		return typ, binary.LittleEndian.Uint32(b[4:8]), true
	case 3:
		if len(b) != 64 {
			return 0, 0, false
		}
		return typ, binary.LittleEndian.Uint32(b[4:8]), true
	case 4:
		if len(b) < 32 || len(b) > wstransport.MaxRelayDatagram {
			return 0, 0, false
		}
		return typ, binary.LittleEndian.Uint32(b[4:8]), true
	}
	return 0, 0, false
}
func (n *nativeWGRelay) serve() {
	buf := make([]byte, wstransport.MaxRelayDatagram+64)
	for {
		size, addr, err := n.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		from, ok := addrPort(addr)
		if !ok {
			continue
		}
		b := append([]byte(nil), buf[:size]...)
		n.handle(b, from)
	}
}
func (n *nativeWGRelay) handle(b []byte, from netip.AddrPort) {
	if typ, payload, ok := wstransport.DecodeControlFrame(b); ok {
		if typ != wstransport.FrameNativeWireGuardAssociate || len(payload) < 32 {
			return
		}
		n.mu.Lock()
		tenant, found := n.tokens[string(payload)]
		if found {
			n.servers[tenant] = from
		}
		n.mu.Unlock()
		return
	}
	typ, receiver, ok := validWGPacket(b)
	if !ok {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	// A packet from the authenticated server leg is only forwarded to a
	// previously learned receiver index. It can never select an arbitrary
	// internet destination.
	for _, server := range n.servers {
		if from == server {
			route, found := n.indices[receiver]
			if found && time.Now().Before(route.expires) {
				_, _ = n.conn.WriteTo(b, net.UDPAddrFromAddrPort(route.client))
			}
			return
		}
	}
	// Client-to-server direction: learn the initiator's sender index (bytes
	// 4:8) for the response; all packets still go only to this tenant's
	// authenticated server association.
	var server netip.AddrPort
	for _, candidate := range n.servers {
		server = candidate
		break
	}
	if !server.IsValid() {
		return
	}
	if typ == 1 {
		n.indices[receiver] = nativeWGRoute{client: from, expires: time.Now().Add(3 * time.Minute)}
		if len(n.indices) > 4096 {
			for k, v := range n.indices {
				if time.Now().After(v.expires) {
					delete(n.indices, k)
					break
				}
			}
		}
	}
	_, _ = n.conn.WriteTo(b, net.UDPAddrFromAddrPort(server))
}
