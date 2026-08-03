package relay

import (
	"log/slog"
	"net"
	"net/netip"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// readBufSize is sized comfortably above wstransport.MaxRelayDatagram so a
// legitimately oversized datagram is read in full and rejected by
// ValidRelayDatagram, rather than silently truncated by ReadFrom (UDP
// truncates a datagram larger than the read buffer with no error) and
// forwarded as corrupt data.
const readBufSize = wstransport.MaxRelayDatagram + 64

// datagramRelay is the UDP-relay tier's forwarding engine: one goroutine per
// pooled server-leg socket (parked in ReadFrom, a cheap and normal pattern
// for Go's runtime up to the low thousands of sockets a sanely sized
// listen.udp_relay_ports range implies -- see docs/RELAY.md) plus one
// goroutine for the shared client-facing socket. It never buffers a
// datagram for a half-bound session -- WireGuard's own retransmits cover a
// dropped first packet, and buffering here would be a memory-amplification
// vector for an unauthenticated sender on the client-facing socket. It is
// explicitly a symmetric pair-relay (a TURN-style permission model): a
// datagram is only ever forwarded between two addresses that have each
// completed their own token-verified bind for the same session, never to an
// arbitrary destination -- this, not just rate limiting, is what keeps it
// from being usable as an open reflector.
type datagramRelay struct {
	sessions   *udpSessionTable
	clientConn net.PacketConn
	rate       *rateLimiter // gates bind attempts from unrecognized senders on clientConn only
	log        *slog.Logger
}

func newDatagramRelay(sessions *udpSessionTable, clientConn net.PacketConn, maxNewBindsPerMinute int, log *slog.Logger) *datagramRelay {
	if log == nil {
		log = slog.Default()
	}
	return &datagramRelay{sessions: sessions, clientConn: clientConn, rate: newRateLimiter(maxNewBindsPerMinute), log: log}
}

// serveClientLeg reads until clientConn is closed (relay shutdown).
func (d *datagramRelay) serveClientLeg() {
	buf := make([]byte, readBufSize)
	for {
		n, addr, err := d.clientConn.ReadFrom(buf)
		if err != nil {
			return
		}
		if from, ok := addrPort(addr); ok {
			d.handleClientDatagram(buf[:n], from)
		}
	}
}

// serveServerLeg reads until pc is closed (relay shutdown); it is started
// once per pooled port at Relay.Start and runs for the relay's whole life,
// independent of which session -- if any -- currently owns port.
func (d *datagramRelay) serveServerLeg(pc net.PacketConn, port uint16) {
	buf := make([]byte, readBufSize)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if from, ok := addrPort(addr); ok {
			d.handleServerDatagram(port, buf[:n], from)
		}
	}
}

func addrPort(addr net.Addr) (netip.AddrPort, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return udpAddr.AddrPort(), true
}

// handleClientDatagram processes one datagram received on the shared
// client-facing socket: either a bind/rebind for some session (identified by
// the token it carries, not by from), or -- once bound -- an ordinary
// WireGuard datagram to forward, demuxed by the from address a prior bind
// locked in.
func (d *datagramRelay) handleClientDatagram(b []byte, from netip.AddrPort) {
	if typ, payload, ok := wstransport.DecodeControlFrame(b); ok {
		if typ != wstransport.FrameRelayBind {
			return // e.g. a stray reflector/prime frame that ended up on this socket; not ours
		}
		if !d.rate.allow(from.Addr().String()) {
			d.log.Debug("udp relay: client bind rate limit exceeded", "peer", from)
			return
		}
		if _, ok := d.sessions.BindClient(string(payload), from); !ok {
			return // unknown or expired token: no reply, indistinguishable from a dropped packet
		}
		ack := wstransport.EncodeControlFrame(wstransport.FrameRelayBindAck, nil)
		_, _ = d.clientConn.WriteTo(ack, net.UDPAddrFromAddrPort(from))
		return
	}
	if !wstransport.ValidRelayDatagram(b) {
		return
	}
	sess, ok := d.sessions.LookupByClientAddr(from)
	if !ok {
		// An unrecognized sender on a public, internet-facing UDP socket is
		// routine background noise (scanners, stray retransmits after this
		// session already released); logging every one would itself be a
		// log-amplification vector, so this stays silent.
		return
	}
	serverAddr, serverBound, _, _ := sess.legs()
	if !serverBound {
		return // half-bound session: drop rather than buffer
	}
	sess.touch()
	_, _ = sess.serverConn.WriteTo(b, net.UDPAddrFromAddrPort(serverAddr))
}

// handleServerDatagram processes one datagram received on the pooled socket
// bound to port: either a bind/rebind for the session currently allocated
// that port, or an ordinary WireGuard datagram to forward toward the locked
// client address.
func (d *datagramRelay) handleServerDatagram(port uint16, b []byte, from netip.AddrPort) {
	sess, ok := d.sessions.sessionForPort(port)
	if !ok {
		return // port not currently allocated to any session: stray/late packet, drop
	}
	if typ, payload, ok := wstransport.DecodeControlFrame(b); ok {
		// The port already implies which session this must be, but the
		// frame's token must still match that session's -- never trust the
		// port mapping alone to authenticate a bind, since anyone can send
		// a UDP datagram to a port within the advertised pool.
		if typ != wstransport.FrameRelayBind || string(payload) != sess.token {
			return
		}
		d.sessions.BindServer(sess.token, from)
		ack := wstransport.EncodeControlFrame(wstransport.FrameRelayBindAck, nil)
		_, _ = sess.serverConn.WriteTo(ack, net.UDPAddrFromAddrPort(from))
		return
	}
	if !wstransport.ValidRelayDatagram(b) {
		return
	}
	serverAddr, serverBound, clientAddr, clientBound := sess.legs()
	if !serverBound || from != serverAddr || !clientBound {
		// Not yet bound on one leg or the other (drop, don't buffer), or a
		// sender other than the address this session's server leg locked in
		// at bind time -- the address-lock half of the TURN-style
		// permission model.
		return
	}
	sess.touch()
	_, _ = d.clientConn.WriteTo(b, net.UDPAddrFromAddrPort(clientAddr))
}
