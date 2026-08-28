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
	ap := udpAddr.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// handleClientDatagram processes one datagram received on the shared
// client-facing socket: either a bind/rebind for some session (identified by
// the token it carries, not by from), or -- once bound -- an ordinary
// WireGuard datagram to forward, demuxed by the from address a prior bind
// locked in.
func (d *datagramRelay) handleClientDatagram(b []byte, from netip.AddrPort) {
	if typ, payload, ok := wstransport.DecodeControlFrame(b); ok {
		switch typ {
		case wstransport.FrameRelayBind:
			if !d.rate.allow(from.Addr().String()) {
				d.log.Debug("udp relay: client bind rate limit exceeded", "peer", from)
				return
			}
			if _, ok := d.sessions.BindClient(string(payload), from); !ok {
				return // unknown or expired token: no reply, indistinguishable from a dropped packet
			}
			ack := wstransport.EncodeControlFrame(wstransport.FrameRelayBindAck, nil)
			_, _ = d.clientConn.WriteTo(ack, net.UDPAddrFromAddrPort(from))
		case wstransport.FramePathProbe, wstransport.FramePathAck:
			// The relay never interprets these -- it forwards the opaque
			// frame between an already-bound session pair under exactly the
			// same permission check as an ordinary WireGuard datagram (see
			// forwardFromClient), so multipath-v3's health probing can ride
			// this tier without the relay needing to understand it.
			if wstransport.ValidPathControl(typ, payload) {
				d.forwardFromClient(b, from)
			}
		}
		return // every other recognized control type (including retired frames 8 and 11) stays dropped: e.g. a stray reflector/prime frame that ended up on this socket, not ours
	}
	if !wstransport.ValidRelayDatagram(b) {
		return
	}
	d.forwardFromClient(b, from)
}

// forwardFromClient forwards b -- an ordinary WireGuard datagram, or an
// opaque FramePathProbe/FramePathAck the relay never interprets -- from a
// client-facing sender to its bound session's server leg. Both callers in
// handleClientDatagram share this so a probe/ack frame goes through exactly
// the same token-verified bind/address-lock permission check as every other
// byte this tier relays, never a separately maintained copy of it.
func (d *datagramRelay) forwardFromClient(b []byte, from netip.AddrPort) {
	sess, ok := d.sessions.LookupByClientAddr(from)
	if !ok {
		// An unrecognized sender on a public, internet-facing UDP socket is
		// routine background noise (scanners, stray retransmits after this
		// session already released); logging every one would itself be a
		// log-amplification vector, so this stays silent.
		return
	}
	sess.clientReceived(len(b))
	serverAddr, serverBound, _, _ := sess.legs()
	if !serverBound {
		return // half-bound session: drop rather than buffer
	}
	sess.touch()
	if n, err := sess.serverConn.WriteTo(b, net.UDPAddrFromAddrPort(serverAddr)); err == nil && n == len(b) {
		sess.serverForwarded(n)
	}
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
		switch typ {
		case wstransport.FrameRelayBind:
			// The port already implies which session this must be, but the
			// frame's token must still match that session's -- never trust the
			// port mapping alone to authenticate a bind, since anyone can send
			// a UDP datagram to a port within the advertised pool.
			if string(payload) != sess.token {
				return
			}
			d.sessions.BindServer(sess.token, from)
			ack := wstransport.EncodeControlFrame(wstransport.FrameRelayBindAck, nil)
			_, _ = sess.serverConn.WriteTo(ack, net.UDPAddrFromAddrPort(from))
		case wstransport.FramePathProbe, wstransport.FramePathAck:
			if wstransport.ValidPathControl(typ, payload) {
				d.forwardFromServer(sess, b, from)
			}
		}
		return
	}
	if !wstransport.ValidRelayDatagram(b) {
		return
	}
	d.forwardFromServer(sess, b, from)
}

// forwardFromServer forwards b -- an ordinary WireGuard datagram, or an
// opaque FramePathProbe/FramePathAck -- from a sender on sess's pooled
// server-leg port onto the shared client-facing socket, under the same
// bound/address-lock permission check (sess.legs()) as every other byte this
// tier relays.
func (d *datagramRelay) forwardFromServer(sess *udpRelaySession, b []byte, from netip.AddrPort) {
	serverAddr, serverBound, clientAddr, clientBound := sess.legs()
	if !serverBound || from != serverAddr || !clientBound {
		// Not yet bound on one leg or the other (drop, don't buffer), or a
		// sender other than the address this session's server leg locked in
		// at bind time -- the address-lock half of the TURN-style
		// permission model.
		return
	}
	sess.serverReceived(len(b))
	sess.touch()
	if n, err := d.clientConn.WriteTo(b, net.UDPAddrFromAddrPort(clientAddr)); err == nil && n == len(b) {
		sess.clientForwarded(n)
	}
}
