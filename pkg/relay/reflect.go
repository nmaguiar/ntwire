package relay

import (
	"log/slog"
	"net"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// reflector answers ntwire's minimal UDP address-reflection protocol (see
// wstransport.EncodeControlFrame/DecodeControlFrame): for every
// FrameReflectRequest it receives, it replies with a FrameReflectResponse
// carrying the sender's observed "ip:port" as seen by the relay. It never
// inspects, decrypts, or forwards anything else -- WireGuard traffic itself
// never reaches this listener, and no per-sender state is kept beyond the
// same per-source rate limiting the public listener already applies. This
// lets a relayed ntwire-server, and the clients connecting to it, learn
// their own NAT-mapped UDP endpoint for the opportunistic direct-connection
// upgrade (see docs/RELAY.md) without the relay becoming a party to any
// session.
type reflector struct {
	conn net.PacketConn
	rate *rateLimiter
	log  *slog.Logger
}

func newReflector(pc net.PacketConn, maxPerMinute int, log *slog.Logger) *reflector {
	if log == nil {
		log = slog.Default()
	}
	return &reflector{conn: pc, rate: newRateLimiter(maxPerMinute), log: log}
}

// serve reads until conn is closed. Unlike the public listener's TCP accept
// loop, a UDP ReadFrom error is never transient in a way worth retrying --
// it means the socket is gone -- so this simply returns.
func (r *reflector) serve() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		r.handle(buf[:n], addr)
	}
}

func (r *reflector) handle(b []byte, addr net.Addr) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	if !r.rate.allow(udpAddr.IP.String()) {
		r.log.Debug("reflector: rate limit exceeded", "peer", addr)
		return
	}
	typ, _, ok := wstransport.DecodeControlFrame(b)
	if !ok || typ != wstransport.FrameReflectRequest {
		return // not our protocol, or a frame type we never expect to receive
	}
	reply := wstransport.EncodeControlFrame(wstransport.FrameReflectResponse, []byte(addr.String()))
	if _, err := r.conn.WriteTo(reply, addr); err != nil {
		r.log.Debug("reflector write failed", "peer", addr, "error", err)
		return
	}
	// Info, not Debug: docs/RELAY.md discloses to operators turning on
	// advertise_direct that "the relay's reflector logs it, for whoever can
	// read the relay's logs" -- that promise should hold at the default log
	// level, not only when debug logging is turned on.
	r.log.Info("reflector: address reflected", "peer", addr)
}
