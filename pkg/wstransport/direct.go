package wstransport

import (
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// controlMagic marks a datagram as an ntwire control frame rather than
// WireGuard traffic. Byte 0 is 0x00, which a real WireGuard datagram's first
// byte (message type 1-4, little-endian encoded) can never be, so a control
// frame is unambiguous even before the remaining three bytes are checked.
var controlMagic = [4]byte{0x00, 'N', 'T', 'W'}

const (
	// FrameReflectRequest asks the receiver (the relay's reflector) to
	// report the sender's observed source address.
	FrameReflectRequest byte = 1
	// FrameReflectResponse carries that observed address back, encoded as
	// its "ip:port" text form.
	FrameReflectResponse byte = 2
	// FramePrime is a NAT-priming ping sent directly to a peer's candidate
	// address; the receiver may ignore it entirely, its only purpose is to
	// open a local NAT pinhole before WireGuard's own handshake arrives.
	FramePrime byte = 3
)

const controlHeaderLen = 5 // magic(4) + frame type(1)

// PrimeBurst and PrimeInterval bound a NAT-priming burst of FramePrime pings
// (see pkg/client's primeAddr and pkg/server's primeClient). Both ends of a
// punch attempt need their bursts to overlap in time for hole-punching to
// work at all, so this lives here, shared, rather than as two independently
// tuned copies that could silently drift apart.
const PrimeBurst = 4
const PrimeInterval = 150 * time.Millisecond

// ControlPacket is one intercepted, non-WireGuard datagram delivered off
// FilterBind.Control.
type ControlPacket struct {
	Type    byte
	Payload []byte
	From    netip.AddrPort
}

func isControlFrame(b []byte) bool {
	return len(b) >= controlHeaderLen &&
		b[0] == controlMagic[0] && b[1] == controlMagic[1] && b[2] == controlMagic[2] && b[3] == controlMagic[3]
}

// EncodeControlFrame builds a magic-prefixed control frame of the given
// type. Exported so the relay's reflector -- which talks this same wire
// format over a plain net.PacketConn, not a conn.Bind -- can build and parse
// frames without duplicating the framing.
func EncodeControlFrame(typ byte, payload []byte) []byte {
	b := make([]byte, controlHeaderLen+len(payload))
	copy(b, controlMagic[:])
	b[4] = typ
	copy(b[controlHeaderLen:], payload)
	return b
}

// DecodeControlFrame reports whether b is a control frame and, if so, its
// type and payload. The returned payload aliases b.
func DecodeControlFrame(b []byte) (typ byte, payload []byte, ok bool) {
	if !isControlFrame(b) {
		return 0, nil, false
	}
	return b[4], b[controlHeaderLen:], true
}

// FilterBind wraps a conn.Bind -- normally conn.NewStdNetBind() -- and
// intercepts magic-prefixed control frames used for the relay's UDP address
// reflection and NAT-priming pings (see the opportunistic direct WireGuard
// upgrade in pkg/server and pkg/client) before they reach wireguard-go's own
// demux, which would otherwise silently discard them as malformed WireGuard
// packets. Every other datagram passes through unchanged on the same
// receive funcs, so it does not disturb the underlying bind's normal
// receive/send path or batching (e.g. StdNetBind's recvmmsg use).
type FilterBind struct {
	conn.Bind
	control chan ControlPacket
}

// NewFilterBind wraps bind. Control frames beyond the internal 32-entry
// buffer are dropped rather than blocking WireGuard's own receive path --
// reflection and priming are both fire-and-forget and safe to lose.
func NewFilterBind(bind conn.Bind) *FilterBind {
	return &FilterBind{Bind: bind, control: make(chan ControlPacket, 32)}
}

// Control receives intercepted control frames.
func (f *FilterBind) Control() <-chan ControlPacket { return f.control }

func (f *FilterBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := f.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = f.wrapReceive(fn)
	}
	return wrapped, actual, nil
}

// wrapReceive filters control frames out of fn's results in place, shifting
// surviving WireGuard packets down to fill the gaps so the caller sees a
// dense [0:n) slice exactly as any other conn.Bind receive func would
// produce.
func (f *FilterBind) wrapReceive(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		// A batch that turns out to be entirely control frames must not be
		// reported as a zero-packet, no-error return: ReceiveFunc's contract
		// is that it receives at least one packet per call, and
		// wireguard-go's receive loop is not written to tolerate a
		// same-batch (0, nil). Retry the underlying read instead.
		for {
			n, err := fn(bufs, sizes, eps)
			if err != nil {
				return n, err
			}
			out := 0
			for i := 0; i < n; i++ {
				b := bufs[i][:sizes[i]]
				if isControlFrame(b) {
					f.deliverControl(b, eps[i])
					continue
				}
				if out != i {
					bufs[out], sizes[out], eps[out] = bufs[i], sizes[i], eps[i]
				}
				out++
			}
			if out > 0 {
				return out, nil
			}
		}
	}
}

func (f *FilterBind) deliverControl(b []byte, ep conn.Endpoint) {
	addr, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return
	}
	payload := append([]byte(nil), b[controlHeaderLen:]...)
	select {
	case f.control <- ControlPacket{Type: b[4], Payload: payload, From: addr}:
	default:
	}
}

// SendControl sends a raw control frame of the given type to addr, using the
// wrapped bind's own Send/ParseEndpoint so it goes out from the exact same
// local port -- and thus NAT mapping -- that WireGuard traffic itself uses,
// which is essential for a reflected address to be usable for priming.
func (f *FilterBind) SendControl(typ byte, payload []byte, addr string) error {
	ep, err := f.Bind.ParseEndpoint(addr)
	if err != nil {
		return err
	}
	return f.Bind.Send([][]byte{EncodeControlFrame(typ, payload)}, ep)
}
