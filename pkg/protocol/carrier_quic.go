package protocol

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
)

const (
	CapabilityQUICDatagramV1 = "quic-datagram-v1"
	CarrierQUIC              = "quic-datagram"
	CarrierQUICALPN          = "ntwire-wg-dgram/1"
	CarrierQUICReady         = byte(1)
	CarrierQUICCommitted     = byte(2)
	CarrierQUICQualified     = byte(3)
	carrierQUICVersion       = byte(1)
)

// CarrierQUICHello is the fixed-length first control record on a connection
// that has completed TLS. It contains a one-use ticket, never a session bearer.
type CarrierQUICHello struct {
	Lane   CarrierID
	Ticket [32]byte
	Nonce  [32]byte
}

func ParseCarrierTicket(text string) ([32]byte, bool) {
	var raw [32]byte
	if len(text) != 43 {
		return raw, false
	}
	n, err := base64.RawURLEncoding.Strict().Decode(raw[:], []byte(text))
	return raw, err == nil && n == len(raw)
}

func (h CarrierQUICHello) MarshalBinary() []byte {
	var data [81]byte
	data[0] = carrierQUICVersion
	copy(data[1:17], h.Lane[:])
	copy(data[17:49], h.Ticket[:])
	copy(data[49:], h.Nonce[:])
	return data[:]
}

func ReadCarrierQUICHello(r io.Reader) (CarrierQUICHello, error) {
	var data [81]byte
	if _, err := io.ReadFull(r, data[:]); err != nil || data[0] != carrierQUICVersion {
		return CarrierQUICHello{}, errors.New("invalid QUIC carrier hello")
	}
	return CarrierQUICHello{Lane: CarrierID(data[1:17]), Ticket: [32]byte(data[17:49]), Nonce: [32]byte(data[49:])}, nil
}

func CarrierQUICProbe(size int, nonce [32]byte) []byte {
	if size < len(nonce) || size > CarrierWSSDatagramMax {
		return nil
	}
	data := make([]byte, size)
	copy(data, nonce[:])
	return data
}

func ValidCarrierQUICProbe(data []byte, size int, nonce [32]byte) bool {
	if len(data) != size || size < len(nonce) || size > CarrierWSSDatagramMax {
		return false
	}
	var padding byte
	for _, b := range data[len(nonce):] {
		padding |= b
	}
	return padding == 0 && subtle.ConstantTimeCompare(data[:len(nonce)], nonce[:]) == 1
}
