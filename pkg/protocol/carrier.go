package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// CapabilityAdaptiveCarrierV1 identifies the isolated adaptive mode. It
// must only be advertised by a controller with authenticated lane support.
const CapabilityAdaptiveCarrierV1 = "adaptive-carrier-v1"

// CapabilityAdaptiveUDPV1 enables qualification on a dedicated UDP socket.
const CapabilityAdaptiveUDPV1 = "adaptive-udp-v1"

// CapabilityAdaptiveUDPSelectV1 permits coordinated selection of a proven native UDP path.
const CapabilityAdaptiveUDPSelectV1 = "adaptive-udp-select-v1"

// CapabilityAdaptiveUDPAltV1 adds a second authenticated native UDP candidate.
const CapabilityAdaptiveUDPAltV1 = "adaptive-udp-alt-v1"

// CapabilityAdaptiveMTUV1 negotiates the fixed MTU of the anchor lane.
const CapabilityAdaptiveMTUV1 = "adaptive-mtu-v1"

// CapabilityAdaptivePerformanceV1 negotiates lane-scoped forwarding feedback.
const CapabilityAdaptivePerformanceV1 = "adaptive-performance-v1"

// CapabilityAdaptivePathSelectV1 separates stream carrier qualification
// from the authenticated primary selection.
const CapabilityAdaptivePathSelectV1 = "adaptive-path-select-v1"

// CapabilityAdaptiveRelayCatalogV1 exposes live relay candidates to a
// negotiated adaptive lane. Allocation and selection are separate.
const CapabilityAdaptiveRelayCatalogV1 = "adaptive-relay-catalog-v1"

// CapabilityAdaptiveRelayUDPV1 enables lane-scoped UDP relay qualification.
const CapabilityAdaptiveRelayUDPV1 = "adaptive-relay-udp-v1"

// CapabilityAdaptiveRelaySelectV1 allows coordinated selection of a qualified relay.
const CapabilityAdaptiveRelaySelectV1 = "adaptive-relay-select-v1"

const CapabilityRelayPerformanceV1 = "relay-performance-v1"
const MaxRelayCandidates = 8

const (
	// CarrierProofMin is the minimum complete UDP probe datagram size.
	CarrierProofMin = 64
	// CarrierProofMax bounds both the proof parser and the hash input.
	CarrierProofMax = 1500

	carrierProofHeader = 40
	carrierProofTag    = 16
	// CarrierProofACKSize is the fixed wire size of an acknowledgement.
	CarrierProofACKSize = carrierProofHeader + carrierProofTag
	carrierProofMagic   = "NTA\x01"
)

type CarrierID [16]byte

// CarrierProofScope is retained on both ends when attaching a candidate.
// The generation and epoch are implicit in the MAC and never taken from
// an unauthenticated UDP datagram.
type CarrierProofScope struct {
	Parent         CarrierID
	Lane           CarrierID
	Candidate      CarrierID
	AuthGeneration uint64
	PathEpoch      uint64
}

type CarrierProofKind byte

const (
	CarrierProbe CarrierProofKind = 1
	CarrierACK   CarrierProofKind = 2
)

type CarrierDirection byte

const (
	CarrierUpload   CarrierDirection = 1
	CarrierDownload CarrierDirection = 2
)

// CarrierProof describes a sized, authenticated reachability challenge.
// An ACK carries the challenged size and direction in a fixed shorter frame.
type CarrierProof struct {
	Kind      CarrierProofKind
	Direction CarrierDirection
	Nonce     CarrierID
	Size      uint16
}

func (p CarrierProof) wireLength() int {
	if p.Nonce == (CarrierID{}) || p.Size < CarrierProofMin || p.Size > CarrierProofMax ||
		(p.Direction != CarrierUpload && p.Direction != CarrierDownload) {
		return 0
	}
	switch p.Kind {
	case CarrierProbe:
		return int(p.Size)
	case CarrierACK:
		return CarrierProofACKSize
	default:
		return 0
	}
}

func (s CarrierProofScope) valid() bool {
	zero := CarrierID{}
	return s.AuthGeneration != 0 && s.Parent != zero && s.Lane != zero && s.Candidate != zero
}

// CarrierProofCandidate retrieves the untrusted lookup hint from a bounded
// proof frame. A caller must verify the matching scope and key separately.
func CarrierProofCandidate(frame []byte) (CarrierID, bool) {
	var candidate CarrierID
	if len(frame) < CarrierProofACKSize || len(frame) > CarrierProofMax || string(frame[:4]) != carrierProofMagic {
		return candidate, false
	}
	copy(candidate[:], frame[6:22])
	return candidate, candidate != (CarrierID{})
}

// IsCarrierProof identifies the reserved prefix even on a malformed frame.
func IsCarrierProof(frame []byte) bool {
	return len(frame) >= len(carrierProofMagic) && string(frame[:len(carrierProofMagic)]) == carrierProofMagic
}

func EncodeCarrierProof(scope CarrierProofScope, key [32]byte, proof CarrierProof) []byte {
	length := proof.wireLength()
	if length == 0 || !scope.valid() || key == ([32]byte{}) {
		return nil
	}
	frame := make([]byte, length)
	copy(frame, carrierProofMagic)
	frame[4], frame[5] = byte(proof.Kind), byte(proof.Direction)
	copy(frame[6:22], scope.Candidate[:])
	copy(frame[22:38], proof.Nonce[:])
	binary.BigEndian.PutUint16(frame[38:carrierProofHeader], proof.Size)
	body := frame[:length-carrierProofTag]
	copy(frame[len(body):], carrierProofMAC(scope, key, body))
	return frame
}

// DecodeCarrierProof authenticates the complete frame, including any padding.
// It does not consume or authorize a nonce. The candidate owner must still
// match a live challenge, generation, direction and observed socket tuple.
func DecodeCarrierProof(scope CarrierProofScope, key [32]byte, frame []byte) (CarrierProof, bool) {
	candidate, ok := CarrierProofCandidate(frame)
	if !ok || candidate != scope.Candidate || !scope.valid() || key == ([32]byte{}) {
		return CarrierProof{}, false
	}
	p := CarrierProof{
		Kind: CarrierProofKind(frame[4]), Direction: CarrierDirection(frame[5]),
		Size: binary.BigEndian.Uint16(frame[38:carrierProofHeader]),
	}
	copy(p.Nonce[:], frame[22:38])
	if p.wireLength() != len(frame) {
		return CarrierProof{}, false
	}
	body := frame[:len(frame)-carrierProofTag]
	if !hmac.Equal(frame[len(body):], carrierProofMAC(scope, key, body)) ||
		len(bytes.Trim(body[carrierProofHeader:], "\x00")) != 0 {
		return CarrierProof{}, false
	}
	return p, true
}

func carrierProofMAC(scope CarrierProofScope, key [32]byte, body []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("ntwire/adaptive-carrier/proof-v1\x00"))
	_, _ = mac.Write(scope.Parent[:])
	_, _ = mac.Write(scope.Lane[:])
	var generation [16]byte
	binary.BigEndian.PutUint64(generation[:8], scope.AuthGeneration)
	binary.BigEndian.PutUint64(generation[8:], scope.PathEpoch)
	_, _ = mac.Write(generation[:])
	_, _ = mac.Write(body)
	return mac.Sum(nil)[:carrierProofTag]
}

// AdaptiveSession describes the anchor lane returned by authenticated
// control-plane operations. PathEpoch is the server's current commit epoch.
type AdaptiveSession struct {
	ParentID         string `json:"parent_id"`
	LaneID           string `json:"anchor_lane_id"`
	AuthGeneration   uint64 `json:"auth_generation"`
	PathEpoch        uint64 `json:"path_epoch"`
	DirectUDP        string `json:"direct_udp,omitempty"`
	AlternateUDP     string `json:"alternate_udp,omitempty"`
	UDPSelect        bool   `json:"udp_select,omitempty"`
	QUIC             string `json:"quic_udp,omitempty"`
	HTTP3            string `json:"h3_carrier,omitempty"`
	HTTP2            bool   `json:"http2_carrier,omitempty"`
	TunnelMTU        int    `json:"tunnel_mtu,omitempty"`
	Performance      bool   `json:"performance,omitempty"`
	PathSelect       bool   `json:"path_select,omitempty"`
	RelayCatalog     bool   `json:"relay_catalog,omitempty"`
	RelayUDP         bool   `json:"relay_udp,omitempty"`
	RelaySelect      bool   `json:"relay_select,omitempty"`
	RelayPerformance bool   `json:"relay_performance,omitempty"`
	MaxLanes         int    `json:"max_lanes,omitempty"`
	LaneCarriers     bool   `json:"lane_carriers,omitempty"`
	Child            bool   `json:"child,omitempty"`
}

// Capabilities returns the transport features bound to this session.
func (a AdaptiveSession) Capabilities() []string {
	caps := []string{CapabilityAdaptiveCarrierV1}
	if a.DirectUDP != "" {
		caps = append(caps, CapabilityAdaptiveUDPV1)
	}
	if a.UDPSelect {
		caps = append(caps, CapabilityAdaptiveUDPSelectV1)
	}
	if a.AlternateUDP != "" {
		caps = append(caps, CapabilityAdaptiveUDPAltV1)
	}
	if a.TunnelMTU != 0 {
		caps = append(caps, CapabilityAdaptiveMTUV1)
	}
	if a.QUIC != "" {
		caps = append(caps, CapabilityQUICDatagramV1)
	}
	if a.HTTP3 != "" {
		caps = append(caps, CapabilityMASQUECarrierV1)
	}
	if a.HTTP2 {
		caps = append(caps, CapabilityHTTP2CarrierV1)
	}
	if a.Performance {
		caps = append(caps, CapabilityAdaptivePerformanceV1)
	}
	if a.PathSelect {
		caps = append(caps, CapabilityAdaptivePathSelectV1)
	}
	if a.RelayCatalog {
		caps = append(caps, CapabilityAdaptiveRelayCatalogV1)
	}
	if a.RelayUDP {
		caps = append(caps, CapabilityAdaptiveRelayUDPV1)
	}
	if a.RelaySelect {
		caps = append(caps, CapabilityAdaptiveRelaySelectV1)
	}
	if a.RelayPerformance {
		caps = append(caps, CapabilityRelayPerformanceV1)
	}
	if a.MaxLanes > 1 {
		caps = append(caps, CapabilityMultiLaneV1)
	}
	if a.LaneCarriers {
		caps = append(caps, CapabilityLaneCarriersV1)
	}
	return caps
}

const (
	CarrierWSS            = "wss"
	CarrierDirectUDP      = "direct-udp"
	CarrierAlternateUDP   = "alternate-udp"
	CarrierRelayUDP       = "relay-udp"
	CarrierWSSPath        = "/v1/transport/wg"
	CarrierTicketHeader   = "X-Ntwire-Attach-Ticket"
	CarrierWSSDatagramMax = 1500
)

func (a AdaptiveSession) NativeUDPAddress(candidate string) string {
	switch candidate {
	case CarrierDirectUDP:
		return a.DirectUDP
	case CarrierAlternateUDP:
		return a.AlternateUDP
	default:
		return ""
	}
}

func IsNativeUDPCarrier(candidate string) bool {
	return candidate == CarrierDirectUDP || candidate == CarrierAlternateUDP
}

type CarrierCandidates struct {
	AdaptiveSession
	Selected string   `json:"selected_candidate_id,omitempty"`
	IDs      []string `json:"candidates"`
}

// RelayCandidateCatalog lists opaque offers for one authenticated lane.
type RelayCandidateCatalog struct {
	LaneID         string   `json:"lane_id"`
	AuthGeneration uint64   `json:"auth_generation"`
	ExpiresInMS    int64    `json:"expires_in_ms"`
	Candidates     []string `json:"candidates"`
	// Members parallels Candidates for performance-capable sessions.
	// Member IDs are opaque, per-registration hints, never allocation authority.
	Members []string `json:"members,omitempty"`
}

// CarrierPerformance is forwarding feedback from an authenticated lane. Its
// clock is elapsed time in the lane's lifetime, with no synchronized clocks
// required. Counters include forwarded protocol framing where applicable.
type CarrierPerformance struct {
	AuthGeneration uint64 `json:"auth_generation"`
	PathEpoch      uint64 `json:"path_epoch"`
	Primary        string `json:"primary"`
	ElapsedUS      uint64 `json:"elapsed_us"`
	ReceivedBytes  uint64 `json:"received_bytes"`
	OfferedBytes   uint64 `json:"offered_bytes"`
	WSSBacklogged  bool   `json:"wss_backlogged,omitempty"`
}

type CarrierAttachRequest struct {
	RequestID     string `json:"request_id"`
	Generation    uint64 `json:"auth_generation"`
	ExpectedEpoch uint64 `json:"expected_path_epoch"`
	Candidate     string `json:"candidate_id"`
}

type CarrierAttachResponse struct {
	Ticket      string `json:"attach_ticket"`
	ExpiresInMS int64  `json:"expires_in_ms"`
	DatagramMax int    `json:"datagram_max"`
}

// CarrierPrimary is the confirmed selection after a successful CAS.
type CarrierPrimary struct {
	Candidate string `json:"selected_candidate_id"`
	PathEpoch uint64 `json:"path_epoch"`
}

type CarrierUDPOffer struct {
	ID          string `json:"offer_id"`
	ProofKey    string `json:"proof_key"`
	DatagramMax int    `json:"datagram_max"`
	ExpiresInMS int64  `json:"expires_in_ms"`
}

// CarrierRelayUDPOffer separates the client-facing address from the server leg.
type CarrierRelayUDPOffer struct {
	CarrierUDPOffer
	RelayAddr string `json:"relay_addr"`
	BindToken string `json:"bind_token"`
}

type CarrierUDPStatus struct {
	Candidate   string `json:"candidate_id"`
	DatagramMax int    `json:"datagram_max"`
	ExpiresInMS int64  `json:"expires_in_ms"`
}

// ValidCarrierID recognizes a canonical opaque 128-bit carrier control ID.
func ValidCarrierID(id string) bool {
	_, ok := ParseCarrierID(id)
	return ok
}

func ParseCarrierID(id string) (CarrierID, bool) {
	if len(id) != 22 {
		return CarrierID{}, false
	}
	var raw CarrierID
	n, err := base64.RawURLEncoding.Strict().Decode(raw[:], []byte(id))
	return raw, err == nil && n == len(raw)
}

// DecodeCarrierAttach accepts exactly one bounded, versioned operation body.
// The caller limits the reader before decoding.
func DecodeCarrierAttach(r io.Reader) (CarrierAttachRequest, error) {
	var request CarrierAttachRequest
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || !ValidCarrierID(request.RequestID) {
		return CarrierAttachRequest{}, fmt.Errorf("invalid carrier attach request")
	}
	return request, nil
}
