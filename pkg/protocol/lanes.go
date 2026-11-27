package protocol

import (
	"encoding/json"
	"errors"
	"io"
)

const CapabilityMultiLaneV1 = "multilane-v1"
const CapabilityLaneCarriersV1 = "lane-carriers-v1"
const MaxAdaptiveLanes = 8

// ChildSession inherits only the carrier permissions bound to the parent.
// Each child must qualify its own physical paths under its new lane ID.
func (a AdaptiveSession) ChildSession(laneID string) AdaptiveSession {
	child := AdaptiveSession{
		ParentID: a.ParentID, LaneID: laneID, AuthGeneration: a.AuthGeneration,
		TunnelMTU: a.TunnelMTU, Performance: a.Performance, Child: true,
		RelayCatalog: a.RelayCatalog, RelayUDP: a.RelayUDP, RelaySelect: a.RelaySelect,
		RelayPerformance: a.RelayPerformance,
		PathSelect:       a.RelaySelect,
	}
	if a.LaneCarriers {
		child.DirectUDP, child.AlternateUDP, child.QUIC = a.DirectUDP, a.AlternateUDP, a.QUIC
		child.UDPSelect, child.PathSelect = a.UDPSelect, a.PathSelect
	}
	return child
}

// LaneRequest is scoped to a parent bearer and authorization generation.
// WireGuardPublicKey is required for creation and omitted for retirement.
type LaneRequest struct {
	RequestID          string `json:"request_id"`
	Generation         uint64 `json:"auth_generation"`
	WireGuardPublicKey string `json:"wireguard_public_key,omitempty"`
}

type LaneDescriptor struct {
	Adaptive        AdaptiveSession `json:"adaptive"`
	TunnelIP        string          `json:"tunnel_ip"`
	ServerTunnelIP  string          `json:"server_tunnel_ip"`
	ServerPublicKey string          `json:"server_public_key"`
	TTLSeconds      int             `json:"ttl_seconds"`
	State           string          `json:"state"`
}

type LaneList struct {
	ParentID   string           `json:"parent_id"`
	Generation uint64           `json:"auth_generation"`
	Lanes      []LaneDescriptor `json:"lanes"`
}

// DecodeLaneRequest accepts one object. The HTTP handler limits the body.
func DecodeLaneRequest(r io.Reader) (LaneRequest, error) {
	var request LaneRequest
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || !ValidCarrierID(request.RequestID) || request.Generation == 0 ||
		len(request.WireGuardPublicKey) > 64 {
		return LaneRequest{}, errors.New("invalid lane request")
	}
	return request, nil
}
