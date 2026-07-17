// Package protocol defines the versioned HTTPS control-plane wire format.
package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
)

const Version = 1

type ClientInfo struct {
	OS, Arch, Hostname, Username, ClientVersion string            `json:"os,omitempty"`
	Extra                                       map[string]string `json:"extra,omitempty"`
}
type AuthRequest struct {
	Version            int        `json:"version"`
	PublicKey          string     `json:"public_key"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	Timestamp          string     `json:"timestamp"`
	Nonce              string     `json:"nonce"`
	Info               ClientInfo `json:"client_info"`
	Signature          string     `json:"signature"`
}
type Tunnel struct {
	Name, Description string `json:"name"`
	VirtualPort       int    `json:"virtual_port"`
	TargetHint        string `json:"target_hint,omitempty"`
}
type AuthResponse struct {
	SessionID, Token, TunnelIP, ServerPublicKey string   `json:"session_id"`
	TTLSeconds                                  int      `json:"ttl_seconds"`
	Tunnels                                     []Tunnel `json:"tunnels"`
	UDP                                         string   `json:"udp_endpoint,omitempty"`
	WebSocket                                   string   `json:"websocket_endpoint,omitempty"`
}
type RenewRequest struct {
	Info ClientInfo `json:"client_info"`
}
type Error struct {
	Error string `json:"error"`
}

// SigningPayload is a byte-exact, length-prefixed encoding. It intentionally
// does not depend on JSON serialization order.
func SigningPayload(r AuthRequest) ([]byte, error) {
	if r.Version != Version {
		return nil, fmt.Errorf("unsupported protocol version %d", r.Version)
	}
	var b bytes.Buffer
	b.WriteString("nwire-auth-v1\x00")
	fields := []string{r.PublicKey, r.WireGuardPublicKey, r.Timestamp, r.Nonce, r.Info.OS, r.Info.Arch, r.Info.Hostname, r.Info.Username, r.Info.ClientVersion}
	keys := make([]string, 0, len(r.Info.Extra))
	for k := range r.Info.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields = append(fields, k, r.Info.Extra[k])
	}
	for _, f := range fields {
		if len(f) > 1<<20 {
			return nil, fmt.Errorf("field too large")
		}
		_ = binary.Write(&b, binary.BigEndian, uint32(len(f)))
		b.WriteString(f)
	}
	return b.Bytes(), nil
}

func ParseTimestamp(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
