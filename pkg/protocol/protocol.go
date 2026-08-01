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
	OS            string            `json:"os,omitempty"`
	Arch          string            `json:"arch,omitempty"`
	Hostname      string            `json:"hostname,omitempty"`
	Username      string            `json:"username,omitempty"`
	ClientVersion string            `json:"client_version,omitempty"`
	LatencyMillis uint64            `json:"latency_millis,omitempty"`
	Reconnections uint64            `json:"reconnections,omitempty"`
	Extra         map[string]string `json:"extra,omitempty"`
}
type AuthRequest struct {
	Version            int        `json:"version"`
	PublicKey          string     `json:"public_key"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	Timestamp          string     `json:"timestamp"`
	Nonce              string     `json:"nonce"`
	Info               ClientInfo `json:"client_info"`
	Signature          string     `json:"signature"`
	// QueryOnly asks the server to report the caller's allowed tunnels
	// without establishing a tunnel session: no WireGuard peer/IP is
	// allocated and the request does not count against
	// max_sessions_per_key. Not part of the signed payload since it only
	// ever narrows what the server does for the caller's own request.
	QueryOnly bool `json:"query_only,omitempty"`
}

// OIDCAuthRequest authenticates with an ID token instead of an SSH signature.
// There is no nonce: the ID token carries its own exp/iat, and the existing
// per-source-IP rate limit bounds replay of a still-valid token.
type OIDCAuthRequest struct {
	Version            int        `json:"version"`
	IssuerName         string     `json:"issuer_name"`
	IDToken            string     `json:"id_token"`
	WireGuardPublicKey string     `json:"wireguard_public_key"`
	Timestamp          string     `json:"timestamp"`
	Info               ClientInfo `json:"client_info"`
	// QueryOnly: see AuthRequest.QueryOnly.
	QueryOnly bool `json:"query_only,omitempty"`
}

// OIDCIssuerInfo advertises an issuer to clients so they can run the login
// flow with zero local configuration.
type OIDCIssuerInfo struct {
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes,omitempty"`
	GroupsClaim string   `json:"groups_claim,omitempty"`
}

type InfoResponse struct {
	Version      int              `json:"version"`
	Capabilities []string         `json:"capabilities"`
	OIDCIssuers  []OIDCIssuerInfo `json:"oidc_issuers,omitempty"`
}
type Tunnel struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	VirtualPort int    `json:"virtual_port"`
	LocalPort   int    `json:"local_port,omitempty"`
	TargetHint  string `json:"target_hint,omitempty"`
	// Instructions is optional Markdown describing how to use this tunnel,
	// expanded as a Go template by the client (see pkg/instructions) so that
	// the real loopback port can appear in the commands it documents.
	Instructions string `json:"instructions,omitempty"`
	// DocsURL is an optional http(s) link to fuller setup documentation.
	DocsURL string `json:"docs_url,omitempty"`
}
type AuthResponse struct {
	SessionID       string   `json:"session_id"`
	Token           string   `json:"token"`
	TunnelIP        string   `json:"tunnel_ip"`
	ServerTunnelIP  string   `json:"server_tunnel_ip,omitempty"`
	ServerPublicKey string   `json:"server_public_key"`
	TTLSeconds      int      `json:"ttl_seconds"`
	Tunnels         []Tunnel `json:"tunnels"`
	UDP             string   `json:"udp_endpoint,omitempty"`
	WebSocket       string   `json:"websocket_endpoint,omitempty"`
	Identity        string   `json:"identity,omitempty"`
	Method          string   `json:"method,omitempty"`
	// ServerName is the operator-configured listen.name, letting a client
	// distinguish several servers it is connected to at once. Empty when
	// unset; clients fall back to the host:port they connected to.
	ServerName string `json:"server_name,omitempty"`
}
type RenewRequest struct {
	Info ClientInfo `json:"client_info"`
}
type Error struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

const (
	ErrorInvalidRequest      = "invalid_request"
	ErrorClockSkew           = "clock_skew"
	ErrorReplayedNonce       = "replayed_nonce"
	ErrorUnknownKey          = "unknown_key"
	ErrorBadSignature        = "bad_signature"
	ErrorRateLimited         = "rate_limited"
	ErrorNotAllowed          = "not_allowed"
	ErrorMaxSessions         = "max_sessions"
	ErrorOIDCInvalidToken    = "oidc_invalid_token"
	ErrorNoCapacity          = "no_capacity"
	ErrorInvalidWireGuardKey = "invalid_wireguard_key"
	ErrorRelayNameNotAllowed = "relay_name_not_allowed"
)

// RelayRegisterRequest is sent by an ntwire-server over its long-lived
// control connection to claim a tenant name on the relay. It authenticates
// with the same sshkey primitives as AuthRequest, but under a distinct
// domain separator (see RelayRegisterPayload) because it binds a Name field
// that SigningPayload does not cover.
type RelayRegisterRequest struct {
	Version   int    `json:"version"`
	PublicKey string `json:"public_key"` // authorized_keys line
	Name      string `json:"name"`       // requested tenant label
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// RelayRegisterResponse answers a RelayRegisterRequest. Name is the
// authoritative label the relay bound to this key (from its own
// registrations config, never the wire), not necessarily an echo of the
// request.
type RelayRegisterResponse struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Error   string `json:"error,omitempty"`
	Code    string `json:"code,omitempty"`
	// ReflectAddr is the relay's UDP address-reflection endpoint (see
	// pkg/relay's reflector), empty when the relay has none configured. A
	// registered ntwire-server uses it to learn its own NAT-mapped UDP
	// address for the opportunistic direct-connection upgrade; it is passed
	// on to clients (via PunchResponse) rather than exposed in relay config,
	// so a client never needs to know the relay's internals directly.
	ReflectAddr string `json:"reflect_addr,omitempty"`
}

// PunchRequest is POSTed by an authenticated client to a relayed server's
// /v1/punch endpoint to exchange candidate UDP addresses for an opportunistic
// direct WireGuard connection, bypassing the relay's TCP/WebSocket fallback.
// ClientAddr is empty on the client's first request, made only to learn
// RelayReflectAddr; the client self-reflects off that address and POSTs
// again with ClientAddr filled in once it knows its own NAT-mapped endpoint.
type PunchRequest struct {
	ClientAddr string `json:"client_addr,omitempty"`
}

// PunchResponse answers a PunchRequest. ServerAddr is the server's own most
// recently self-reflected UDP endpoint, empty if the server has not
// discovered one yet (or does not have direct-upgrade enabled).
// RelayReflectAddr mirrors RelayRegisterResponse.ReflectAddr so the client
// does not need any relay configuration of its own.
type PunchResponse struct {
	ServerAddr       string `json:"server_addr,omitempty"`
	RelayReflectAddr string `json:"relay_reflect_addr,omitempty"`
}

// RelayOpen is pushed by the relay to an ntwire-server's control connection
// each time an inbound client TCP connection is accepted with that server's
// SNI name, instructing it to dial back a data connection carrying ConnID.
type RelayOpen struct {
	ConnID     string `json:"conn_id"`
	ClientAddr string `json:"client_addr"` // real client ip:port
	SNI        string `json:"sni"`
}

// RelayRegisterPayload is a byte-exact, length-prefixed encoding, structured
// identically to SigningPayload, over [PublicKey, Name, Timestamp, Nonce].
// It intentionally uses its own domain separator rather than reusing
// SigningPayload's: SigningPayload has no Name field, so reusing it would
// either leave the tenant name unbound (forgeable) or require stuffing it
// into ClientInfo.Extra, creating a cross-protocol signature-reuse hazard
// between /v1/auth and relay registration.
func RelayRegisterPayload(r RelayRegisterRequest) ([]byte, error) {
	if r.Version != Version {
		return nil, fmt.Errorf("unsupported protocol version %d", r.Version)
	}
	var b bytes.Buffer
	b.WriteString("ntwire-relay-register-v1\x00")
	for _, f := range []string{r.PublicKey, r.Name, r.Timestamp, r.Nonce} {
		if len(f) > 1<<20 {
			return nil, fmt.Errorf("field too large")
		}
		_ = binary.Write(&b, binary.BigEndian, uint32(len(f)))
		b.WriteString(f)
	}
	return b.Bytes(), nil
}

// SigningPayload is a byte-exact, length-prefixed encoding. It intentionally
// does not depend on JSON serialization order.
func SigningPayload(r AuthRequest) ([]byte, error) {
	if r.Version != Version {
		return nil, fmt.Errorf("unsupported protocol version %d", r.Version)
	}
	var b bytes.Buffer
	b.WriteString("ntwire-auth-v1\x00")
	// Telemetry fields in ClientInfo are intentionally excluded here. Keeping
	// this payload stable lets a newer server authenticate existing v1 clients;
	// latency and reconnect counts are operational hints, not authorization data.
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
