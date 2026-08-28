// Package protocol defines the versioned HTTPS control-plane wire format.
package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
)

const Version = 1

// CapabilityMultipathV1 and CapabilityMultipathV2 are retired identifiers.
// They remain constants so older configuration/tests can produce a clear
// non-negotiated fallback, but current peers neither offer nor accept them.
const CapabilityMultipathV1 = "multipath-v1"

// Retained only as a retired wire identifier; current peers do not negotiate it.
const CapabilityMultipathV2 = "multipath-v2"

// CapabilityMultipathV3 is the sole supported multipath contract. It includes
// stable logical endpoints, sticky failure-only selection, and bounded
// out-of-band carrier health probes. It never mirrors real tunnel payloads to
// sample a standby path.
const CapabilityMultipathV3 = "multipath-v3"

// CapabilityPathMTUV1 opts a v3 peer into conservative, authenticated path-MTU
// probes. It remains separate so a peer must explicitly opt into the extra
// diagnostic datagrams.
const CapabilityPathMTUV1 = "path-mtu-v1"

// CapabilityNativeWireGuardRelay advertises the optional opaque WireGuard
// forwarding tier used by unmodified official clients.
const CapabilityNativeWireGuardRelay = "native-wireguard-relay-v1"

// CapabilityMASQUERelayV1 advertises the optional, mTLS-authenticated
// Network Relay gateway. It is intentionally separate from WireGuard and
// WebSocket transport capabilities so legacy clients remain unchanged.
const CapabilityMASQUERelayV1 = "masque-relay-v1"

// ErrorUnsupportedCapability is returned when a peer explicitly requires a
// capability the receiving peer cannot provide. Optional capability strings
// remain additive and are deliberately ignored when unknown.
const ErrorUnsupportedCapability = "unsupported_capability"

// ValidateRequiredCapabilities reports a stable, safe error for an unmet
// required capability. Callers should surface ErrorUnsupportedCapability on
// the wire rather than treating it as a version mismatch.
func ValidateRequiredCapabilities(supported, required []string) error {
	for _, want := range required {
		if want == "" {
			return fmt.Errorf("required capability must not be empty")
		}
		if !HasCapability(supported, want) {
			return fmt.Errorf("required capability %q is not supported", want)
		}
	}
	return nil
}

// HasCapability is exact, case-sensitive membership. Capability names are
// protocol identifiers, not user input; trimming or case-folding would turn
// a typo into an unintended feature request.
func HasCapability(caps []string, want string) bool {
	for _, got := range caps {
		if got == want {
			return true
		}
	}
	return false
}

// IntersectCapabilities returns the capabilities offered by both peers in
// offer order, without duplicates or empty strings. It is used only for
// advertised optional features; required capabilities are validated first.
func IntersectCapabilities(offer, supported []string) []string {
	seen := make(map[string]struct{}, len(offer))
	var out []string
	for _, cap := range offer {
		if cap == "" || strings.TrimSpace(cap) != cap || !HasCapability(supported, cap) {
			continue
		}
		if _, ok := seen[cap]; ok {
			continue
		}
		seen[cap] = struct{}{}
		out = append(out, cap)
	}
	return out
}

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
	Version               int        `json:"version"`
	PublicKey             string     `json:"public_key"`
	WireGuardPublicKey    string     `json:"wireguard_public_key"`
	Timestamp             string     `json:"timestamp"`
	Nonce                 string     `json:"nonce"`
	Info                  ClientInfo `json:"client_info"`
	Signature             string     `json:"signature"`
	TransportCapabilities []string   `json:"transport_capabilities,omitempty"`
	// RequiredTransportCapabilities must be supported by the server for this
	// session to be established. It is intentionally unsigned: it can only
	// narrow the requested behavior, and signing it would break v1 clients.
	RequiredTransportCapabilities []string `json:"required_transport_capabilities,omitempty"`
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
	Version                       int        `json:"version"`
	IssuerName                    string     `json:"issuer_name"`
	IDToken                       string     `json:"id_token"`
	WireGuardPublicKey            string     `json:"wireguard_public_key"`
	Timestamp                     string     `json:"timestamp"`
	Info                          ClientInfo `json:"client_info"`
	TransportCapabilities         []string   `json:"transport_capabilities,omitempty"`
	RequiredTransportCapabilities []string   `json:"required_transport_capabilities,omitempty"`
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
	Version      int      `json:"version"`
	Capabilities []string `json:"capabilities"`
	// RequiredCapabilities lets a future server fail a too-old client before
	// authentication. Omission is the legacy-compatible default.
	RequiredCapabilities []string         `json:"required_capabilities,omitempty"`
	OIDCIssuers          []OIDCIssuerInfo `json:"oidc_issuers,omitempty"`
	MASQUE               *MASQUEInfo      `json:"masque,omitempty"`
}

// MASQUEInfo is published only by an enabled gateway. It contains no
// credential, identity, target, or grant material.
type MASQUEInfo struct {
	HTTP2URL     string   `json:"http2_url,omitempty"`
	HTTP3URL     string   `json:"http3_url,omitempty"`
	MatchDomains []string `json:"match_domains"`
}

// MASQUECertificateRequest asks the control plane to sign a freshly generated
// client key. The private key is deliberately never sent to ntwire-server.
// Certificate issuance is available only when the optional MASQUE gateway is
// enabled.
type MASQUECertificateRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// MASQUECertificateResponse contains a short-lived client certificate and the
// public issuing chain needed to configure an mTLS Network Relay identity.
// It never contains a private key or the bearer session token.
type MASQUECertificateResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	IssuerPEM      string    `json:"issuer_pem"`
	ExpiresAt      time.Time `json:"expires_at"`
}
type Tunnel struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	VirtualPort int    `json:"virtual_port"`
	// Protocol is tcp (the backwards-compatible default) or udp.
	Protocol       string        `json:"protocol,omitempty"`
	UDPIdleTimeout time.Duration `json:"udp_idle_timeout,omitempty"`
	LocalPort      int           `json:"local_port,omitempty"`
	// LocalHost is an optional preferred loopback address for the client's
	// local listener (e.g. "127.70.0.1"), letting distinct tunnels share a
	// memorable port without colliding. The client may override it, and
	// falls back to 127.0.0.1 if the address cannot be bound.
	LocalHost  string `json:"local_host,omitempty"`
	TargetHint string `json:"target_hint,omitempty"`
	// Instructions is optional Markdown describing how to use this tunnel,
	// expanded as a Go template by the client (see pkg/instructions) so that
	// the real loopback port can appear in the commands it documents.
	Instructions string `json:"instructions,omitempty"`
	// DocsURL is an optional http(s) link to fuller setup documentation.
	DocsURL string `json:"docs_url,omitempty"`
}

// IsBrowserSocksTarget reports whether targetHint names an embedded SOCKS
// tunnel whose local TCP listener can be used as a SOCKS5 proxy by a browser.
func IsBrowserSocksTarget(targetHint string) bool {
	return targetHint == "socks"
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
	// Multipath is set only by relay-mode servers that implement the stable
	// candidate transport. Older peers omit it, keeping the legacy endpoint
	// upgrade ladder wire-compatible.
	Multipath             bool     `json:"multipath,omitempty"`
	TransportCapabilities []string `json:"transport_capabilities,omitempty"`
	// RequiredTransportCapabilities lists capabilities the server mandates
	// for this session (e.g. it refuses to fall back below multipath-v3).
	// A client that cannot honor one of these should treat the session as
	// unusable rather than silently degrading.
	RequiredTransportCapabilities []string `json:"required_transport_capabilities,omitempty"`
	// ServerName is the operator-configured listen.name, letting a client
	// distinguish several servers it is connected to at once. Empty when
	// unset; clients fall back to the host:port they connected to.
	ServerName string `json:"server_name,omitempty"`
	// PortalEnabled tells clients whether this server has enabled its optional
	// Portal. It is always present so an omitted value from an older server is
	// safely treated as unavailable.
	PortalEnabled bool `json:"portal_enabled"`
}
type RenewRequest struct {
	Info ClientInfo `json:"client_info"`
}
type Error struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

const (
	ErrorInvalidRequest           = "invalid_request"
	ErrorClockSkew                = "clock_skew"
	ErrorReplayedNonce            = "replayed_nonce"
	ErrorUnknownKey               = "unknown_key"
	ErrorBadSignature             = "bad_signature"
	ErrorRateLimited              = "rate_limited"
	ErrorNotAllowed               = "not_allowed"
	ErrorMaxSessions              = "max_sessions"
	ErrorOIDCInvalidToken         = "oidc_invalid_token"
	ErrorNoCapacity               = "no_capacity"
	ErrorInvalidWireGuardKey      = "invalid_wireguard_key"
	ErrorRelayNameNotAllowed      = "relay_name_not_allowed"
	ErrorUDPRelayPoolExhausted    = "udp_relay_pool_exhausted"
	ErrorUDPRelayTenantAtCapacity = "udp_relay_tenant_at_capacity"
)

// SocksTarget describes an embedded SOCKS proxy target advertised by a registered server.
type SocksTarget struct {
	Name          string   `json:"name"`
	LocalPort     int      `json:"local_port,omitempty"`
	VirtualPort   int      `json:"virtual_port,omitempty"`
	TunnelIP      string   `json:"tunnel_ip,omitempty"`
	DomainFilters []string `json:"domain_filters,omitempty"`
	Filters       []string `json:"filters,omitempty"`
}

// RelayRegisterRequest is sent by an ntwire-server over its long-lived
// control connection to claim a tenant name on the relay. It authenticates
// with the same sshkey primitives as AuthRequest, but under a distinct
// domain separator (see RelayRegisterPayload) because it binds a Name field
// that SigningPayload does not cover.
type RelayRegisterRequest struct {
	Version              int           `json:"version"`
	PublicKey            string        `json:"public_key"` // authorized_keys line
	Name                 string        `json:"name"`       // requested tenant label
	Timestamp            string        `json:"timestamp"`
	Nonce                string        `json:"nonce"`
	Signature            string        `json:"signature"`
	ServerVersion        string        `json:"server_version,omitempty"`
	Capabilities         []string      `json:"capabilities,omitempty"`
	RequiredCapabilities []string      `json:"required_capabilities,omitempty"`
	SocksTargets         []SocksTarget `json:"socks_targets,omitempty"`
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
	// UDPRelayAddr is the relay's shared client-facing UDP address for the
	// UDP-relay forwarding tier (see pkg/relay's datagramRelay), empty when
	// the relay has none configured (listen.udp_relay unset). Unlike
	// ReflectAddr, a registered server acts on this unconditionally -- the
	// tier never reveals the server's real address to a client, so there is
	// no advertise_direct-style opt-in gating it. See docs/RELAY.md.
	UDPRelayAddr         string   `json:"udp_relay_addr,omitempty"`
	NativeWireGuardAddr  string   `json:"native_wireguard_addr,omitempty"`
	NativeWireGuardToken string   `json:"native_wireguard_token,omitempty"`
	RelayVersion         string   `json:"relay_version,omitempty"`
	Capabilities         []string `json:"capabilities,omitempty"`
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
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

// TransportPathRequest registers an authenticated client's observed UDP
// address as a candidate for the server-to-client half of a multipath
// session. Unlike PunchRequest it does not disclose a relay-mode server
// address and is therefore safe for ordinary direct servers as well.
//
// The address is learned by sending a reflection frame to the advertised UDP
// endpoint, then is submitted over the existing authenticated HTTPS control
// connection. The server still treats it only as a candidate: probes must
// succeed before its scheduler can select it.
type TransportPathRequest struct {
	Address string `json:"address"`
}

// PunchResponse answers a PunchRequest. ServerAddr is the server's own most
// recently self-reflected UDP endpoint, empty if the server has not
// discovered one yet (or does not have direct-upgrade enabled).
// RelayReflectAddr mirrors RelayRegisterResponse.ReflectAddr so the client
// does not need any relay configuration of its own.
type PunchResponse struct {
	ServerAddr       string `json:"server_addr,omitempty"`
	RelayReflectAddr string `json:"relay_reflect_addr,omitempty"`
	// Candidates is an ordered set of matching reflector/server mappings for
	// an active-active relay pool. Keeping the legacy fields above lets older
	// clients use the first candidate unchanged.
	Candidates []DirectCandidate `json:"candidates,omitempty"`
}

// DirectCandidate is one destination-specific NAT-punch pair. ServerAddr is
// only valid with its matching RelayReflectAddr, because symmetric NATs may
// allocate a different mapping for every reflector destination.
type DirectCandidate struct {
	ServerAddr       string `json:"server_addr,omitempty"`
	RelayReflectAddr string `json:"relay_reflect_addr,omitempty"`
}

// UDPRelayRequest is POSTed by a client to a relayed server's
// POST /v1/udp-relay endpoint to obtain (or, on a repeat call for the same
// WireGuard identity, be reminded of) a session on the relay's UDP
// forwarding tier -- the middle rung between the WebSocket fallback and the
// full direct-UDP escape (POST /v1/punch). Unlike /v1/punch, this tier never
// reveals the server's real address to the client: the relay stays in the
// data path for the session's whole life, forwarding between two UDP legs
// it allocated, so it carries the same trust exposure as the default
// WSS-through-relay path -- see docs/SECURITY.md. Stats is the only optional
// field: there is nothing else for the client to supply, unlike
// PunchRequest's ClientAddr exchange.
type UDPRelayRequest struct {
	// Stats, when present, is this client's own cumulative observation of
	// its client<->relay UDP-relay leg -- see ClientUDPRelayStats' doc
	// comment for why this closes the hop-telemetry loop. Riding this
	// request rather than a new endpoint or wire frame keeps the report
	// authenticated (this endpoint is already session-token-protected) and
	// needs no new capability negotiation: the client's existing upgrade
	// ladder already calls this endpoint on every retry, revert, and
	// renewal (see pkg/server/udprelay.go's sessionFor), so this simply
	// rides along.
	Stats *ClientUDPRelayStats `json:"stats,omitempty"`
}

// ClientUDPRelayStats is the client's own cumulative byte/packet counters
// for its client<->relay UDP-relay leg, counted independently of anything
// the relay or server observe. Comparing this against the relay's own
// client-facing-leg counters (UDPRelayHopStats' ClientPacketsReceived etc,
// already reported relay->server over /v1/relay/control) is what lets a
// loss localize to specifically the client<->relay leg rather than
// relay<->server. Cumulative since the client's current UDP-relay session
// (token) began, not a rolling window -- the same cumulative-snapshot
// convention the relay's own RelayUDPStats already uses, so no window
// alignment is needed between client, relay, and server. Best-effort
// diagnostics only, like every other counter in this codebase: never used
// for billing or a security decision.
type ClientUDPRelayStats struct {
	BytesSent       uint64 `json:"bytes_sent"`
	PacketsSent     uint64 `json:"packets_sent"`
	BytesReceived   uint64 `json:"bytes_received"`
	PacketsReceived uint64 `json:"packets_received"`
}

// UDPRelayResponse answers UDPRelayRequest. All fields empty means "this
// rung isn't available right now" (no live relay connection, the relay
// doesn't offer the tier, or allocation failed) -- treated by the client
// exactly like a 404 from /v1/punch, not a hard error.
type UDPRelayResponse struct {
	RelayAddr string `json:"relay_addr,omitempty"`
	Token     string `json:"token,omitempty"`
	Error     string `json:"error,omitempty"`
	Code      string `json:"code,omitempty"`
	// Stats is the server's best-known hop-telemetry summary for this
	// session -- the relay's own client-facing/server-facing leg counters,
	// plus (once received) this same client's own most recently reported
	// ClientUDPRelayStats -- so the client's local diagnostics can see the
	// same localized-loss picture the server's dashboard does, not just
	// contribute to it. Omitted until at least one relay stats report has
	// arrived for this session.
	Stats *UDPRelayHopStats `json:"stats,omitempty"`
}

// UDPRelayHopStats is UDPRelayResponse.Stats' payload: the token-free,
// client-facing form of one UDP-relay allocation's cumulative hop counters
// as observed by the relay itself (both legs), plus this client's own most
// recently reported leg counters. It deliberately carries neither the
// allocation token nor either peer address, the same restriction
// RelayUDPStats documents.
type UDPRelayHopStats struct {
	ClientPacketsReceived  uint64 `json:"client_packets_received"`
	ClientBytesReceived    uint64 `json:"client_bytes_received"`
	ServerPacketsForwarded uint64 `json:"server_packets_forwarded"`
	ServerBytesForwarded   uint64 `json:"server_bytes_forwarded"`
	ServerPacketsReceived  uint64 `json:"server_packets_received"`
	ServerBytesReceived    uint64 `json:"server_bytes_received"`
	ClientPacketsForwarded uint64 `json:"client_packets_forwarded"`
	ClientBytesForwarded   uint64 `json:"client_bytes_forwarded"`
	// ClientObserved echoes back this same client's own most recently
	// reported UDP-relay leg counters (see UDPRelayRequest.Stats), so
	// client-side diagnostics don't need to remember what they last sent.
	ClientObserved *ClientUDPRelayStats `json:"client_observed,omitempty"`
}

// RelayOpen is pushed by the relay to an ntwire-server's control connection
// each time an inbound client TCP connection is accepted with that server's
// SNI name, instructing it to dial back a data connection carrying ConnID.
// It carries no "type" discriminator field, unlike the UDP-relay allocation
// messages below -- it predates that convention, and every relay/server pair
// must keep dispatching an untyped message as RelayOpen so a relay or server
// upgraded ahead of its peer degrades gracefully. See docs/PROTOCOL.md.
type RelayOpen struct {
	ConnID     string `json:"conn_id"`
	ClientAddr string `json:"client_addr"` // real client ip:port
	SNI        string `json:"sni"`
}

// RelayUDPAllocateRequest/Response multiplex a request/response pair over
// the same long-lived /v1/relay/control WebSocket used for the one-shot
// registration handshake and the one-way RelayOpen pushes. RequestID
// correlates a reply to its request, since that connection can now carry
// more than one concurrent request at a time (one per connecting client
// asking the server for a UDP-relay session).
type RelayUDPAllocateRequest struct {
	Type      string `json:"type"` // "udp_allocate"
	RequestID string `json:"request_id"`
}
type RelayUDPAllocateResponse struct {
	Type       string `json:"type"` // "udp_allocate_reply"
	RequestID  string `json:"request_id"`
	Token      string `json:"token,omitempty"`
	ServerAddr string `json:"server_addr,omitempty"`
	Error      string `json:"error,omitempty"`
	Code       string `json:"code,omitempty"`
}

// RelayUDPRelease is a one-way, best-effort hint that a UDP-relay session is
// done and its relay-side port can be reclaimed immediately rather than
// waiting out the idle timeout; the idle timeout is the backstop if it never
// arrives (process crash, or a control connection already down).
type RelayUDPRelease struct {
	Type  string `json:"type"` // "udp_release"
	Token string `json:"token"`
}

// RelayUDPStats is one opaque UDP-relay session's cumulative forwarding
// counters. It deliberately contains no packet payload, peer address, or
// identity: the allocation token is already a bearer capability shared only
// by the authenticated server and its relay. Counts are best-effort transport
// diagnostics, not an acknowledgement protocol or a billing record.
type RelayUDPStats struct {
	Token                  string `json:"token"`
	ClientPacketsReceived  uint64 `json:"client_packets_received"`
	ClientBytesReceived    uint64 `json:"client_bytes_received"`
	ServerPacketsForwarded uint64 `json:"server_packets_forwarded"`
	ServerBytesForwarded   uint64 `json:"server_bytes_forwarded"`
	ServerPacketsReceived  uint64 `json:"server_packets_received"`
	ServerBytesReceived    uint64 `json:"server_bytes_received"`
	ClientPacketsForwarded uint64 `json:"client_packets_forwarded"`
	ClientBytesForwarded   uint64 `json:"client_bytes_forwarded"`
}

// RelayUDPStatsReport is pushed from a relay to the registered server over
// their existing authenticated /v1/relay/control WebSocket. An absent report
// is always safe to ignore: older relays do not send it and reports may be
// dropped while the control connection is reconnecting.
type RelayUDPStatsReport struct {
	Type     string          `json:"type"` // "udp_stats"
	Sessions []RelayUDPStats `json:"sessions"`
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
