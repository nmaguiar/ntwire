// Package wgnet provides a small, userspace WireGuard plus gVisor-netstack
// wrapper. It deliberately never creates an operating-system interface.
package wgnet

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/nmaguiar/ntwire/pkg/ipfamily"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Key struct{ Private, Public string }

func GenerateKey() (Key, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	return Key{Private: base64.StdEncoding.EncodeToString(private.Bytes()), Public: base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())}, nil
}

type Endpoint struct{ PublicKey, Address string }
type Config struct {
	PrivateKey string
	Addresses  []netip.Addr
	ListenPort int
	// Bind overrides the default UDP transport. It is used by the WebSocket
	// fallback while retaining the same WireGuard device and netstack.
	Bind conn.Bind
	// IPVersion restricts the default UDP transport (used only when Bind is
	// nil) to one IP family: "4" or "6". "" (default) leaves it dual-stack.
	// A caller that supplies its own Bind is responsible for applying this
	// restriction itself -- see pkg/ipfamily and pkg/wstransport's
	// NewHybridClient/NewMultipathHybridClient.
	IPVersion string
}

// Stack owns both the WireGuard device and its in-memory TCP/IP stack.
type Stack struct {
	device *device.Device
	tun    tun.Device
	Net    *netstack.Net
	key    Key
}

func New(c Config) (*Stack, error) {
	key := Key{Private: c.PrivateKey}
	if key.Private == "" {
		var err error
		key, err = GenerateKey()
		if err != nil {
			return nil, err
		}
	}
	raw, err := decodeKey(key.Private)
	if err != nil {
		return nil, fmt.Errorf("invalid WireGuard private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	key.Public = base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	td, ns, err := netstack.CreateNetTUN(c.Addresses, nil, 1420)
	if err != nil {
		return nil, err
	}
	bind := c.Bind
	if bind == nil {
		bind = ipfamily.New(conn.NewStdNetBind(), c.IPVersion)
	}
	d := device.NewDevice(td, bind, device.NewLogger(device.LogLevelSilent, ""))
	// ntwire carries WireGuard keys as Base64, while WireGuard's IPC protocol
	// requires their 32-byte values encoded as hexadecimal.
	lines := "private_key=" + hex.EncodeToString(raw) + "\n"
	if c.ListenPort > 0 {
		lines += "listen_port=" + strconv.Itoa(c.ListenPort) + "\n"
	}
	if err = d.IpcSet(lines); err != nil {
		d.Close()
		return nil, err
	}
	if err = d.Up(); err != nil {
		d.Close()
		return nil, err
	}
	return &Stack{device: d, tun: td, Net: ns, key: key}, nil
}
func (s *Stack) PublicKey() string { return s.key.Public }

// ValidatePublicKey validates the base64 WireGuard public-key representation
// used by ntwire configuration without installing a peer.
func ValidatePublicKey(publicKey string) error {
	_, err := decodeKey(publicKey)
	if err != nil {
		return fmt.Errorf("invalid WireGuard public key: %w", err)
	}
	return nil
}

// PublicKeyFromPrivate derives the base64-encoded WireGuard public key from
// a base64-encoded private key.
func PublicKeyFromPrivate(privateKey string) (string, error) {
	raw, err := decodeKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("invalid WireGuard private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
func (s *Stack) AddPeer(e Endpoint) error {
	public, err := decodeKey(e.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}
	lines := "public_key=" + hex.EncodeToString(public) + "\nreplace_allowed_ips=true\n"
	// Address is an allowed CIDR, optionally followed by @host:port endpoint.
	parts := strings.SplitN(e.Address, "@", 2)
	if parts[0] != "" {
		lines += "allowed_ip=" + parts[0] + "\n"
	}
	if len(parts) == 2 && parts[1] != "" {
		lines += "endpoint=" + parts[1] + "\n"
	}
	return s.device.IpcSet(lines)
}

// UpdateEndpoint reseeds an existing peer's endpoint without touching its
// allowed-ips, unlike AddPeer. It is how the opportunistic direct-UDP
// upgrade both seeds a candidate address for wireguard-go to try, and forces
// a revert back to the WebSocket fallback endpoint if that candidate stalls
// (see pkg/client). addr is resolved through the Bind's ParseEndpoint,
// exactly like a normal "endpoint=" IPC line.
func (s *Stack) UpdateEndpoint(publicKey, addr string) error {
	public, err := decodeKey(publicKey)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}
	return s.device.IpcSet("public_key=" + hex.EncodeToString(public) + "\nendpoint=" + addr + "\n")
}

// LastHandshake returns the time of the most recent completed WireGuard
// handshake with the peer identified by publicKey, and whether that peer is
// currently known to the device at all (found is false, err is nil, if not).
// A known peer that has never completed a handshake reports found=true with
// the zero Unix time (1970-01-01), not a zero time.Time -- callers comparing
// against "how long ago" should treat any implausibly old value the same way.
func (s *Stack) LastHandshake(publicKey string) (t time.Time, found bool, err error) {
	public, err := decodeKey(publicKey)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("invalid peer public key: %w", err)
	}
	want := hex.EncodeToString(public)
	raw, err := s.device.IpcGet()
	if err != nil {
		return time.Time{}, false, err
	}
	var sec, nsec int64
	cur := ""
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			cur = v
		case "last_handshake_time_sec":
			if cur == want {
				found = true
				sec, _ = strconv.ParseInt(v, 10, 64)
			}
		case "last_handshake_time_nsec":
			if cur == want {
				nsec, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	if !found {
		return time.Time{}, false, nil
	}
	return time.Unix(sec, nsec), true, nil
}

// PeerEndpoint returns wireguard-go's current endpoint address for the peer
// identified by publicKey -- its "ip:port" text exactly as IpcGet's
// endpoint= line reports it -- and whether the peer is known to the device
// at all. A known peer that has never had an endpoint seeded (AddPeer with
// no @host:port, and never UpdateEndpoint) reports found=true with an empty
// endpoint, since wireguard-go's IpcGet omits the endpoint= line entirely in
// that case; one seeded with wstransport.WSSentinel reports "0.0.0.0:0",
// since that sentinel deliberately resolves to the unspecified address (see
// wstransport's endpointAddress) rather than a real one. Callers verifying
// the opportunistic direct-UDP upgrade -- pkg/client's directupgrade.go --
// compare this against the candidate they seeded, since a valid packet
// arriving over the WebSocket fallback in the meantime makes wireguard-go's
// own peer roaming silently move the endpoint back on its own.
func (s *Stack) PeerEndpoint(publicKey string) (endpoint string, found bool, err error) {
	public, err := decodeKey(publicKey)
	if err != nil {
		return "", false, fmt.Errorf("invalid peer public key: %w", err)
	}
	want := hex.EncodeToString(public)
	raw, err := s.device.IpcGet()
	if err != nil {
		return "", false, err
	}
	cur := ""
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			cur = v
			if cur == want {
				found = true
			}
		case "endpoint":
			if cur == want {
				endpoint = v
			}
		}
	}
	return endpoint, found, nil
}

func decodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(key))
	}
	return key, nil
}
func (s *Stack) RemovePeer(publicKey string) error {
	if raw, err := decodeKey(publicKey); err == nil {
		publicKey = hex.EncodeToString(raw)
	}
	return s.device.IpcSet("public_key=" + publicKey + "\nremove=true\n")
}
func (s *Stack) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return s.Net.DialContext(ctx, network, address)
}
func (s *Stack) Listen(network, address string) (net.Listener, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported netstack listener network %q", network)
	}
	a, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	return s.Net.ListenTCP(a)
}

// Close tears the device down. It deliberately does not also close s.tun:
// wireguard-go's Device.Close already closes the tun.Device it was built
// with, so closing it again here would double-close the netstack tun's
// internal channels and panic.
//
// RemoveAllPeers is called first, ahead of Close, because Close's own
// internal ordering closes the tun before removing peers (its comment even
// says peers should go first, but the code doesn't). That leaves a window
// where a peer's still-running receive routine can write into the tun
// concurrently with it being closed -- a real data race, not just a benign
// one, since a peer that's mid-handshake or mid-transfer at Close time has
// an actively running routine writing decrypted packets into the tun.
// Removing peers here first stops and waits for those routines (Peer.Stop
// blocks on them) before Close ever touches the tun.
func (s *Stack) Close() error {
	s.device.RemoveAllPeers()
	s.device.Close()
	return nil
}
