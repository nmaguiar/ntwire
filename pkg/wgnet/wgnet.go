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
		bind = conn.NewStdNetBind()
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
func (s *Stack) Close() error { s.device.Close(); return s.tun.Close() }
