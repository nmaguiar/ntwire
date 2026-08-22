package server

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
	qrcode "github.com/skip2/go-qrcode"
)

// WireGuardClientOptions holds optional parameters for generating an official WireGuard client configuration.
type WireGuardClientOptions struct {
	PeerName         string
	ClientPrivateKey string
	ServerPublicKey  string
	Endpoint         string
}

// WireGuardClientConfig represents the computed fields for an official WireGuard client configuration.
type WireGuardClientConfig struct {
	PeerName              string
	ClientPrivateKey      string
	ClientPublicKey       string
	ClientAddress         string
	ServerPublicKey       string
	ServerPublicKeySample bool
	Endpoint              string
	AllowedIPs            string
	PersistentKeepalive   int
}

// Conf returns the WireGuard INI configuration format (.conf).
func (c *WireGuardClientConfig) Conf() string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = %d
`, c.ClientPrivateKey, c.ClientAddress, c.ServerPublicKey, c.Endpoint, c.AllowedIPs, c.PersistentKeepalive)
}

// QRCodeText returns an ASCII/Unicode text representation of the QR code
// encoding the client .conf configuration, suitable for display in terminals.
func (c *WireGuardClientConfig) QRCodeText() (string, error) {
	qr, err := qrcode.New(c.Conf(), qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("generate QR code: %w", err)
	}
	return qr.ToSmallString(false), nil
}

// GenerateWireGuardClientConfig builds a WireGuard client configuration from a server Config.
func GenerateWireGuardClientConfig(c Config, opts WireGuardClientOptions) (*WireGuardClientConfig, error) {
	clientPriv, clientPub, err := deriveClientKey(opts.ClientPrivateKey)
	if err != nil {
		return nil, err
	}
	clientAddr, peerName, err := deriveClientAddress(c, opts.PeerName)
	if err != nil {
		return nil, err
	}
	serverPub, isSample, err := deriveServerPublicKey(c, opts.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	endpoint := deriveEndpoint(c, opts.Endpoint)
	allowedIPs := c.Network.TunnelCIDR
	if allowedIPs == "" {
		allowedIPs = "100.64.0.0/16"
	}
	return &WireGuardClientConfig{
		PeerName:              peerName,
		ClientPrivateKey:      clientPriv,
		ClientPublicKey:       clientPub,
		ClientAddress:         clientAddr,
		ServerPublicKey:       serverPub,
		ServerPublicKeySample: isSample,
		Endpoint:              endpoint,
		AllowedIPs:            allowedIPs,
		PersistentKeepalive:   25,
	}, nil
}

func deriveEndpoint(c Config, override string) string {
	if override != "" {
		return override
	}
	if c.Network.AdvertisedEndpoint != "" {
		return c.Network.AdvertisedEndpoint
	}
	if c.Relay.Enabled {
		port := "51821"
		relayHost := "relay.example.com"
		if c.Relay.URL != "" {
			if u, err := url.Parse(c.Relay.URL); err == nil && u.Hostname() != "" {
				relayHost = u.Hostname()
			}
		} else if len(c.Relay.Endpoints) > 0 && c.Relay.Endpoints[0].URL != "" {
			if u, err := url.Parse(c.Relay.Endpoints[0].URL); err == nil && u.Hostname() != "" {
				relayHost = u.Hostname()
			}
		}
		if c.Relay.Name != "" {
			return fmt.Sprintf("%s.%s:%s", c.Relay.Name, relayHost, port)
		}
		return fmt.Sprintf("%s:%s", relayHost, port)
	}
	port := "51820"
	host := "vpn.example.com"
	if c.Listen.WireGuard != "" {
		h, p, err := net.SplitHostPort(c.Listen.WireGuard)
		if err == nil {
			if p != "" {
				port = p
			}
			if h != "" && h != "0.0.0.0" && h != "::" {
				host = h
			}
		}
	}
	if host == "vpn.example.com" && c.Listen.HTTPS != "" {
		h, _, err := net.SplitHostPort(c.Listen.HTTPS)
		if err == nil && h != "" && h != "0.0.0.0" && h != "::" {
			host = h
		}
	}
	return net.JoinHostPort(host, port)
}

func deriveServerPublicKey(c Config, override string) (pubKey string, isSample bool, err error) {
	if override != "" {
		return override, false, nil
	}
	if c.Network.WireGuardPrivateKeyFile != "" {
		if b, readErr := os.ReadFile(c.Network.WireGuardPrivateKeyFile); readErr == nil {
			keyStr := strings.TrimSpace(string(b))
			if pk, deriveErr := wgnet.PublicKeyFromPrivate(keyStr); deriveErr == nil {
				return pk, false, nil
			}
		}
	}
	sampleKey, err := wgnet.GenerateKey()
	if err != nil {
		return "", false, err
	}
	return sampleKey.Public, true, nil
}

func deriveClientAddress(c Config, peerName string) (address string, name string, err error) {
	cidr := c.Network.TunnelCIDR
	if cidr == "" {
		cidr = "100.64.0.0/16"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", "", fmt.Errorf("invalid network.tunnel_cidr %q: %w", cidr, err)
	}
	is6 := prefix.Addr().Is6()
	mask := "/32"
	if is6 {
		mask = "/128"
	}

	if c.NativeWireGuard.Enabled && len(c.NativeWireGuard.Peers) > 0 {
		if peerName != "" {
			for _, p := range c.NativeWireGuard.Peers {
				if p.Name == peerName {
					return p.TunnelIP + mask, p.Name, nil
				}
			}
			return "", "", fmt.Errorf("native WireGuard peer %q not found", peerName)
		}
		return c.NativeWireGuard.Peers[0].TunnelIP + mask, c.NativeWireGuard.Peers[0].Name, nil
	}

	serverIP := prefix.Addr().Next()
	clientIP := serverIP.Next()
	return clientIP.String() + mask, peerName, nil
}

func deriveClientKey(override string) (privKey string, pubKey string, err error) {
	if override != "" {
		pub, err := wgnet.PublicKeyFromPrivate(override)
		if err != nil {
			return "", "", fmt.Errorf("invalid client private key: %w", err)
		}
		return override, pub, nil
	}
	key, err := wgnet.GenerateKey()
	if err != nil {
		return "", "", err
	}
	return key.Private, key.Public, nil
}
