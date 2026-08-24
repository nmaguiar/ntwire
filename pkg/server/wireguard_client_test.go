package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

func TestGenerateWireGuardClientConfig_Defaults(t *testing.T) {
	c := Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	c.Listen.WireGuard = ":51820"

	cfg, err := GenerateWireGuardClientConfig(c, WireGuardClientOptions{})
	if err != nil {
		t.Fatalf("GenerateWireGuardClientConfig failed: %v", err)
	}

	if cfg.ClientAddress != "100.64.0.2/32" {
		t.Errorf("ClientAddress = %q, want 100.64.0.2/32", cfg.ClientAddress)
	}
	if cfg.Endpoint != "vpn.example.com:51820" {
		t.Errorf("Endpoint = %q, want vpn.example.com:51820", cfg.Endpoint)
	}
	if cfg.AllowedIPs != "100.64.0.0/16" {
		t.Errorf("AllowedIPs = %q, want 100.64.0.0/16", cfg.AllowedIPs)
	}
	if cfg.PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive = %d, want 25", cfg.PersistentKeepalive)
	}
	if !cfg.ServerPublicKeySample {
		t.Errorf("ServerPublicKeySample should be true for default config")
	}

	if cfg.DNS != "100.64.0.1" {
		t.Errorf("DNS = %q, want 100.64.0.1", cfg.DNS)
	}

	conf := cfg.Conf()
	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
		t.Errorf("Conf() missing WireGuard sections:\n%s", conf)
	}
	if !strings.Contains(conf, "Address = 100.64.0.2/32") {
		t.Errorf("Conf() missing Address:\n%s", conf)
	}
	if !strings.Contains(conf, "DNS = 100.64.0.1") {
		t.Errorf("Conf() missing DNS:\n%s", conf)
	}
	if !strings.Contains(conf, "PersistentKeepalive = 25") {
		t.Errorf("Conf() missing PersistentKeepalive:\n%s", conf)
	}

	qr, err := cfg.QRCodeText()
	if err != nil {
		t.Fatalf("QRCodeText() failed: %v", err)
	}
	if len(qr) == 0 {
		t.Errorf("QRCodeText() returned empty string")
	}
}

func TestGenerateWireGuardClientConfig_DNSDisabled(t *testing.T) {
	c := Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	disabled := false
	c.Network.DNS.Enabled = &disabled

	cfg, err := GenerateWireGuardClientConfig(c, WireGuardClientOptions{})
	if err != nil {
		t.Fatalf("GenerateWireGuardClientConfig failed: %v", err)
	}
	if cfg.DNS != "" {
		t.Errorf("DNS = %q, want empty when disabled", cfg.DNS)
	}
	conf := cfg.Conf()
	if strings.Contains(conf, "DNS =") {
		t.Errorf("Conf() should not contain DNS = when disabled:\n%s", conf)
	}
}

func TestGenerateWireGuardClientConfig_NativePeers(t *testing.T) {
	c := Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	c.NativeWireGuard.Enabled = true
	c.NativeWireGuard.Peers = []NativeWireGuardPeer{
		{Name: "iphone", TunnelIP: "100.64.0.10", PublicKey: "dummy-key-1"},
		{Name: "laptop", TunnelIP: "100.64.0.20", PublicKey: "dummy-key-2"},
	}

	// Default peer (first)
	cfg1, err := GenerateWireGuardClientConfig(c, WireGuardClientOptions{})
	if err != nil {
		t.Fatalf("GenerateWireGuardClientConfig failed: %v", err)
	}
	if cfg1.PeerName != "iphone" || cfg1.ClientAddress != "100.64.0.10/32" {
		t.Errorf("cfg1 = %+v, want peer iphone / 100.64.0.10/32", cfg1)
	}

	// Specific peer
	cfg2, err := GenerateWireGuardClientConfig(c, WireGuardClientOptions{PeerName: "laptop"})
	if err != nil {
		t.Fatalf("GenerateWireGuardClientConfig failed: %v", err)
	}
	if cfg2.PeerName != "laptop" || cfg2.ClientAddress != "100.64.0.20/32" {
		t.Errorf("cfg2 = %+v, want peer laptop / 100.64.0.20/32", cfg2)
	}

	// Unknown peer
	_, err = GenerateWireGuardClientConfig(c, WireGuardClientOptions{PeerName: "unknown"})
	if err == nil {
		t.Errorf("expected error for unknown peer")
	}
}

func TestGenerateWireGuardClientConfig_WireGuardPrivateKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wireguard.key")

	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(key.Private+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	c := Config{}
	c.Network.TunnelCIDR = "100.64.0.0/16"
	c.Network.WireGuardPrivateKeyFile = keyPath

	cfg, err := GenerateWireGuardClientConfig(c, WireGuardClientOptions{})
	if err != nil {
		t.Fatalf("GenerateWireGuardClientConfig failed: %v", err)
	}

	if cfg.ServerPublicKey != key.Public {
		t.Errorf("ServerPublicKey = %q, want %q", cfg.ServerPublicKey, key.Public)
	}
	if cfg.ServerPublicKeySample {
		t.Errorf("ServerPublicKeySample should be false when loaded from file")
	}
}

func TestGenerateWireGuardClientConfig_RelayAndAdvertisedEndpoint(t *testing.T) {
	cRelay := Config{}
	cRelay.Network.TunnelCIDR = "100.64.0.0/16"
	cRelay.Relay.Enabled = true
	cRelay.Relay.Name = "home"
	cRelay.Relay.URL = "wss://relay.example.com:8444"

	cfg, err := GenerateWireGuardClientConfig(cRelay, WireGuardClientOptions{})
	if err != nil {
		t.Fatalf("GenerateWireGuardClientConfig failed: %v", err)
	}
	if cfg.Endpoint != "home.relay.example.com:51821" {
		t.Errorf("Relay endpoint = %q, want home.relay.example.com:51821", cfg.Endpoint)
	}

	cAdv := Config{}
	cAdv.Network.TunnelCIDR = "100.64.0.0/16"
	cAdv.Network.AdvertisedEndpoint = "custom.vpn.net:51820"

	cfgAdv, err := GenerateWireGuardClientConfig(cAdv, WireGuardClientOptions{})
	if err != nil {
		t.Fatalf("GenerateWireGuardClientConfig failed: %v", err)
	}
	if cfgAdv.Endpoint != "custom.vpn.net:51820" {
		t.Errorf("Advertised endpoint = %q, want custom.vpn.net:51820", cfgAdv.Endpoint)
	}
}

func TestGenerateWireGuardClientConfig_IPv6AndClientKeyOverride(t *testing.T) {
	c := Config{}
	c.Network.TunnelCIDR = "fd00::/64"

	clientKey, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := GenerateWireGuardClientConfig(c, WireGuardClientOptions{
		ClientPrivateKey: clientKey.Private,
		Endpoint:         "198.51.100.1:51820",
		ServerPublicKey:  "dGVzdHNlcnZlcnB1YmxpY2tleTEyMzQ1Njc4OTAxMjM=",
	})
	if err != nil {
		t.Fatalf("GenerateWireGuardClientConfig failed: %v", err)
	}

	if cfg.ClientPrivateKey != clientKey.Private {
		t.Errorf("ClientPrivateKey = %q, want %q", cfg.ClientPrivateKey, clientKey.Private)
	}
	if cfg.ClientPublicKey != clientKey.Public {
		t.Errorf("ClientPublicKey = %q, want %q", cfg.ClientPublicKey, clientKey.Public)
	}
	if cfg.Endpoint != "198.51.100.1:51820" {
		t.Errorf("Endpoint = %q, want 198.51.100.1:51820", cfg.Endpoint)
	}
	if cfg.ServerPublicKey != "dGVzdHNlcnZlcnB1YmxpY2tleTEyMzQ1Njc4OTAxMjM=" {
		t.Errorf("ServerPublicKey mismatch")
	}
	if !strings.HasSuffix(cfg.ClientAddress, "/128") {
		t.Errorf("IPv6 ClientAddress should end with /128, got %q", cfg.ClientAddress)
	}
}
