package server

import (
	"net/netip"
	"os"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/wgnet"
)

func TestDestinationPolicyCIDRProtocolAndPort(t *testing.T) {
	p, err := compilePolicy(DestinationPolicy{Filters: []string{"203.0.113.0/24"}, Protocols: []string{"tcp"}, Ports: []uint16{443}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := DestinationContext{IP: netip.MustParseAddr("203.0.113.4"), Protocol: "tcp", Port: 443}
	if !p.decide(base).Allowed {
		t.Fatal("matching destination denied")
	}
	base.Port = 80
	if p.decide(base).Allowed {
		t.Fatal("wrong port allowed")
	}
	base.Port = 443
	base.Protocol = "udp"
	if p.decide(base).Allowed {
		t.Fatal("wrong protocol allowed")
	}
	base.Protocol = "tcp"
	base.IP = netip.MustParseAddr("198.51.100.2")
	if p.decide(base).Allowed {
		t.Fatal("wrong CIDR allowed")
	}
}

func TestDestinationPolicyDomainReverseAndDefaultDeny(t *testing.T) {
	p, err := compilePolicy(DestinationPolicy{DomainFilters: []string{".corp.example"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.decide(DestinationContext{Hostname: "db.corp.example", IP: netip.MustParseAddr("203.0.113.1")}).Allowed {
		t.Fatal("domain denied")
	}
	if p.decide(DestinationContext{Hostname: "db.public.example", IP: netip.MustParseAddr("203.0.113.1")}).Allowed {
		t.Fatal("other domain allowed")
	}
	r, err := compilePolicy(DestinationPolicy{Filters: []string{"10.0.0.0/8"}, ReverseFilters: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.decide(DestinationContext{IP: netip.MustParseAddr("10.0.0.1")}).Allowed || !r.decide(DestinationContext{IP: netip.MustParseAddr("203.0.113.1")}).Allowed {
		t.Fatal("reverse filter semantics wrong")
	}
}

func TestNativePeerConfigValidation(t *testing.T) {
	key, err := wgnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/ntwire.yaml"
	text := "auth:\n  authorized_keys_dir: keys\ntunnels:\n  - name: reports\n    target: 127.0.0.1:443\n    virtual_port: 443\ndestination_policies:\n  corp:\n    filters: [127.0.0.0/8]\nnative_wireguard:\n  enabled: true\n  peers:\n    - name: phone\n      public_key: " + key.Public + "\n      tunnel_ip: 100.64.0.10\n      tunnels: [reports]\n      destination_policy: corp\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.NativeWireGuard.Peers) != 1 {
		t.Fatal("native peer not loaded")
	}
}
