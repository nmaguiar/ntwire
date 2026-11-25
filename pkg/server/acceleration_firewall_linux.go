//go:build linux

package server

import (
	"encoding/binary"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type kernelFirewall struct {
	conn    *nftables.Conn
	table   *nftables.Table
	input   *nftables.Chain
	forward *nftables.Chain
	tcp     *nftables.Set
	udp     *nftables.Set
}

func newKernelFirewall(service netip.Addr) (*kernelFirewall, error) {
	// The lasting socket is opened by the namespace worker and cannot later
	// open a netfilter socket in the original namespace.
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, err
	}
	firewall := &kernelFirewall{conn: conn}
	firewall.table = conn.AddTable(&nftables.Table{Name: "ntwire", Family: nftables.TableFamilyINet})
	drop := nftables.ChainPolicyDrop
	firewall.input = conn.AddChain(&nftables.Chain{
		Name: "input", Table: firewall.table, Hooknum: nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter, Policy: &drop, Type: nftables.ChainTypeFilter,
	})
	firewall.forward = conn.AddChain(&nftables.Chain{
		Name: "forward", Table: firewall.table, Hooknum: nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter, Policy: &drop, Type: nftables.ChainTypeFilter,
	})
	firewall.tcp = &nftables.Set{Name: "tcp_ports", Table: firewall.table, KeyType: nftables.TypeInetService}
	firewall.udp = &nftables.Set{Name: "udp_ports", Table: firewall.table, KeyType: nftables.TypeInetService}
	for _, ports := range []*nftables.Set{firewall.tcp, firewall.udp} {
		if err := conn.AddSet(ports, nil); err != nil {
			_ = conn.CloseLasting()
			return nil, err
		}
	}

	inputInterface := func(name string) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(name), 0)},
		}
	}
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	conn.AddRule(&nftables.Rule{Table: firewall.table, Chain: firewall.input, Exprs: append(inputInterface("lo"), accept)})
	family, offset := byte(unix.NFPROTO_IPV4), uint32(16)
	icmpProtocol := byte(unix.IPPROTO_ICMP)
	if service.Is6() {
		family, offset = unix.NFPROTO_IPV6, 24
		icmpProtocol = unix.IPPROTO_ICMPV6
	}
	destination := service.AsSlice()
	serviceProtocol := func(protocol byte) []expr.Any {
		return append(inputInterface(kernelInterface),
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(destination))},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: destination},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
		)
	}
	// Preserve tunnel-address ping and IP control messages needed for PMTU.
	conn.AddRule(&nftables.Rule{Table: firewall.table, Chain: firewall.input, Exprs: append(serviceProtocol(icmpProtocol), accept)})
	for _, protocol := range []struct {
		number byte
		ports  *nftables.Set
	}{{unix.IPPROTO_TCP, firewall.tcp}, {unix.IPPROTO_UDP, firewall.udp}} {
		conn.AddRule(&nftables.Rule{Table: firewall.table, Chain: firewall.input, Exprs: append(serviceProtocol(protocol.number),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Lookup{SourceRegister: 1, SetName: protocol.ports.Name, SetID: protocol.ports.ID},
			accept,
		)})
	}
	for _, chain := range []*nftables.Chain{firewall.input, firewall.forward} {
		conn.AddRule(&nftables.Rule{Table: firewall.table, Chain: chain, Exprs: []expr.Any{
			&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop},
		}})
	}
	if err := conn.Flush(); err != nil {
		_ = conn.CloseLasting()
		return nil, err
	}
	return firewall, nil
}

func (f *kernelFirewall) updatePort(udp bool, port uint16, open bool) error {
	ports := f.tcp
	if udp {
		ports = f.udp
	}
	element := []nftables.SetElement{{Key: binary.BigEndian.AppendUint16(nil, port)}}
	update := f.conn.SetDeleteElements
	if open {
		update = f.conn.SetAddElements
	}
	if err := update(ports, element); err != nil {
		return err
	}
	return f.conn.Flush()
}

func (f *kernelFirewall) drops() (uint64, bool) {
	var dropped uint64
	for _, chain := range []*nftables.Chain{f.input, f.forward} {
		rules, err := f.conn.GetRules(f.table, chain)
		if err != nil {
			return 0, false
		}
		for _, rule := range rules {
			for _, expression := range rule.Exprs {
				if counter, ok := expression.(*expr.Counter); ok {
					dropped += counter.Packets
				}
			}
		}
	}
	return dropped, true
}
