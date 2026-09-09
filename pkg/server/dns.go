package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const typeANY dnsmessage.Type = 255

const (
	dnsForwardTimeout = 2 * time.Second
	maxDNSPacketSize  = 65535
)

// Exchange variables keep packet forwarding independently testable without
// requiring the package's authorization tests to open host listeners.
var (
	forwardDNSUDPExchange = forwardDNSUDP
	forwardDNSTCPExchange = forwardDNSTCP
)

// startDNS starts the in-tunnel DNS server on UDP port 53 within the netstack.
func (s *Server) startDNS(d *dataPlane) error {
	conn, err := d.stack.ListenUDP("udp", net.JoinHostPort(d.serverIP.String(), "53"))
	if err != nil {
		return fmt.Errorf("in-tunnel DNS listen: %w", err)
	}
	d.dnsConn = conn
	s.log.Debug("in-tunnel DNS server opened", "address", conn.LocalAddr().String())
	s.mu.Lock()
	forwarding := s.Config.Network.DNS.Forwarding
	s.mu.Unlock()
	if forwarding.Enabled {
		s.log.Info("in-tunnel DNS forwarding enabled", "upstreams", len(forwarding.Upstreams))
	}
	go s.dnsLoop(d)
	return nil
}

// dnsLoop reads incoming UDP DNS queries and responds to them.
func (s *Server) dnsLoop(d *dataPlane) {
	buf := make([]byte, maxDNSPacketSize)
	for {
		n, fromAddr, err := d.dnsConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-d.stop:
				return
			default:
				s.log.Debug("DNS read error", "error", err)
				return
			}
		}
		reqData := make([]byte, n)
		copy(reqData, buf[:n])
		go s.handleDNS(d, reqData, fromAddr)
	}
}

// allowedTunnelsForPrincipal returns the list of configured tunnels permitted for this principal.
func (s *Server) allowedTunnelsForPrincipal(principal DataPlanePrincipal) []TunnelConfig {
	s.mu.Lock()
	tunnels := s.Config.Tunnels
	s.mu.Unlock()
	var out []TunnelConfig
	for _, t := range tunnels {
		if principal.Tunnels[t.Name] {
			out = append(out, t)
		}
	}
	return out
}

// handleDNS unpacks and processes a DNS query from a tunnel peer.
func (s *Server) handleDNS(d *dataPlane, reqBytes []byte, fromAddr net.Addr) {
	var req dnsmessage.Message
	if err := req.Unpack(reqBytes); err != nil {
		return
	}

	clientHost, _, err := net.SplitHostPort(fromAddr.String())
	if err != nil {
		clientHost = fromAddr.String()
	}

	principal, ok := s.principalForIP(clientHost)

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 req.ID,
			Response:           true,
			OpCode:             req.OpCode,
			Authoritative:      true,
			Truncated:          false,
			RecursionDesired:   req.RecursionDesired,
			RecursionAvailable: false,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: req.Questions,
	}

	if !ok {
		resp.RCode = dnsmessage.RCodeRefused
		if out, err := resp.Pack(); err == nil {
			_, _ = d.dnsConn.WriteTo(out, fromAddr)
		}
		return
	}

	s.mu.Lock()
	domain := s.Config.Network.DNS.EffectiveDomain()
	forwarding := s.Config.Network.DNS.Forwarding
	s.mu.Unlock()

	// Keep every ntwire-owned namespace authoritative. A packet containing a
	// local question is deliberately never sent upstream, which also avoids
	// leaking local names in unusual multi-question DNS packets.
	if forwarding.Enabled && allExternalDNSQuestions(req.Questions, domain) {
		select {
		case s.dnsForwardSlots <- struct{}{}:
			defer func() { <-s.dnsForwardSlots }()
		default:
			s.log.Debug("DNS forwarding saturated")
			resp.Authoritative = false
			resp.RecursionAvailable = true
			resp.RCode = dnsmessage.RCodeServerFailure
			s.writeDNSResponse(d, fromAddr, resp)
			return
		}
		out, err := s.dnsForward(reqBytes, forwarding.Upstreams)
		if err == nil {
			s.log.Debug("DNS forwarded query", "upstreams", len(forwarding.Upstreams))
			_, _ = d.dnsConn.WriteTo(out, fromAddr)
			return
		}
		s.log.Debug("DNS forwarding failed", "error", err)
		resp.Authoritative = false
		resp.RecursionAvailable = true
		resp.RCode = dnsmessage.RCodeServerFailure
		s.writeDNSResponse(d, fromAddr, resp)
		return
	}

	allowedTunnels := s.allowedTunnelsForPrincipal(principal)
	allowedMap := make(map[string]TunnelConfig, len(allowedTunnels))
	for _, t := range allowedTunnels {
		allowedMap[strings.ToLower(t.Name)] = t
	}

	for _, q := range req.Questions {
		s.resolveDNSQuestion(d, q, principal, domain, allowedTunnels, allowedMap, &resp)
	}

	s.writeDNSResponse(d, fromAddr, resp)
}

func (s *Server) writeDNSResponse(d *dataPlane, fromAddr net.Addr, resp dnsmessage.Message) {
	out, err := resp.Pack()
	if err != nil {
		s.log.Debug("failed to pack DNS response", "error", err)
		return
	}
	_, _ = d.dnsConn.WriteTo(out, fromAddr)
}

func allExternalDNSQuestions(questions []dnsmessage.Question, domain string) bool {
	if len(questions) == 0 {
		return false
	}
	for _, q := range questions {
		name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
		if isLocalDNSName(name, domain) {
			return false
		}
	}
	return true
}

func isLocalDNSName(name, domain string) bool {
	if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		return true
	}
	_, _, matched := matchDomainPrefix(name, domain)
	return matched
}

// forwardDNS proxies a DNS packet as-is. It retains EDNS and response record
// semantics that would be lost by reconstructing answers one record at a time.
func (s *Server) forwardDNS(query []byte, upstreams []string) ([]byte, error) {
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		return nil, err
	}
	var errs []error
	for i, upstream := range upstreams {
		response, err := forwardDNSUDPExchange(query, upstream)
		if err == nil && dnsResponseMatches(response, request.ID) {
			var msg dnsmessage.Message
			if unpackErr := msg.Unpack(response); unpackErr == nil && msg.Truncated {
				response, err = forwardDNSTCPExchange(query, upstream)
			}
			if err == nil && dnsResponseMatches(response, request.ID) {
				return response, nil
			}
		}
		if err == nil {
			err = errors.New("invalid upstream DNS response")
		}
		errs = append(errs, fmt.Errorf("%s: %w", upstream, err))
		if i+1 < len(upstreams) {
			s.log.Debug("DNS upstream failover", "upstream", upstream, "error", err)
		}
	}
	return nil, errors.Join(errs...)
}

func dnsResponseMatches(raw []byte, id uint16) bool {
	var msg dnsmessage.Message
	return msg.Unpack(raw) == nil && msg.Response && msg.ID == id
}

func forwardDNSUDP(query []byte, upstream string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsForwardTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsForwardTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSPacketSize)
	n, err := conn.Read(buf)
	return buf[:n], err
}

func forwardDNSTCP(query []byte, upstream string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsForwardTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsForwardTimeout))
	if len(query) > maxDNSPacketSize {
		return nil, fmt.Errorf("DNS query exceeds maximum size")
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(query)))
	if _, err := conn.Write(append(size[:], query...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 {
		return nil, fmt.Errorf("empty TCP DNS response")
	}
	response := make([]byte, n)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *Server) resolveDNSQuestion(
	d *dataPlane,
	q dnsmessage.Question,
	principal DataPlanePrincipal,
	domain string,
	allowedTunnels []TunnelConfig,
	allowedMap map[string]TunnelConfig,
	resp *dnsmessage.Message,
) {
	qName := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")

	// Check reverse DNS (in-addr.arpa / ip6.arpa)
	if strings.HasSuffix(qName, ".in-addr.arpa") || strings.HasSuffix(qName, ".ip6.arpa") {
		if q.Type == dnsmessage.TypePTR || q.Type == typeANY {
			if isReverseOf(qName, d.serverIP) {
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypePTR,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.PTRResource{
						PTR: dnsmessage.MustNewName("server." + domain + "."),
					},
				})
				return
			}
			if isReverseOf(qName, principal.TunnelIP) {
				idName := sanitizeLabel(principal.Identity)
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypePTR,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.PTRResource{
						PTR: dnsmessage.MustNewName(idName + "." + domain + "."),
					},
				})
				return
			}
		}
		resp.RCode = dnsmessage.RCodeNameError
		return
	}

	prefix, matchedDomain, matched := matchDomainPrefix(qName, domain)
	if !matched {
		resp.RCode = dnsmessage.RCodeNameError
		return
	}

	// 1. Apex or server gateway query (e.g. ntwire., server.ntwire.)
	if prefix == "" || prefix == "server" || prefix == "gateway" {
		switch q.Type {
		case dnsmessage.TypeA:
			if d.serverIP.Is4() {
				resp.Answers = append(resp.Answers, dnsARecord(q.Name, d.serverIP))
			}
		case dnsmessage.TypeAAAA:
			if d.serverIP.Is6() {
				resp.Answers = append(resp.Answers, dnsAAAARecord(q.Name, d.serverIP))
			}
		case dnsmessage.TypeTXT:
			var names []string
			for _, t := range allowedTunnels {
				names = append(names, t.Name)
			}
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
					TTL:   10,
				},
				Body: &dnsmessage.TXTResource{
					TXT: []string{"ntwire", "version=1", "tunnels=" + strings.Join(names, ",")},
				},
			})
		case dnsmessage.TypeSOA:
			resp.Answers = append(resp.Answers, dnsSOARecord(q.Name, matchedDomain))
		case dnsmessage.TypeNS:
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeNS,
					Class: dnsmessage.ClassINET,
					TTL:   10,
				},
				Body: &dnsmessage.NSResource{
					NS: dnsmessage.MustNewName("server." + matchedDomain + "."),
				},
			})
		}
		return
	}

	// 2. Service discovery discovery query (_ntwire._tcp, _services._dns-sd._udp, _ntwire)
	if prefix == "_ntwire._tcp" || prefix == "_ntwire" || prefix == "_services._dns-sd._udp" || prefix == "_services._tcp" {
		switch q.Type {
		case dnsmessage.TypeSRV, typeANY:
			for _, t := range allowedTunnels {
				tName := strings.ToLower(t.Name)
				targetFQDN := tName + "." + matchedDomain + "."
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypeSRV,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.SRVResource{
						Priority: 0,
						Weight:   0,
						Port:     uint16(t.VirtualPort),
						Target:   dnsmessage.MustNewName(targetFQDN),
					},
				})
				if d.serverIP.Is4() {
					resp.Additionals = append(resp.Additionals, dnsARecord(dnsmessage.MustNewName(targetFQDN), d.serverIP))
				} else if d.serverIP.Is6() {
					resp.Additionals = append(resp.Additionals, dnsAAAARecord(dnsmessage.MustNewName(targetFQDN), d.serverIP))
				}
			}
		case dnsmessage.TypeTXT:
			for _, t := range allowedTunnels {
				txtEntry := fmt.Sprintf("name=%s port=%d target=%s desc=%s", t.Name, t.VirtualPort, t.Target, t.Description)
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypeTXT,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.TXTResource{
						TXT: []string{txtEntry},
					},
				})
			}
		case dnsmessage.TypePTR:
			for _, t := range allowedTunnels {
				ptrTarget := "_" + strings.ToLower(t.Name) + "._tcp." + matchedDomain + "."
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypePTR,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.PTRResource{
						PTR: dnsmessage.MustNewName(ptrTarget),
					},
				})
			}
		case dnsmessage.TypeSOA:
			resp.Answers = append(resp.Answers, dnsSOARecord(q.Name, matchedDomain))
		}
		return
	}

	// 3. Specific SRV query (e.g. _reports._tcp.ntwire or _reports)
	if strings.HasPrefix(prefix, "_") {
		tName := strings.TrimPrefix(strings.TrimSuffix(prefix, "._tcp"), "_")
		t, ok := allowedMap[tName]
		if !ok {
			resp.RCode = dnsmessage.RCodeNameError
			return
		}
		targetFQDN := tName + "." + matchedDomain + "."
		switch q.Type {
		case dnsmessage.TypeSRV, typeANY:
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeSRV,
					Class: dnsmessage.ClassINET,
					TTL:   10,
				},
				Body: &dnsmessage.SRVResource{
					Priority: 0,
					Weight:   0,
					Port:     uint16(t.VirtualPort),
					Target:   dnsmessage.MustNewName(targetFQDN),
				},
			})
			if d.serverIP.Is4() {
				resp.Additionals = append(resp.Additionals, dnsARecord(dnsmessage.MustNewName(targetFQDN), d.serverIP))
			} else if d.serverIP.Is6() {
				resp.Additionals = append(resp.Additionals, dnsAAAARecord(dnsmessage.MustNewName(targetFQDN), d.serverIP))
			}
		case dnsmessage.TypeTXT:
			resp.Answers = append(resp.Answers, dnsTunnelTXTRecord(q.Name, t))
		case dnsmessage.TypeA:
			if d.serverIP.Is4() {
				resp.Answers = append(resp.Answers, dnsARecord(q.Name, d.serverIP))
			}
		case dnsmessage.TypeAAAA:
			if d.serverIP.Is6() {
				resp.Answers = append(resp.Answers, dnsAAAARecord(q.Name, d.serverIP))
			}
		}
		return
	}

	// 4. Target name query (e.g. reports.ntwire)
	t, ok := allowedMap[prefix]
	if !ok {
		resp.RCode = dnsmessage.RCodeNameError
		return
	}

	switch q.Type {
	case dnsmessage.TypeA:
		if d.serverIP.Is4() {
			resp.Answers = append(resp.Answers, dnsARecord(q.Name, d.serverIP))
		}
	case dnsmessage.TypeAAAA:
		if d.serverIP.Is6() {
			resp.Answers = append(resp.Answers, dnsAAAARecord(q.Name, d.serverIP))
		}
	case dnsmessage.TypeSRV:
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeSRV,
				Class: dnsmessage.ClassINET,
				TTL:   10,
			},
			Body: &dnsmessage.SRVResource{
				Priority: 0,
				Weight:   0,
				Port:     uint16(t.VirtualPort),
				Target:   q.Name,
			},
		})
		if d.serverIP.Is4() {
			resp.Additionals = append(resp.Additionals, dnsARecord(q.Name, d.serverIP))
		} else if d.serverIP.Is6() {
			resp.Additionals = append(resp.Additionals, dnsAAAARecord(q.Name, d.serverIP))
		}
	case dnsmessage.TypeTXT:
		resp.Answers = append(resp.Answers, dnsTunnelTXTRecord(q.Name, t))
	case dnsmessage.TypeCNAME:
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeCNAME,
				Class: dnsmessage.ClassINET,
				TTL:   10,
			},
			Body: &dnsmessage.CNAMEResource{
				CNAME: dnsmessage.MustNewName("server." + matchedDomain + "."),
			},
		})
	case dnsmessage.TypeSOA:
		resp.Answers = append(resp.Answers, dnsSOARecord(q.Name, matchedDomain))
	}
}

func matchDomainPrefix(qName, domain string) (prefix string, matchedDomain string, matched bool) {
	domains := []string{domain, "ntwire", "tunnel", "ntwire.internal"}
	for _, d := range domains {
		if d == "" {
			continue
		}
		if qName == d {
			return "", d, true
		}
		if strings.HasSuffix(qName, "."+d) {
			return strings.TrimSuffix(qName, "."+d), d, true
		}
	}
	if !strings.Contains(qName, ".") {
		return qName, domain, true
	}
	return "", "", false
}

func dnsARecord(name dnsmessage.Name, ip netip.Addr) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   10,
		},
		Body: &dnsmessage.AResource{
			A: ip.As4(),
		},
	}
}

func dnsAAAARecord(name dnsmessage.Name, ip netip.Addr) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  name,
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
			TTL:   10,
		},
		Body: &dnsmessage.AAAAResource{
			AAAA: ip.As16(),
		},
	}
}

func dnsSOARecord(name dnsmessage.Name, domain string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  name,
			Type:  dnsmessage.TypeSOA,
			Class: dnsmessage.ClassINET,
			TTL:   10,
		},
		Body: &dnsmessage.SOAResource{
			NS:      dnsmessage.MustNewName("server." + domain + "."),
			MBox:    dnsmessage.MustNewName("hostmaster." + domain + "."),
			Serial:  1,
			Refresh: 300,
			Retry:   60,
			Expire:  86400,
			MinTTL:  10,
		},
	}
}

func dnsTunnelTXTRecord(name dnsmessage.Name, t TunnelConfig) dnsmessage.Resource {
	entries := []string{
		"port=" + strconv.Itoa(t.VirtualPort),
		"target=" + t.Target,
	}
	if t.Description != "" {
		entries = append(entries, "desc="+t.Description)
	}
	if t.DocsURL != "" {
		entries = append(entries, "docs="+t.DocsURL)
	}
	if t.IsSocks() {
		entries = append(entries, "type=socks")
	} else {
		entries = append(entries, "type=tcp")
	}
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  name,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
			TTL:   10,
		},
		Body: &dnsmessage.TXTResource{
			TXT: entries,
		},
	}
}

func reverseARPAName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	if ip.Is6() {
		b := ip.As16()
		var sb strings.Builder
		for i := 15; i >= 0; i-- {
			fmt.Fprintf(&sb, "%x.%x.", b[i]&0x0f, b[i]>>4)
		}
		sb.WriteString("ip6.arpa")
		return sb.String()
	}
	return ""
}

func isReverseOf(arpaName string, ip netip.Addr) bool {
	return strings.EqualFold(strings.TrimSuffix(arpaName, "."), strings.TrimSuffix(reverseARPAName(ip), "."))
}

func sanitizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var sb strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			sb.WriteRune(r)
		} else if r == '@' || r == '.' || r == '_' {
			sb.WriteByte('-')
		}
	}
	res := strings.Trim(sb.String(), "-")
	if res == "" {
		return "client"
	}
	if len(res) > 63 {
		res = res[:63]
	}
	return res
}
