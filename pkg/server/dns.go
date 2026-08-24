package server

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const typeANY dnsmessage.Type = 255

// startDNS starts the in-tunnel DNS server on UDP port 53 within the netstack.
func (s *Server) startDNS(d *dataPlane) error {
	conn, err := d.stack.ListenUDP("udp", net.JoinHostPort(d.serverIP.String(), "53"))
	if err != nil {
		return fmt.Errorf("in-tunnel DNS listen: %w", err)
	}
	d.dnsConn = conn
	s.log.Debug("in-tunnel DNS server opened", "address", conn.LocalAddr().String())
	go s.dnsLoop(d)
	return nil
}

// dnsLoop reads incoming UDP DNS queries and responds to them.
func (s *Server) dnsLoop(d *dataPlane) {
	buf := make([]byte, 2048)
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
	s.mu.Unlock()

	allowedTunnels := s.allowedTunnelsForPrincipal(principal)
	allowedMap := make(map[string]TunnelConfig, len(allowedTunnels))
	for _, t := range allowedTunnels {
		allowedMap[strings.ToLower(t.Name)] = t
	}

	for _, q := range req.Questions {
		s.resolveDNSQuestion(d, q, principal, domain, allowedTunnels, allowedMap, &resp)
	}

	out, err := resp.Pack()
	if err != nil {
		s.log.Debug("failed to pack DNS response", "error", err)
		return
	}
	_, _ = d.dnsConn.WriteTo(out, fromAddr)
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
