package socks

import (
	"net/netip"
	"strings"
)

// FilterConfig mirrors socksd's (openaf-opacks/SocksServer/socksServer.js)
// getNetFilter/getLocalNetFilter feature set: destination CIDR allow-lists,
// destination hostname-suffix allow-lists, destination ASN allow-lists, an
// only-local override, and a reverse (allow -> deny) inversion.
type FilterConfig struct {
	OnlyLocal      bool
	CIDRs          []string
	DomainSuffixes []string
	ASNs           []uint32
	Invert         bool

	// AllowAll is an ntwire-only addition (socksd has no equivalent): when
	// no filters are configured at all, socksd defaults to allow-all. That
	// default would make an authenticated ntwire session a silent open
	// egress proxy, so ntwire instead defaults to deny-all in that case
	// unless AllowAll is explicitly set.
	AllowAll bool

	// AllowLocalEgress lifts the loopback/link-local floor below. It exists
	// for the legitimate "proxy to a service on the server host" case and is
	// reported as a security capability, because it re-exposes the server's
	// own loopback and its cloud metadata endpoint to every session holding
	// the tunnel's grant.
	AllowLocalEgress bool
}

// deniedByDefault are destination classes no filter configuration reaches: the
// server's own loopback, the link-local range that carries cloud instance
// metadata (169.254.169.254 and its IPv6 equivalent), and the unspecified
// address.
//
// Without this, socks.allow_all -- or any filter set an operator wrote thinking
// only about external destinations -- turns an authenticated tunnel into a
// request forgery primitive against services that trust the server's own
// address. Set AllowLocalEgress to opt back in deliberately.
func deniedByDefault(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsValid() ||
		ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

// localCIDRs matches socksd's getLocalNetFilter(): the private ranges used
// when ONLY_LOCAL=true. This list intentionally ignores any user-configured
// CIDRs/domains/ASNs/invert, exactly as socksd's ONLY_LOCAL does.
var localCIDRs = mustParsePrefixes([]string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
})

func mustParsePrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			panic("socks: invalid built-in CIDR " + c + ": " + err.Error())
		}
		out[i] = p
	}
	return out
}

// ASNLookup resolves a destination IP to its announcing ASN, if known.
type ASNLookup interface {
	Lookup(ip netip.Addr) (asn uint32, ok bool)
}

// Filter is the compiled, ready-to-evaluate form of a FilterConfig.
type Filter struct {
	allowLocal bool
	onlyLocal  bool
	cidrs      []netip.Prefix
	domains    []string
	asns       map[uint32]struct{}
	invert     bool
	allowAll   bool
	hasFilters bool
	asnLookup  ASNLookup
}

// NewFilter compiles cfg into a Filter. asnLookup may be nil; it is only
// consulted when cfg.ASNs is non-empty.
func NewFilter(cfg FilterConfig, asnLookup ASNLookup) (*Filter, error) {
	cidrs := make([]netip.Prefix, 0, len(cfg.CIDRs))
	for _, c := range cfg.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, p)
	}
	asns := make(map[uint32]struct{}, len(cfg.ASNs))
	for _, a := range cfg.ASNs {
		asns[a] = struct{}{}
	}
	return &Filter{
		allowLocal: cfg.AllowLocalEgress,
		onlyLocal:  cfg.OnlyLocal,
		cidrs:      cidrs,
		domains:    cfg.DomainSuffixes,
		asns:       asns,
		invert:     cfg.Invert,
		allowAll:   cfg.AllowAll,
		hasFilters: len(cidrs) > 0 || len(cfg.DomainSuffixes) > 0 || len(asns) > 0 || cfg.Invert,
		asnLookup:  asnLookup,
	}, nil
}

// Allowed reports whether a connection to the destination (hostname, ip) may
// proceed. hostname is the name the client asked to connect to (SOCKS5
// domain requests only; empty for IP-literal requests) and ip is the
// destination address that will actually be dialed (post-resolution for
// domain requests). Both are consulted, matching socksd: CIDR/ASN filters
// match the resolved IP, domain filters match the requested hostname.
//
// This ports socksd's getNetFilter/getLocalNetFilter algorithm faithfully,
// including one non-obvious interaction: when both CIDR and domain filters
// are configured, a CIDR/ASN miss short-circuits to deny without consulting
// the domain filters, but a CIDR/ASN *hit* does not by itself allow the
// connection -- the domain suffix check still runs and is decisive. ASN-only
// (no CIDR) configurations do not gate the domain check at all, mirroring
// socksd's use of `filters.length > 0` (the CIDR list only) for that veto.
func (f *Filter) Allowed(hostname string, ip netip.Addr) bool {
	// Evaluated before onlyLocal, allowAll and invert, so no configuration can
	// reach these destinations by accident and invert cannot turn the floor
	// into an allow.
	if !f.allowLocal && deniedByDefault(ip) {
		return false
	}
	if f.onlyLocal {
		return matchesAnyCIDR(ip, localCIDRs)
	}
	if !f.hasFilters {
		return f.allowAll
	}

	cidrMatch := matchesAnyCIDR(ip, f.cidrs)
	asnMatch := false
	if !cidrMatch && len(f.asns) > 0 && f.asnLookup != nil {
		if asn, ok := f.asnLookup.Lookup(ip); ok {
			_, asnMatch = f.asns[asn]
		}
	}
	netMatch := cidrMatch || asnMatch

	var match bool
	switch {
	case len(f.domains) == 0:
		match = netMatch
	case len(f.cidrs) > 0 && !netMatch:
		match = false
	default:
		match = matchesDomainSuffix(hostname, f.domains)
	}

	if f.invert {
		return !match
	}
	return match
}

func matchesAnyCIDR(ip netip.Addr, prefixes []netip.Prefix) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, p := range prefixes {
		if p.Addr().Is4() != ip.Is4() {
			continue
		}
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func matchesDomainSuffix(hostname string, suffixes []string) bool {
	if hostname == "" {
		return false
	}
	for _, suf := range suffixes {
		if suf != "" && strings.HasSuffix(hostname, suf) {
			return true
		}
	}
	return false
}
