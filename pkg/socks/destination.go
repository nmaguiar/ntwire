package socks

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ErrInvalidDestination indicates a malformed or unsupported destination.
var ErrInvalidDestination = errors.New("invalid destination")

// Destination retains the requested host and SOCKS wire type for authorization
// and forwarding. AddressType is zero for HTTP and programmatic destinations.
// Host and Port keep their existing names on the attachment protocol.
type Destination struct {
	Host        string
	Port        uint16
	AddressType byte `json:"address_type,omitempty"`
}

// ParseDestination validates a host:port authority without resolving it.
func ParseDestination(address string) (Destination, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return Destination{}, ErrInvalidDestination
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return Destination{}, ErrInvalidDestination
	}
	dst := Destination{Host: host, Port: uint16(n)}
	ip, err := dst.validate()
	if err != nil || address[0] == '[' && !ip.Is6() {
		return Destination{}, ErrInvalidDestination
	}
	return dst, nil
}

// IP returns the canonical numeric address, including for mapped IPv6 literals.
func (d Destination) IP() netip.Addr {
	ip, _ := netip.ParseAddr(d.Host)
	if ip.Zone() != "" {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// NumericDomain reports whether the SOCKS domain field contained an IP literal.
func (d Destination) NumericDomain() bool {
	return d.AddressType == socks5AtypDomain && d.IP().IsValid()
}

// CanonicalHost formats IP literals for routing keys and preserves DNS names.
func (d Destination) CanonicalHost() string {
	if ip := d.IP(); ip.IsValid() {
		return ip.String()
	}
	return d.Host
}

// Address formats a validated host:port, retaining the numeric address family.
// Use ConnectDestination when the original SOCKS wire type matters.
func (d Destination) Address() (string, error) {
	ip, err := d.validate()
	if err != nil {
		return "", err
	}
	if ip.IsValid() {
		return netip.AddrPortFrom(ip, d.Port).String(), nil
	}
	return net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))), nil
}

func (d Destination) validate() (netip.Addr, error) {
	ip, err := parseHost(d.Host)
	if err != nil || d.Port == 0 {
		return netip.Addr{}, ErrInvalidDestination
	}
	switch d.AddressType {
	case 0, socks5AtypDomain:
		return ip, nil
	case socks5AtypIPv4:
		if ip.Is4() {
			return ip, nil
		}
	case socks5AtypIPv6:
		if ip.Is6() {
			return ip, nil
		}
	}
	return netip.Addr{}, errAddressType
}

// parseHost recognizes only unscoped IP literals or the existing DNS character
// set. Reject legacy inet_aton spellings that a resolver might treat as IPs.
func parseHost(host string) (netip.Addr, error) {
	if len(host) == 0 || len(host) > 255 {
		return netip.Addr{}, ErrInvalidDestination
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return netip.Addr{}, ErrInvalidDestination
		}
		return ip, nil
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return netip.Addr{}, ErrInvalidDestination
		}
	}
	name := strings.TrimSuffix(host, ".")
	if len(name) > 253 {
		return netip.Addr{}, ErrInvalidDestination
	}
	numeric := true
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return netip.Addr{}, ErrInvalidDestination
		}
		if numeric && !numericLabel(label) {
			numeric = false
		}
	}
	if numeric {
		return netip.Addr{}, ErrInvalidDestination
	}
	return netip.Addr{}, nil
}

func numericLabel(label string) bool {
	hex := len(label) >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X')
	if hex {
		label = label[2:]
	}
	for _, c := range label {
		if !(c >= '0' && c <= '9' || hex && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func wireDestination(host string, ip netip.Addr, port uint16) (Destination, error) {
	if port == 0 {
		return Destination{}, ErrInvalidDestination
	}
	if ip.Is4() {
		return Destination{Host: ip.String(), Port: port, AddressType: socks5AtypIPv4}, nil
	}
	if ip.Is6() {
		return Destination{Host: ip.String(), Port: port, AddressType: socks5AtypIPv6}, nil
	}
	_, err := parseHost(host)
	return Destination{Host: host, Port: port, AddressType: socks5AtypDomain}, err
}
