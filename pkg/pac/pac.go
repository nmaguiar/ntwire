package pac

import (
	"fmt"
	"net"
	"strings"
)

// ContentType is the standard MIME type for Proxy Auto-Configuration (.pac) files.
const ContentType = "application/x-ns-proxy-autoconfig"

// Generate builds the JavaScript source for a Proxy Auto-Configuration (PAC) file
// that routes Kubernetes internal services, local networks, and configured destination
// filters through a SOCKS proxy, while bypassing all other traffic (DIRECT).
//
// When host is empty or "127.0.0.1", it generates a localhost-targeting PAC file suitable
// for desktop/laptop OS where the ntwire client runs locally.
// When host is an explicit address (e.g. WireGuard netstack IP like "100.64.0.1" for iOS
// official WireGuard app clients), it targets that server tunnel address.
//
// It addresses iOS and mobile platform restrictions on local network and k8s access by:
//  1. Performing string-based pattern matching (shExpMatch/isPlainHostName) first before DNS
//     resolution, preventing iOS sandbox/timeout failures on unresolvable internal domains;
//  2. Safely verifying dnsResolve() output before invoking isInNet();
//  3. Providing multi-fallback proxy return strings ("SOCKS5 HOST:PORT; SOCKS HOST:PORT; DIRECT")
//     to ensure compatibility across iOS, macOS, Windows, Linux, and Android;
//  4. Covering standard Kubernetes cluster suffixes (*.svc, *.svc.cluster.local, *.cluster.local),
//     RFC 1918 private IPv4 networks (10/8, 172.16/12, 192.168/16), loopback (127/8), CGNAT (100.64/10),
//     link-local (169.254/16), and local/internal TLDs (*.local, *.internal, *.lan, *.home, *.corp).
func Generate(host string, port int, domainFilters []string, ipFilters []string) string {
	if port <= 0 {
		port = 10080
	}
	host = strings.TrimSpace(host)

	var proxyString string
	if host == "" || host == "127.0.0.1" || host == "localhost" {
		proxyString = fmt.Sprintf("SOCKS5 127.0.0.1:%d; SOCKS 127.0.0.1:%d; SOCKS localhost:%d; DIRECT", port, port, port)
	} else {
		proxyString = fmt.Sprintf("SOCKS5 %s:%d; SOCKS %s:%d; DIRECT", host, port, host, port)
	}

	var extraDomains strings.Builder
	for _, d := range domainFilters {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		d = strings.TrimPrefix(d, ".")
		extraDomains.WriteString(fmt.Sprintf(" ||\n        shExpMatch(host, \"*.%s\") ||\n        shExpMatch(host, \"%s\")", d, d))
	}

	var extraIPs strings.Builder
	for _, f := range ipFilters {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		ip, ipNet, err := net.ParseCIDR(f)
		if err != nil {
			continue
		}
		mask := net.IP(ipNet.Mask).String()
		extraIPs.WriteString(fmt.Sprintf(" ||\n            isInNet(resolved_ip, \"%s\", \"%s\")", ip.String(), mask))
	}

	return fmt.Sprintf(`function FindProxyForURL(url, host)
{
    var proxy = "%s";

    if (shExpMatch(host, "*.svc") ||
        shExpMatch(host, "*.svc.cluster.local") ||
        shExpMatch(host, "*.cluster.local") ||
        shExpMatch(host, "*.local") ||
        shExpMatch(host, "*.internal") ||
        shExpMatch(host, "*.corp") ||
        shExpMatch(host, "*.home") ||
        shExpMatch(host, "*.lan") ||
        isPlainHostName(host) ||
        !isResolvable(host)%s) {
        return proxy;
    }

    var resolved_ip = dnsResolve(host);
    if (resolved_ip) {
        if (isInNet(resolved_ip, "10.0.0.0", "255.0.0.0") ||
            isInNet(resolved_ip, "172.16.0.0", "255.240.0.0") ||
            isInNet(resolved_ip, "192.168.0.0", "255.255.0.0") ||
            isInNet(resolved_ip, "127.0.0.0", "255.0.0.0") ||
            isInNet(resolved_ip, "100.64.0.0", "255.192.0.0") ||
            isInNet(resolved_ip, "169.254.0.0", "255.255.0.0")%s) {
            return proxy;
        }
    }

    return "DIRECT";
}
`, proxyString, extraDomains.String(), extraIPs.String())
}

// Path returns the canonical URL path for a PAC endpoint given a target name.
// When targetName is empty, it returns "/proxy.pac".
// Otherwise, it returns "/proxy-<targetName>.pac".
func Path(targetName string) string {
	return PathForPlatform(targetName, false)
}

// PathForPlatform returns the canonical URL path for a PAC endpoint given a target name
// and whether the target is an iOS / mobile client.
func PathForPlatform(targetName string, isIOS bool) string {
	targetName = strings.TrimSpace(targetName)
	if isIOS {
		if targetName == "" {
			return "/proxy-ios.pac"
		}
		return fmt.Sprintf("/proxy-ios-%s.pac", targetName)
	}
	if targetName == "" {
		return "/proxy.pac"
	}
	return fmt.Sprintf("/proxy-%s.pac", targetName)
}

// URL combines a base server URL with the PAC path for the given target name.
func URL(baseURL, targetName string) string {
	return URLForPlatform(baseURL, targetName, false)
}

// URLForPlatform combines a base server URL with the platform-specific PAC path.
func URLForPlatform(baseURL, targetName string, isIOS bool) string {
	baseURL = strings.TrimRight(baseURL, "/")
	p := PathForPlatform(targetName, isIOS)
	if baseURL == "" {
		return p
	}
	return baseURL + p
}
