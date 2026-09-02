package portal

import (
	"net/http"
	"strings"
)

// NormalizeOS maps Go and browser platform names to the stable Portal API.
func NormalizeOS(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ios", "iphone":
		return "ios"
	case "ipados", "ipad":
		return "ipados"
	case "darwin", "macos", "mac os", "mac os x":
		return "macos"
	case "windows", "win32", "win64":
		return "windows"
	case "linux":
		return "linux"
	case "android":
		return "android"
	default:
		return "unknown"
	}
}

func normalizeBrowser(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "safari", "chrome", "edge", "firefox":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "unknown"
	}
}

// DetectBrowserContext derives only presentation information from headers.
// It deliberately has no role in peer identity or authorization.
func DetectBrowserContext(h http.Header) ClientContext {
	ua := strings.ToLower(h.Get("User-Agent"))
	platform := strings.ToLower(h.Get("Sec-CH-UA-Platform"))
	os := NormalizeOS(strings.Trim(platform, `"`))
	if os == "unknown" {
		switch {
		case strings.Contains(ua, "android"):
			os = "android"
		case strings.Contains(ua, "iphone"):
			os = "ios"
		case strings.Contains(ua, "ipad"):
			os = "ipados"
		case strings.Contains(ua, "macintosh") && strings.Contains(ua, "mobile"):
			os = "ipados" // iPad desktop UA
		case strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh"):
			os = "macos"
		case strings.Contains(ua, "windows"):
			os = "windows"
		case strings.Contains(ua, "linux"):
			os = "linux"
		}
	}
	browser := "unknown"
	switch {
	case strings.Contains(ua, "edg/") || strings.Contains(ua, "edga/"):
		browser = "edge"
	case strings.Contains(ua, "firefox/") || strings.Contains(ua, "fxios/"):
		browser = "firefox"
	case strings.Contains(ua, "chrome/") || strings.Contains(ua, "crios/"):
		browser = "chrome"
	case strings.Contains(ua, "safari/") && !strings.Contains(ua, "chrome/") && !strings.Contains(ua, "crios/"):
		browser = "safari"
	}
	return ClientContext{OS: os, DetectedOS: os, ViewOS: os, Browser: browser, Mobile: os == "ios" || os == "ipados" || os == "android"}
}

// WithViewOS applies a documentation-only web Portal override.
func (c ClientContext) WithViewOS(raw string) ClientContext {
	if strings.EqualFold(strings.TrimSpace(raw), "wireguard") {
		c.ViewType, c.Override = "wireguard", true
		return c
	}
	v := NormalizeOS(raw)
	if v != "unknown" {
		c.ViewOS, c.Override = v, v != c.DetectedOS
	}
	return c
}

// NormalizeClient makes absent and malformed presentation metadata safe.
func NormalizeClient(c ClientContext, mode string) ClientContext {
	c.OS = NormalizeOS(c.OS)
	if c.DetectedOS == "" {
		c.DetectedOS = c.OS
	} else {
		c.DetectedOS = NormalizeOS(c.DetectedOS)
	}
	if c.ViewOS == "" {
		c.ViewOS = c.OS
	} else {
		c.ViewOS = NormalizeOS(c.ViewOS)
	}
	if c.ViewType == "" {
		c.ViewType = c.Type
	}
	c.Browser = normalizeBrowser(c.Browser)
	c.Type = strings.ToLower(strings.TrimSpace(c.Type))
	if c.Type != "ntwire" && c.Type != "wireguard" && c.Type != "browser" {
		c.Type = "unknown"
	}
	if c.Version == "" {
		c.Version = c.ClientVersion
	}
	c.ClientVersion = c.Version
	c.Arch = strings.ToLower(strings.TrimSpace(c.Arch))
	if c.Type == "ntwire" {
		c.Capabilities.PortalNative = true
		c.Capabilities.LocalPorts = true
		c.Capabilities.Socks = true
		c.Capabilities.OpenURL = true
	}
	if c.Type == "wireguard" {
		c.Capabilities.NativeWireGuard = true
	}
	if mode == "wireguard" {
		c.Capabilities.PortalWeb = true
	}
	return c
}
