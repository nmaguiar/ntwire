package portal

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// TargetInfo is an abstraction of a granted tunnel for building portal context.
type TargetInfo struct {
	Name         string
	Target       string
	Description  string
	VirtualPort  int
	LocalPort    int
	LocalHost    string
	Instructions string
	DocsURL      string
	IsSocks      bool
	BrowserSocks bool
	Portal       *TargetPortalConfig
}

// BuildContext constructs a sanitized PortalContext containing only authorized targets.
func BuildContext(
	portalCfg PortalConfig,
	user PortalUser,
	client PortalClient,
	targets []TargetInfo,
	mode string,
	serverTunnelIP string,
) *PortalContext {
	if portalCfg.Title == "" {
		portalCfg.Title = "ntwire Portal"
	}

	modeLower := strings.ToLower(strings.TrimSpace(mode))
	isNative := modeLower == "native" || modeLower == "client"
	client = NormalizeClient(client, modeLower)

	caps := PortalCapabilities{
		NativeClient:     client.Capabilities.PortalNative,
		WebPortal:        !isNative,
		OpenSocksBrowser: client.Capabilities.LaunchBrowserWithSocks,
		Copy:             true,
		LocalForward:     client.Capabilities.LocalPorts,
		SSHLauncher:      client.Capabilities.LocalPorts,
	}

	// Find any SOCKS proxy tunnel among authorized targets
	var socksHost string
	var socksPort int
	for _, t := range targets {
		if t.IsSocks || t.BrowserSocks {
			if isNative && t.LocalPort > 0 {
				socksHost = "127.0.0.1"
				if t.LocalHost != "" {
					socksHost = t.LocalHost
				}
				socksPort = t.LocalPort
			} else {
				socksHost = serverTunnelIP
				socksPort = t.VirtualPort
			}
			break
		}
	}

	// Build authorized portal targets
	var portalTargets []PortalTarget
	categoryMap := make(map[string][]PortalTarget)

	for _, t := range targets {
		pt := derivePortalTarget(t, client.Capabilities.LocalPorts, serverTunnelIP, socksHost, socksPort)
		portalTargets = append(portalTargets, pt)

		cat := pt.Category
		if cat == "" {
			cat = "General"
		}
		categoryMap[cat] = append(categoryMap[cat], pt)
	}

	// Build categories (sorted, non-empty only)
	var catNames []string
	for cat := range categoryMap {
		catNames = append(catNames, cat)
	}
	sort.Strings(catNames)

	var categories []PortalCategory
	for _, catName := range catNames {
		categories = append(categories, PortalCategory{
			Name:    catName,
			Targets: categoryMap[catName],
		})
	}

	vars := make(map[string]string)
	for k, v := range portalCfg.Variables {
		vars[k] = v
	}

	return &PortalContext{
		Schema: SchemaVersion,
		Portal: PortalInfo{
			Title:       portalCfg.Title,
			Description: "",
			Version:     1,
		},
		User:         user,
		Client:       client,
		Capabilities: caps,
		Targets:      portalTargets,
		Categories:   categories,
		Variables:    vars,
	}
}

func derivePortalTarget(
	t TargetInfo,
	isNative bool,
	serverTunnelIP string,
	defaultSocksHost string,
	defaultSocksPort int,
) PortalTarget {
	name := t.Name
	desc := t.Description
	category := "General"
	icon := "network"
	var urlStr string
	var apps []string
	var socksTunnel string

	if t.Portal != nil {
		if t.Portal.Name != "" {
			name = t.Portal.Name
		}
		if t.Portal.Description != "" {
			desc = t.Portal.Description
		}
		if t.Portal.Category != "" {
			category = t.Portal.Category
		}
		if t.Portal.Icon != "" {
			icon = t.Portal.Icon
		}
		urlStr = t.Portal.URL
		apps = t.Portal.Applications
		socksTunnel = t.Portal.SocksTunnel
	}

	// Host & Port extraction from target
	host := ""
	port := 0
	if !t.IsSocks && t.Target != "" {
		if h, p, err := net.SplitHostPort(t.Target); err == nil {
			host = h
			if pNum, err := strconv.Atoi(p); err == nil {
				port = pNum
			}
		} else {
			host = t.Target
		}
	}

	// If no explicit icon, guess from target / name / port
	if t.Portal == nil || t.Portal.Icon == "" {
		icon = inferIcon(t.Name, host, port, t.IsSocks)
	}

	// Local address calculation
	localAddr := ""
	if t.LocalPort > 0 {
		lh := "127.0.0.1"
		if t.LocalHost != "" {
			lh = t.LocalHost
		}
		localAddr = net.JoinHostPort(lh, strconv.Itoa(t.LocalPort))
	}

	// Build connection semantic helper
	conn := PortalConnectionInfo{}
	if t.IsSocks {
		sHost := "127.0.0.1"
		sPort := t.LocalPort
		if !isNative || sPort <= 0 {
			sHost = serverTunnelIP
			sPort = t.VirtualPort
		}
		conn.Socks = &SocksConnectionInfo{
			Host: sHost,
			Port: sPort,
		}
	} else {
		// SSH target
		if port == 22 || strings.Contains(strings.ToLower(t.Name), "ssh") {
			sshHost := host
			sshPort := port
			if isNative && t.LocalPort > 0 {
				sshHost = "127.0.0.1"
				if t.LocalHost != "" {
					sshHost = t.LocalHost
				}
				sshPort = t.LocalPort
			} else if !isNative {
				sshHost = serverTunnelIP
				sshPort = t.VirtualPort
			}
			cmd := fmt.Sprintf("ssh -p %d %s", sshPort, sshHost)
			if sshPort == 22 {
				cmd = fmt.Sprintf("ssh %s", sshHost)
			}
			conn.SSH = &SSHConnectionInfo{
				Host:    sshHost,
				Port:    sshPort,
				Command: cmd,
			}
		}

		// Database / DBeaver target
		if port == 5432 || port == 3306 || port == 27017 || port == 6379 || strings.Contains(strings.ToLower(t.Name), "db") || strings.Contains(strings.ToLower(t.Name), "postgres") {
			dbHost := host
			dbPort := port
			if isNative && t.LocalPort > 0 {
				dbHost = "127.0.0.1"
				if t.LocalHost != "" {
					dbHost = t.LocalHost
				}
				dbPort = t.LocalPort
			} else if !isNative {
				dbHost = serverTunnelIP
				dbPort = t.VirtualPort
			}
			conn.DBeaver = &DBeaverConnectionInfo{
				Host:      dbHost,
				Port:      dbPort,
				SocksHost: defaultSocksHost,
				SocksPort: defaultSocksPort,
			}
		}

		// Web / HTTP target
		if urlStr != "" {
			conn.HTTP = &HTTPConnectionInfo{
				URL: urlStr,
			}
		}
	}

	return PortalTarget{
		ID:                     t.Name,
		Name:                   name,
		Description:            desc,
		Category:               category,
		Icon:                   icon,
		URL:                    urlStr,
		Target:                 t.Target,
		TargetHint:             t.Target,
		Host:                   host,
		Port:                   port,
		VirtualPort:            t.VirtualPort,
		LocalPort:              t.LocalPort,
		LocalHost:              t.LocalHost,
		LocalAddress:           localAddr,
		DocsURL:                t.DocsURL,
		Instructions:           t.Instructions,
		ConnectionInstructions: t.Instructions,
		IsSocks:                t.IsSocks,
		SocksTunnel:            socksTunnel,
		Applications:           apps,
		Connection:             conn,
	}
}

func inferIcon(name, host string, port int, isSocks bool) string {
	if isSocks {
		return "globe"
	}
	n := strings.ToLower(name)
	h := strings.ToLower(host)
	switch {
	case strings.Contains(n, "grafana") || strings.Contains(n, "kibana") || strings.Contains(n, "chart") || strings.Contains(n, "metric"):
		return "chart"
	case strings.Contains(n, "db") || strings.Contains(n, "postgres") || strings.Contains(n, "mysql") || strings.Contains(n, "mongo") || port == 5432 || port == 3306:
		return "database"
	case strings.Contains(n, "ssh") || strings.Contains(n, "shell") || port == 22:
		return "terminal"
	case strings.Contains(n, "http") || strings.Contains(n, "web") || port == 80 || port == 443 || port == 8080 || port == 8443:
		return "browser"
	case strings.Contains(h, "redis") || port == 6379:
		return "database"
	default:
		return "server"
	}
}
