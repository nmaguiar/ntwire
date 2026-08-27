package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/clientopts"
	"github.com/nmaguiar/ntwire/pkg/completion"
	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/pac"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/ui"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
	"golang.org/x/term"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	noColor := noColorFrom(os.Args[1:])
	u := ui.New(os.Stdout, os.Stderr, noColor)
	if len(os.Args) < 2 {
		usage(u)
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(buildinfo.String())
	case "keygen":
		keygen(os.Args[2:], u)
	case "list":
		list(os.Args[2:], u)
	case "connect":
		connect(os.Args[2:], u)
	case "status":
		status(os.Args[2:], u)
	case "disconnect":
		disconnect(os.Args[2:], u)
	case "port":
		port(os.Args[2:], u)
	case "transport":
		transportCmd(os.Args[2:], u)
	case "browser":
		browser(os.Args[2:], u)
	case "logout":
		logout(os.Args[2:], u)
	case "completion":
		completionCmd(os.Args[2:], u)
	case "help":
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "keygen":
				keygen([]string{"-h"}, u)
			case "connect":
				connect([]string{"-h"}, u)
			case "list":
				list([]string{"-h"}, u)
			case "status":
				status([]string{"-h"}, u)
			case "disconnect":
				disconnect([]string{"-h"}, u)
			case "port":
				port([]string{"-h"}, u)
			case "transport":
				transportCmd([]string{"-h"}, u)
			case "browser":
				browser([]string{"-h"}, u)
			case "logout":
				logout([]string{"-h"}, u)
			case "completion":
				completionCmd([]string{"-h"}, u)
			default:
				usage(u)
			}
			return
		}
		usage(u)
	default:
		usage(u)
	}
}

// noColorFrom scans raw args for --no-color/-no-color before any
// subcommand-specific flag.FlagSet has parsed anything, so both "ntwire
// --no-color connect ..." and "ntwire connect --no-color ..." disable
// color for the single UI shared by main() and every subcommand.
func noColorFrom(args []string) bool {
	for _, a := range args {
		if a == "--no-color" || a == "-no-color" {
			return true
		}
	}
	return false
}

func usage(u *ui.UI) {
	ui.Spec{
		Tool:    "ntwire",
		Tagline: "connect to tunnels published by an ntwire-server",
		Commands: []ui.Command{
			{Name: "keygen", Summary: "create an SSH identity"},
			{Name: "connect", Summary: "connect tunnels"},
			{Name: "list", Summary: "show allowed tunnels"},
			{Name: "status", Summary: "show the running connection"},
			{Name: "disconnect", Summary: "stop the running connection"},
			{Name: "port", Summary: "replace a tunnel's local port"},
			{Name: "transport", Summary: "show or switch the active transport mode"},
			{Name: "browser", Summary: "open a browser configured for a SOCKS tunnel"},
			{Name: "logout", Summary: "clear cached SSO tokens"},
			{Name: "completion", Summary: "generate shell completion script"},
			{Name: "version", Summary: "print the build version"},
		},
		Examples: []string{
			"ntwire keygen",
			"ntwire connect server.example",
			"ntwire <command> -h",
		},
	}.Fprint(u.Err, u)
}

// setUsage installs a shared-format -h renderer on fs. It can be called
// any time before fs.Parse, since the renderer visits fs's flags lazily
// when invoked, not when this function runs.
func setUsage(fs *flag.FlagSet, u *ui.UI, tagline string, examples ...string) {
	fs.Usage = func() {
		ui.Spec{
			Tool:     "ntwire " + fs.Name(),
			Tagline:  tagline,
			Flags:    ui.FlagsOf(fs),
			Examples: examples,
		}.Fprint(u.Err, u)
	}
}

// clientLogger builds the diagnostic logger used by connect/list's -v
// flag. NTWIRE_LOG_FORMAT/NTWIRE_LOG_LEVEL are honored (so a containerized
// `ntwire connect` can emit Logstash JSON diagnostics) but there is no
// config-file or per-subcommand flag layer here: this is an interactive,
// human-facing tool most of the time, and cluttering every subcommand's
// -h output with a rarely-used logging flag isn't worth it.
func clientLogger(verbose bool, caps ui.Capabilities) *slog.Logger {
	env := logging.EnvOptions("NTWIRE")
	level := "warn"
	if verbose {
		level = "debug"
	}
	if env.Level != "" {
		level = env.Level
	}
	format := env.Format
	if format == "" {
		format = "text"
	}
	return slog.New(logging.NewHandler(os.Stderr, logging.Options{Format: format, Level: level}, caps))
}

// logout clears cached SSO tokens for a server, so the next authentication
// reopens the browser (or device flow) instead of silently refreshing.
func logout(args []string, u *ui.UI) {
	settings, configPath := settingsFor(args)
	fs := clientopts.NewFlagSet("logout", clientopts.Defaults{Settings: settings, ConfigPath: configPath})
	setUsage(fs.FlagSet, u, "clear cached SSO tokens for a server", "ntwire logout https://server:8443")
	fs.Parse(args)
	cache := fs.Str("token-cache")
	server := settings.Server
	if fs.NArg() == 1 {
		server = fs.Arg(0)
	}
	if server == "" || fs.NArg() > 1 {
		u.Errorf("usage: ntwire logout https://server:8443")
		os.Exit(2)
	}
	if err := client.Logout(cache, server); err != nil {
		u.Errorf("%v", err)
		os.Exit(1)
	}
	u.Success("logged out of %s", server)
}

// port replaces the local loopback address for a running tunnel. The
// connect process owns the listener, so this uses its token-protected
// local status UI. The mapping accepts name=local-port (host unchanged) or
// name=host:local-port (IPv6 as name=[::1]:local-port), the same syntax as
// connect's --port.
func port(args []string, u *ui.UI) {
	fs := clientopts.NewFlagSet("port", clientopts.Defaults{})
	setUsage(fs.FlagSet, u, "replace a running tunnel's local address", "ntwire port reports=8080", "ntwire port reports=127.70.0.1:8080")
	fs.Parse(args)
	path := fs.Str("status-file")
	if fs.NArg() != 1 {
		u.Errorf("usage: ntwire port [--status-file path] name=local-port")
		os.Exit(2)
	}
	parts := strings.SplitN(fs.Arg(0), "=", 2)
	if len(parts) != 2 || parts[0] == "" {
		u.Errorf("invalid port mapping; use name=local-port or name=host:local-port")
		os.Exit(2)
	}
	var localHost string
	localPort, err := strconv.Atoi(parts[1])
	if err != nil {
		var portStr string
		localHost, portStr, err = net.SplitHostPort(parts[1])
		if err == nil && localHost == "" {
			err = fmt.Errorf("missing host before ':'")
		}
		if err == nil {
			localPort, err = strconv.Atoi(portStr)
		}
	}
	if err != nil || localPort < 1 || localPort > 65535 {
		u.Errorf("invalid local port; use name=local-port or name=host:local-port")
		os.Exit(2)
	}
	s, err := client.ReadStatus(path)
	if err != nil {
		u.Errorf("not connected: %v", err)
		os.Exit(1)
	}
	uu, err := url.Parse(s.UIURL)
	if err != nil || uu.Scheme != "http" || uu.Host == "" {
		u.Errorf("running client does not expose a local status UI")
		os.Exit(1)
	}
	uu.Path = "/tunnels/" + url.PathEscape(parts[0])
	body, err := json.Marshal(struct {
		LocalPort int    `json:"local_port"`
		LocalHost string `json:"local_host,omitempty"`
	}{LocalPort: localPort, LocalHost: localHost})
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(1)
	}
	req, err := http.NewRequest(http.MethodPut, uu.String(), bytes.NewReader(body))
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		u.Errorf("replace local port: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		u.Errorf("replace local port: %s", resp.Status)
		os.Exit(1)
	}
	var out struct {
		LocalAddress string `json:"local_address"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		u.Errorf("replace local port: %v", err)
		os.Exit(1)
	}
	fmt.Fprintf(u.Out, "%s  %s\n", u.OutPal.Highlight.Sprint(parts[0]), out.LocalAddress)
}

// transportCmd displays or overrides the live transport for a running connection.
func transportCmd(args []string, u *ui.UI) {
	fs := clientopts.NewFlagSet("transport", clientopts.Defaults{})
	setUsage(fs.FlagSet, u, "show or switch the active transport mode", "ntwire transport", "ntwire transport direct-udp", "ntwire transport auto")
	fs.Parse(args)
	path := fs.Str("status-file")
	s, err := client.ReadStatus(path)
	if err != nil {
		u.Errorf("not connected: %v", err)
		os.Exit(1)
	}
	uu, err := url.Parse(s.UIURL)
	if err != nil || uu.Scheme != "http" || uu.Host == "" {
		u.Errorf("running client does not expose a local status UI")
		os.Exit(1)
	}
	uu.Path = "/transport"

	if fs.NArg() == 0 {
		req, err := http.NewRequest(http.MethodGet, uu.String(), nil)
		if err != nil {
			u.Errorf("%v", err)
			os.Exit(1)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			u.Errorf("failed to query running connection: %v", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			u.Errorf("failed to get transport info: %s", strings.TrimSpace(string(b)))
			os.Exit(1)
		}
		var info client.TransportInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			u.Errorf("failed to parse response: %v", err)
			os.Exit(1)
		}
		u.Info("Active transport: %s", info.Active)
		if info.Forced != "" {
			if info.ForcedEffective {
				u.Info("Transport override: %s (effective)", info.Forced)
			} else {
				u.Warn("Transport override: %s (fallback active, using %s)", info.Forced, info.Active)
			}
		} else {
			u.Info("Transport mode: automatic")
		}
		if len(info.Paths) > 0 {
			fmt.Fprintln(u.Out)
			t := ui.Table{
				Columns: []ui.Column{
					{Header: "PATH", Width: 12, Align: "left"},
					{Header: "KIND", Width: 10, Align: "left"},
					{Header: "STATUS", Width: 30, Align: "left"},
					{Header: "RTT", Width: 8, Align: "right"},
					{Header: "LOSS", Width: 7, Align: "right"},
					{Header: "DELIVERY", Sep: "  "},
				},
			}
			for _, p := range info.Paths {
				t.Rows = append(t.Rows, pathStatusRow(p))
			}
			fmt.Fprint(u.Out, t.Render(u))
		}
		return
	}

	target := fs.Arg(0)
	body, err := json.Marshal(struct {
		Transport string `json:"transport"`
	}{Transport: target})
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(1)
	}
	req, err := http.NewRequest(http.MethodPut, uu.String(), bytes.NewReader(body))
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		u.Errorf("failed to update transport: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		u.Errorf("failed to set transport: %s", strings.TrimSpace(string(b)))
		os.Exit(1)
	}
	var info client.TransportInfo
	_ = json.NewDecoder(resp.Body).Decode(&info)
	if info.Forced == "" {
		u.Success("Transport set to automatic mode (active: %s)", info.Active)
	} else if info.ForcedEffective {
		u.Success("Transport forced to %s (active: %s)", info.Forced, info.Active)
	} else {
		u.Warn("Transport forced to %s (unavailable or unhealthy; fallback active: %s)", info.Forced, info.Active)
	}
}

// browser opens a Chrome/Chromium instance configured (via --proxy-server)
// to route through a running SOCKS egress tunnel's local port, using a
// persistent, isolated profile directory per tunnel name so logins/cookies
// survive between launches. --clean removes that profile directory instead
// of opening it.
func browser(args []string, u *ui.UI) {
	fs := clientopts.NewFlagSet("browser", clientopts.Defaults{})
	setUsage(fs.FlagSet, u, "open a browser configured for a SOCKS tunnel",
		"ntwire browser", "ntwire browser reports", "ntwire browser --clean reports",
		"ntwire browser --list", "ntwire browser --clean-all")
	fs.Parse(args)
	path := fs.Str("status-file")
	clean := fs.BoolVal("clean")
	list := fs.BoolVal("list")
	cleanAll := fs.BoolVal("clean-all")

	if list {
		profiles, err := browseropen.ListProfiles()
		if err != nil {
			u.Errorf("list browser profiles: %v", err)
			os.Exit(1)
		}
		for _, p := range profiles {
			status := "unused"
			if p.InUse {
				status = "in use"
			}
			if !p.ModTime.IsZero() {
				u.Info("%s [%s] (modified %s)", p.Key, status, p.ModTime.Format("2006-01-02 15:04:05"))
			} else {
				u.Info("%s [%s]", p.Key, status)
			}
		}
		return
	}

	if cleanAll {
		profiles, err := browseropen.ListProfiles()
		if err != nil {
			u.Errorf("list browser profiles: %v", err)
			os.Exit(1)
		}
		for _, p := range profiles {
			if p.InUse {
				continue
			}
			if err := browseropen.CleanProfile(p.Key); err != nil {
				u.Errorf("failed to remove %s: %v", p.Key, err)
			} else {
				u.Info("removed browser profile %s", p.Key)
			}
		}
		return
	}

	if fs.NArg() > 1 {
		u.Errorf("usage: ntwire browser [--clean] [name]")
		os.Exit(2)
	}
	name := fs.Arg(0)

	s, err := client.ReadStatus(path)
	if err != nil {
		u.Errorf("not connected: %v", err)
		os.Exit(1)
	}
	ws, err := client.FetchWebStatus(s.UIURL)
	if err != nil {
		u.Errorf("fetch status: %v", err)
		os.Exit(1)
	}
	var socksTunnels []client.WebTunnel
	for _, t := range ws.Tunnels {
		if t.TargetHint == "socks" {
			socksTunnels = append(socksTunnels, t)
		}
	}
	if len(socksTunnels) == 0 {
		u.Errorf("no SOCKS tunnels on this connection")
		os.Exit(1)
	}

	var tunnel client.WebTunnel
	switch {
	case name != "":
		found := false
		for _, t := range socksTunnels {
			if t.Name == name {
				tunnel, found = t, true
				break
			}
		}
		if !found {
			u.Errorf("no SOCKS tunnel named %q", name)
			os.Exit(1)
		}
	case len(socksTunnels) == 1:
		tunnel = socksTunnels[0]
	default:
		names := make([]string, len(socksTunnels))
		for i, t := range socksTunnels {
			names[i] = t.Name
		}
		u.Errorf("multiple SOCKS tunnels; specify one: %s", strings.Join(names, ", "))
		os.Exit(2)
	}

	if clean {
		if err := browseropen.CleanProfile("cli-" + tunnel.Name); err != nil {
			u.Errorf("%v", err)
			os.Exit(1)
		}
		u.Info("removed browser profile for %s", tunnel.Name)
		return
	}
	if err := browseropen.OpenSocks("cli-"+tunnel.Name, tunnel.LocalAddress); err != nil {
		u.Errorf("open browser: %v", err)
		os.Exit(1)
	}
	u.Info("opening browser for %s via socks5://%s", tunnel.Name, tunnel.LocalAddress)
}

// formatBytes renders a byte count the same way the local status UI's
// dashboard does (pkg/client/webui/static/index.html's bytes()): B/KiB/
// MiB/GiB/TiB, one decimal place once it's past whole bytes.
func formatBytes(n uint64) string {
	units := [...]string{"B", "KiB", "MiB", "GiB", "TiB"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", f, units[i])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// connsSummary and trafficSummary render a tunnel's live counters as two
// bounded fields (rather than one combined field, which can run long
// enough to break column alignment) reused by both `list`'s CONNS/TRAFFIC
// columns and `status`'s per-tunnel breakdown.
func connsSummary(s client.TunnelStats) string {
	return fmt.Sprintf("%d/%d", s.Active, s.Connections)
}

func trafficSummary(s client.TunnelStats) string {
	return fmt.Sprintf("%s in / %s out", formatBytes(s.BytesFromTunnel), formatBytes(s.BytesToTunnel))
}

// tunnelStatusRow builds one row of a NAME | LOCAL ADDRESS | STATUS |
// CONNS | TRAFFIC table for a live tunnel, where STATUS reflects whether
// it currently has any active connections (distinct from list's STATUS
// column, which reflects whether the tunnel is connected at all).
func tunnelStatusRow(t client.WebTunnel) []string {
	status := "idle"
	if t.Stats.Active > 0 {
		status = "active"
	}
	return []string{t.Name, t.LocalAddress, status, connsSummary(t.Stats), trafficSummary(t.Stats)}
}

// pathStatusRow builds one row of a NAME | KIND | STATUS | RTT | LOSS |
// DELIVERY table for a multipath candidate. DELIVERY renders "-" rather than
// a percentage when DeliveryRatio is negative -- the scheduler's sentinel
// for "no comparable mirrored-traffic sample yet", not "confirmed zero".
func pathStatusRow(p wstransport.PathStatus) []string {
	status := "unhealthy"
	if p.Healthy {
		status = "healthy"
	}
	if p.Primary {
		if p.Forced {
			status += " (primary, forced)"
		} else {
			status += " (primary)"
		}
	} else if p.Forced {
		status += " (forced, fallback active)"
	}
	delivery := "-"
	if p.DeliveryRatio >= 0 {
		delivery = fmt.Sprintf("%.0f%%", p.DeliveryRatio*100)
	}
	return []string{p.Name, string(p.Kind), status, fmt.Sprintf("%dms", p.RTT.Milliseconds()), fmt.Sprintf("%.1f%%", p.Loss*100), delivery}
}

// listColumns is factored out of list() so a test can render the exact
// column widths list() uses and catch overflow that would break the
// DESCRIPTION column's alignment (see TestListColumnsFitLiveStats).
func listColumns() []ui.Column {
	return []ui.Column{
		{Header: "NAME", Width: 20, Align: "left"},
		{Header: "PORT", Width: 5, Align: "right"},
		{Header: "LOCAL", Width: 6, Align: "right"},
		{Header: "STATUS", Width: 10, Align: "left"},
		{Header: "CONNS", Width: 11, Align: "right"},
		{Header: "TRAFFIC", Width: 30, Align: "left"},
		{Header: "DESCRIPTION", Sep: "  "},
	}
}

// listEntry is the --json shape for one row of `list`'s table: the
// tunnel's server-side definition plus, when a matching `ntwire connect`
// process is running, its live stats.
type listEntry struct {
	Name        string              `json:"name"`
	VirtualPort int                 `json:"virtual_port"`
	LocalPort   int                 `json:"local_port,omitempty"`
	Connected   bool                `json:"connected"`
	Stats       *client.TunnelStats `json:"stats,omitempty"`
	Description string              `json:"description,omitempty"`
	PACURL      string              `json:"pac_url,omitempty"`
	PACURLiOS   string              `json:"pac_url_ios,omitempty"`
}

func pacURLFor(server, targetName string, isIOS bool) string {
	normalized, err := client.NormalizeServerURL(server)
	if err != nil {
		normalized = server
	}
	return pac.URLForPlatform(normalized, targetName, isIOS)
}

// liveTunnelStatus best-effort looks up a currently-running `ntwire
// connect` process's live per-tunnel status, but only when that process is
// connected to the same server being queried -- a status file pointing at
// a different server is not relevant here. Any failure (nothing running,
// wrong server, unreachable status UI) yields a nil map, which callers
// treat the same as "nothing live to show."
func liveTunnelStatus(server, statusFile string) map[string]client.WebTunnel {
	target, err := client.NormalizeServerURL(server)
	if err != nil {
		return nil
	}
	s, err := client.ReadStatus(statusFile)
	if err != nil {
		return nil
	}
	running, err := client.NormalizeServerURL(s.Server)
	if err != nil || running != target {
		return nil
	}
	ws, err := client.FetchWebStatus(s.UIURL)
	if err != nil {
		return nil
	}
	byName := make(map[string]client.WebTunnel, len(ws.Tunnels))
	for _, t := range ws.Tunnels {
		byName[t.Name] = t
	}
	return byName
}

// statusJSON is the --json shape for `status`: the local status-file
// record plus, when the running connect process's local status UI answers,
// its live WebStatus. WebStatus is a pointer so a failed fetch (nothing
// running, or unreachable) omits those fields entirely rather than
// reporting zero values as if they were real.
type statusJSON struct {
	client.Status
	*client.WebStatus
}

func status(args []string, u *ui.UI) {
	fs := clientopts.NewFlagSet("status", clientopts.Defaults{})
	setUsage(fs.FlagSet, u, "show the running connection", "ntwire status")
	fs.Parse(args)
	path := fs.Str("status-file")
	jsonOut := fs.BoolVal("json")
	s, err := client.ReadStatus(path)
	if err != nil {
		u.Errorf("not connected: %v", err)
		os.Exit(1)
	}
	ws, wsErr := client.FetchWebStatus(s.UIURL)
	if jsonOut {
		out := statusJSON{Status: s}
		if wsErr == nil {
			out.WebStatus = &ws
		}
		enc := json.NewEncoder(u.Out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	var kv ui.KV
	kv.Add("pid", fmt.Sprintf("%d", s.PID))
	kv.Add("server", s.Server)
	if s.Name != "" {
		kv.Add("name", s.Name)
	}
	kv.Add("status", s.UIURL)
	for _, address := range s.LocalAddresses {
		kv.Add("local", address)
	}
	if wsErr == nil {
		kv.Add("connected", fmt.Sprintf("%t", ws.Connected))
		connType := ws.ConnectionType
		if ws.Forced != "" {
			if ws.ForcedEffective {
				connType += fmt.Sprintf(" [forced: %s]", ws.Forced)
			} else {
				connType += fmt.Sprintf(" [forced: %s, fallback active]", ws.Forced)
			}
		}
		kv.Add("connection", connType)
		kv.Add("ttl", fmt.Sprintf("%ds", ws.TTLSeconds))
		kv.Add("latency", fmt.Sprintf("%dms", ws.LatencyMillis))
		kv.Add("reconnections", fmt.Sprintf("%d", ws.Reconnections))
	}
	fmt.Fprint(u.Out, kv.Render(u))
	if wsErr == nil && len(ws.Tunnels) > 0 {
		fmt.Fprintln(u.Out)
		t := ui.Table{
			Columns: []ui.Column{
				{Header: "NAME", Width: 20, Align: "left"},
				{Header: "LOCAL ADDRESS", Width: 22, Align: "left"},
				{Header: "STATUS", Width: 8, Align: "left"},
				{Header: "CONNS", Width: 11, Align: "right"},
				{Header: "TRAFFIC", Sep: "  "},
			},
		}
		for _, tn := range ws.Tunnels {
			t.Rows = append(t.Rows, tunnelStatusRow(tn))
		}
		fmt.Fprint(u.Out, t.Render(u))
	}
	if wsErr == nil && len(ws.Paths) > 0 {
		fmt.Fprintln(u.Out)
		t := ui.Table{
			Columns: []ui.Column{
				{Header: "PATH", Width: 12, Align: "left"},
				{Header: "KIND", Width: 10, Align: "left"},
				{Header: "STATUS", Width: 30, Align: "left"},
				{Header: "RTT", Width: 8, Align: "right"},
				{Header: "LOSS", Width: 7, Align: "right"},
				{Header: "DELIVERY", Sep: "  "},
			},
		}
		for _, p := range ws.Paths {
			t.Rows = append(t.Rows, pathStatusRow(p))
		}
		fmt.Fprint(u.Out, t.Render(u))
	}
}

func disconnect(args []string, u *ui.UI) {
	fs := clientopts.NewFlagSet("disconnect", clientopts.Defaults{})
	setUsage(fs.FlagSet, u, "stop the running connection", "ntwire disconnect")
	fs.Parse(args)
	path := fs.Str("status-file")
	s, err := client.ReadStatus(path)
	if err != nil {
		u.Errorf("not connected: %v", err)
		os.Exit(1)
	}
	p, err := os.FindProcess(s.PID)
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(1)
	}
	if err = p.Signal(os.Interrupt); err != nil {
		u.Errorf("disconnect: %v", err)
		os.Exit(1)
	}
}
func connect(args []string, u *ui.UI) {
	settings, configPath := settingsFor(args)
	fs := clientopts.NewFlagSet("connect", clientopts.Defaults{Settings: settings, ConfigPath: configPath})
	setUsage(fs.FlagSet, u, "connect tunnels", "ntwire connect server.example", "ntwire connect --sso server.example")
	fs.Parse(args)
	verbose := fs.BoolVal("v")
	key := fs.Str("i")
	ca := fs.Str("ca")
	insecure := fs.BoolVal("insecure")
	httpsProxy := fs.Str("https-proxy")
	noSystemProxy := fs.BoolVal("no-system-proxy")
	known := fs.Str("known-servers")
	noBrowser := fs.BoolVal("no-browser")
	sso := fs.BoolVal("sso")
	sso = resolveSSO(sso, fs.WasSet("sso"), fs.WasSet("i"))
	provider := fs.Str("provider")
	tokenCache := fs.Str("token-cache")
	websocket := fs.BoolVal("websocket")
	collect := fs.Str("collect-exec")
	bind := fs.Str("bind")
	ipVersion := fs.Str("ip-version")
	transport := fs.Str("transport")
	mappings := fs.KeyValues("port")
	server := settings.Server
	if fs.NArg() == 1 {
		server = fs.Arg(0)
	}
	key = resolveIdentityKey(key, sso, client.DefaultIdentityFile)
	if server == "" || fs.NArg() > 1 {
		u.Errorf("No server is configured.\n1. Run: ntwire keygen\n2. Send ~/.ntwire/id_ed25519.pub to your administrator\n3. Run: ntwire connect <server>")
		os.Exit(2)
	}
	ports, hosts, perr := mergePorts(settings.Ports, settings.Hosts, mappings)
	if perr != nil {
		u.Errorf("%v", perr)
		os.Exit(2)
	}
	info, e := collectedInfo(collect)
	if e != nil {
		u.Errorf("%v", e)
		os.Exit(2)
	}
	passphrase, e := resolveKeyPassphrase(key, u)
	if e != nil {
		u.Errorf("%v", e)
		os.Exit(1)
	}
	settingsURL, closeSettingsUI, sErr := startSettingsUI(configPath)
	if sErr != nil {
		u.Warn("could not start local settings UI: %v", sErr)
	} else {
		defer closeSettingsUI()
	}
	o := client.Options{
		Ports: ports, Hosts: hosts, CAFile: ca, Insecure: insecure, HTTPSProxy: httpsProxy, NoSystemProxy: noSystemProxy, KnownServersFile: known, NoWebUI: noBrowser, UseWebSocket: websocket,
		SSO: sso, Provider: provider, NoBrowser: noBrowser, TokenCacheFile: tokenCache, KeyPassphrase: passphrase,
		BindAddress: bind, IPVersion: ipVersion, Transport: transport, SettingsURL: settingsURL,
	}
	o.Logger = clientLogger(verbose, u.ErrCaps)
	c, e := client.ConnectWithOptions(server, key, info, o)
	var unknown *client.UnknownCertificateError
	if errors.As(e, &unknown) {
		if !trustPrompt(unknown, known) {
			u.Errorf("server certificate was not trusted")
			os.Exit(1)
		}
		c, e = client.ConnectWithOptions(server, key, info, o)
	}
	if e != nil {
		u.Errorf("%v", e)
		os.Exit(1)
	}
	if !insecure {
		if changed, err := client.UpdateSettings(configPath, client.Settings{Server: server, IdentityFile: key, SSO: c.AuthMethod() == "oidc", Provider: provider}); err != nil {
			u.Warn("could not save connection settings: %v", err)
		} else if changed {
			u.Info("saved connection settings to %s (next time just run: ntwire connect)", configPath)
		}
	}
	if len(c.Response.Tunnels) == 0 {
		u.WarnOut("authenticated as %s but no tunnels are allowed for this identity; ask the admin to add it to a tunnel's allow list.", c.Response.Identity)
	}
	defer c.Close()
	for i, t := range c.Response.Tunnels {
		fmt.Fprintf(u.Out, "%s  %s\n", u.OutPal.Highlight.Sprint(t.Name), c.LocalAddresses[i])
	}
	u.Success("connected to %s; press Ctrl-C to disconnect", c.DisplayName())
	if reason := c.TransportReason(); reason != "" {
		u.Info("using %s: %s (will keep trying for a direct UDP path; run: ntwire status to see the current transport)", c.ConnectionType(), reason)
	}
	if c.UIURL != "" {
		fmt.Fprintf(u.Out, "%s %s\n", u.OutPal.Muted.Sprint("status:"), c.UIURL)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func list(args []string, u *ui.UI) {
	settings, configPath := settingsFor(args)
	fs := clientopts.NewFlagSet("list", clientopts.Defaults{Settings: settings, ConfigPath: configPath})
	setUsage(fs.FlagSet, u, "show allowed tunnels", "ntwire list server.example")
	fs.Parse(args)
	verbose := fs.BoolVal("v")
	key := fs.Str("i")
	ca := fs.Str("ca")
	insecure := fs.BoolVal("insecure")
	httpsProxy := fs.Str("https-proxy")
	noSystemProxy := fs.BoolVal("no-system-proxy")
	known := fs.Str("known-servers")
	noBrowser := fs.BoolVal("no-browser")
	sso := fs.BoolVal("sso")
	sso = resolveSSO(sso, fs.WasSet("sso"), fs.WasSet("i"))
	provider := fs.Str("provider")
	tokenCache := fs.Str("token-cache")
	collect := fs.Str("collect-exec")
	ipVersion := fs.Str("ip-version")
	statusFile := fs.Str("status-file")
	jsonOut := fs.BoolVal("json")
	server := settings.Server
	if fs.NArg() == 1 {
		server = fs.Arg(0)
	}
	key = resolveIdentityKey(key, sso, client.DefaultIdentityFile)
	if server == "" || fs.NArg() > 1 {
		u.Errorf("usage: ntwire list [-i key | --sso] https://server:8443")
		os.Exit(2)
	}
	info, err := collectedInfo(collect)
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(2)
	}
	passphrase, err := resolveKeyPassphrase(key, u)
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(1)
	}
	o := client.Options{
		CAFile: ca, Insecure: insecure, HTTPSProxy: httpsProxy, NoSystemProxy: noSystemProxy, KnownServersFile: known,
		SSO: sso, Provider: provider, NoBrowser: noBrowser, TokenCacheFile: tokenCache,
		QueryOnly: true, KeyPassphrase: passphrase, IPVersion: ipVersion,
	}
	o.Logger = clientLogger(verbose, u.ErrCaps)
	r, err := client.AuthenticateWithOptions(server, key, info, o)
	var unknown *client.UnknownCertificateError
	if errors.As(err, &unknown) {
		if !trustPrompt(unknown, known) {
			u.Errorf("server certificate was not trusted")
			os.Exit(1)
		}
		r, err = client.AuthenticateWithOptions(server, key, info, o)
	}
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(1)
	}
	if len(r.Tunnels) == 0 {
		if jsonOut {
			fmt.Fprintln(u.Out, "[]")
			u.Warn("authenticated as %s but no tunnels are allowed for this identity; ask the admin to add it to a tunnel's allow list.", r.Identity)
			return
		}
		u.WarnOut("authenticated as %s but no tunnels are allowed for this identity; ask the admin to add it to a tunnel's allow list.", r.Identity)
		return
	}
	live := liveTunnelStatus(server, statusFile)
	var socksTunnels []protocol.Tunnel
	for _, tunnel := range r.Tunnels {
		if tunnel.TargetHint == "socks" {
			socksTunnels = append(socksTunnels, tunnel)
		}
	}

	if jsonOut {
		entries := make([]listEntry, 0, len(r.Tunnels))
		for _, tunnel := range r.Tunnels {
			e := listEntry{Name: tunnel.Name, VirtualPort: tunnel.VirtualPort, LocalPort: tunnel.LocalPort, Description: tunnel.Description}
			if tunnel.TargetHint == "socks" {
				e.PACURL = pacURLFor(server, tunnel.Name, false)
				e.PACURLiOS = pacURLFor(server, tunnel.Name, true)
			}
			if wt, ok := live[tunnel.Name]; ok {
				e.Connected = true
				stats := wt.Stats
				e.Stats = &stats
			}
			entries = append(entries, e)
		}
		enc := json.NewEncoder(u.Out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(entries)
		return
	}
	t := ui.Table{Columns: listColumns()}
	for _, tunnel := range r.Tunnels {
		localPort, status, conns, traffic := "-", "-", "-", "-"
		if tunnel.LocalPort != 0 {
			localPort = fmt.Sprintf("%d", tunnel.LocalPort)
		}
		if wt, ok := live[tunnel.Name]; ok {
			status = "connected"
			conns = connsSummary(wt.Stats)
			traffic = trafficSummary(wt.Stats)
		}
		t.Rows = append(t.Rows, []string{tunnel.Name, fmt.Sprintf("%d", tunnel.VirtualPort), localPort, status, conns, traffic, tunnel.Description})
	}
	fmt.Fprint(u.Out, t.Render(u))

	if len(socksTunnels) > 0 {
		fmt.Fprintln(u.Out)
		if len(socksTunnels) == 1 {
			u.Info("Proxy PAC (Desktop): %s (or %s)", pacURLFor(server, "", false), pacURLFor(server, socksTunnels[0].Name, false))
			u.Info("Proxy PAC (iOS):     %s (or %s)", pacURLFor(server, "", true), pacURLFor(server, socksTunnels[0].Name, true))
		} else {
			u.Info("Proxy PAC URLs (Desktop):")
			u.Info("  default: %s", pacURLFor(server, "", false))
			for _, st := range socksTunnels {
				u.Info("  %s: %s", st.Name, pacURLFor(server, st.Name, false))
			}
			u.Info("Proxy PAC URLs (iOS):")
			u.Info("  default: %s", pacURLFor(server, "", true))
			for _, st := range socksTunnels {
				u.Info("  %s: %s", st.Name, pacURLFor(server, st.Name, true))
			}
		}
	}
}

func settingsFor(args []string) (client.Settings, string) {
	path := client.DefaultConfigFile()
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			path = args[i+1]
		}
		if strings.HasPrefix(arg, "--config=") {
			path = strings.TrimPrefix(arg, "--config=")
		}
	}
	s, err := client.LoadSettings(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "client configuration:", err)
		os.Exit(2)
	}
	return s, path
}

// resolveIdentityKey applies connect/list's "no explicit key and not using
// SSO -> fall back to the default identity file" rule. An --sso caller
// deliberately leaves key empty so client.ConnectWithOptions/
// AuthenticateWithOptions know to authenticate via OIDC instead of a key.
// defaultIdentityFile is injected so tests don't depend on the real home
// directory.
func resolveIdentityKey(key string, sso bool, defaultIdentityFile func() string) string {
	if key == "" && !sso {
		return defaultIdentityFile()
	}
	return key
}

// resolveSSO makes an explicit identity file select SSH even when an older
// persisted config defaults to SSO. An explicit --sso remains authoritative,
// including when it is supplied alongside -i.
func resolveSSO(sso, ssoExplicit, identityExplicit bool) bool {
	return sso && (ssoExplicit || !identityExplicit)
}

// mergePorts merges settingsPorts/settingsHosts (the persisted config's
// ports: and hosts: maps) with repeatable --port mappings, which take
// precedence over same-named settings entries. Each mapping is either
// name=local-port or name=host:local-port (IPv6 as name=[::1]:local-port),
// with local-port required to be in [1,65535] either way -- a bare host
// with no port (name=127.70.0.1) is rejected as ambiguous rather than
// guessed at. A mapping that includes a host sets that tunnel's local host
// override; a port-only mapping leaves any existing settings-level host
// override for that tunnel in place.
func mergePorts(settingsPorts map[string]int, settingsHosts map[string]string, mappings []string) (map[string]int, map[string]string, error) {
	ports := map[string]int{}
	for n, p := range settingsPorts {
		ports[n] = p
	}
	hosts := map[string]string{}
	for n, h := range settingsHosts {
		hosts[n] = h
	}
	for _, m := range mappings {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, nil, fmt.Errorf("invalid --port %q: want name=local-port or name=host:local-port", m)
		}
		name, value := parts[0], parts[1]
		if p, e := strconv.Atoi(value); e == nil {
			if p < 1 || p > 65535 {
				return nil, nil, fmt.Errorf("invalid --port %q: local-port must be in 1..65535", m)
			}
			ports[name] = p
			continue
		}
		host, portStr, e := net.SplitHostPort(value)
		if e != nil || host == "" {
			return nil, nil, fmt.Errorf("invalid --port %q: want name=local-port or name=host:local-port", m)
		}
		p, e := strconv.Atoi(portStr)
		if e != nil || p < 1 || p > 65535 {
			return nil, nil, fmt.Errorf("invalid --port %q: local-port must be in 1..65535", m)
		}
		ports[name] = p
		hosts[name] = host
	}
	return ports, hosts, nil
}

func collectedInfo(command string) (protocol.ClientInfo, error) {
	info := client.BuiltinInfo()
	if command == "" {
		return info, nil
	}
	v, err := (client.ExecCollector{Command: command}).Collect()
	if err != nil {
		return info, fmt.Errorf("collect-exec: %w", err)
	}
	for k, x := range v {
		info.Extra[k] = x
	}
	return info, nil
}

func trustPrompt(e *client.UnknownCertificateError, path string) bool {
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintf(os.Stderr, "cannot confirm certificate without a terminal; verify with the admin then pre-seed it in %s\n", path)
		return false
	}
	if e.Previous == "" {
		fmt.Fprintf(os.Stderr, "First connection to %s. Verify this fingerprint with the server startup log; it will be remembered in ~/.ntwire/known_servers.\n%s\nTrust? [y/N] ", e.Host, e.Fingerprint)
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: certificate for %s CHANGED. Old: %s\nNew: %s\nConfirm with the admin; this could be interception. Trust? [y/N] ", e.Host, e.Previous, e.Fingerprint)
	}
	var answer string
	if _, err := fmt.Fscan(os.Stdin, &answer); err != nil || strings.ToLower(answer) != "y" && strings.ToLower(answer) != "yes" {
		return false
	}
	if err := client.TrustServer(path, e.Host, e.Fingerprint); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return false
	}
	return true
}

// resolveKeyPassphrase checks whether keyPath is an encrypted private key
// and, if so, prompts for its passphrase on the controlling terminal
// (retrying on a wrong passphrase, like ssh does). Resolving it here, before
// authentication starts, is what lets the background reconnect loop reuse it
// later without ever needing to prompt itself.
func resolveKeyPassphrase(keyPath string, u *ui.UI) (string, error) {
	if keyPath == "" {
		return "", nil
	}
	needs, err := sshkey.NeedsPassphrase(keyPath)
	if err != nil {
		return "", err
	}
	if !needs {
		return "", nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("private key %s is encrypted and no terminal is available to prompt for its passphrase", keyPath)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Fprintf(os.Stderr, "Passphrase for %s: ", keyPath)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if _, err = sshkey.PublicFromPrivateWithPassphrase(keyPath, b); err == nil {
			return string(b), nil
		}
		if attempt < 3 {
			u.Warn("incorrect passphrase, try again")
		}
	}
	return "", fmt.Errorf("incorrect passphrase for %s", keyPath)
}

func keygen(args []string, u *ui.UI) {
	fs := clientopts.NewFlagSet("keygen", clientopts.Defaults{GeneratedIdentityFile: client.DefaultGeneratedIdentityFile()})
	setUsage(fs.FlagSet, u, "create an SSH identity", "ntwire keygen")
	fs.Parse(args)
	out := fs.Str("o")
	fingerprint, err := client.GenerateIdentity(out)
	if err != nil {
		u.Errorf("keygen: %v", err)
		os.Exit(1)
	}
	pub, _ := os.ReadFile(out + ".pub")
	u.Success("Identity created: %s", out)
	fmt.Fprintf(u.Out, "Fingerprint: %s\nSend this line to your administrator:\n%sNext: ntwire connect <server>\n", fingerprint, pub)
}

func completionCmd(args []string, u *ui.UI) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		ui.Spec{
			Tool:    "ntwire completion",
			Tagline: "generate shell completion script for bash, zsh, fish, or powershell",
			Commands: []ui.Command{
				{Name: "bash", Summary: "generate completion script for bash"},
				{Name: "zsh", Summary: "generate completion script for zsh"},
				{Name: "fish", Summary: "generate completion script for fish"},
				{Name: "powershell", Summary: "generate completion script for powershell"},
			},
			Examples: []string{
				"ntwire completion bash > /etc/bash_completion.d/ntwire",
				"source <(ntwire completion zsh)",
				"ntwire completion fish | source",
				"ntwire completion powershell | Out-String | Invoke-Expression",
			},
		}.Fprint(u.Err, u)
		if len(args) == 0 {
			os.Exit(2)
		}
		return
	}
	sh, err := completion.ParseShell(args[0])
	if err != nil {
		u.Errorf("%v", err)
		os.Exit(2)
	}
	if err := completion.Generate(sh, completion.ClientCommand(), u.Out); err != nil {
		u.Errorf("completion: %v", err)
		os.Exit(1)
	}
}
