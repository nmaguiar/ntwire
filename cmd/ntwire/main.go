package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(buildinfo.String())
	case "keygen":
		keygen(os.Args[2:])
	case "list":
		list(os.Args[2:])
	case "connect":
		connect(os.Args[2:])
	case "status":
		status(os.Args[2:])
	case "disconnect":
		disconnect(os.Args[2:])
	case "port":
		port(os.Args[2:])
	case "logout":
		logout(os.Args[2:])
	default:
		usage()
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: ntwire <command>\n\ncommands: keygen  create an SSH identity\n          connect  connect tunnels\n          list     show allowed tunnels\n          status, disconnect, port, logout, version\n\ntypical first run: ntwire keygen; send ~/.ntwire/id_ed25519.pub to your admin; ntwire connect server.example\n\nrun ntwire <command> -h for command help")
}

// logout clears cached SSO tokens for a server, so the next authentication
// reopens the browser (or device flow) instead of silently refreshing.
func logout(args []string) {
	settings, configPath := settingsFor(args)
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	fs.String("config", configPath, "persistent client configuration")
	cache := fs.String("token-cache", "", "token cache file")
	fs.Parse(args)
	server := settings.Server
	if fs.NArg() == 1 {
		server = fs.Arg(0)
	}
	if server == "" || fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: ntwire logout https://server:8443")
		os.Exit(2)
	}
	if err := client.Logout(*cache, server); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("logged out of", server)
}

// port replaces the local loopback port for a running tunnel. The connect
// process owns the listener, so this uses its token-protected local status UI.
func port(args []string) {
	fs := flag.NewFlagSet("port", flag.ExitOnError)
	path := fs.String("status-file", "", "local status file")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: ntwire port [--status-file path] name=local-port")
		os.Exit(2)
	}
	parts := strings.SplitN(fs.Arg(0), "=", 2)
	if len(parts) != 2 || parts[0] == "" {
		fmt.Fprintln(os.Stderr, "invalid port mapping; use name=local-port")
		os.Exit(2)
	}
	var localPort int
	if _, err := fmt.Sscanf(parts[1], "%d", &localPort); err != nil || localPort < 1 || localPort > 65535 {
		fmt.Fprintln(os.Stderr, "invalid local port")
		os.Exit(2)
	}
	s, err := client.ReadStatus(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "not connected:", err)
		os.Exit(1)
	}
	u, err := url.Parse(s.UIURL)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		fmt.Fprintln(os.Stderr, "running client does not expose a local status UI")
		os.Exit(1)
	}
	u.Path = "/tunnels/" + url.PathEscape(parts[0])
	b := strings.NewReader(fmt.Sprintf(`{"local_port":%d}`, localPort))
	req, err := http.NewRequest(http.MethodPut, u.String(), b)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "replace local port:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "replace local port:", resp.Status)
		os.Exit(1)
	}
	var out struct {
		LocalAddress string `json:"local_address"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintln(os.Stderr, "replace local port:", err)
		os.Exit(1)
	}
	fmt.Printf("%s  %s\n", parts[0], out.LocalAddress)
}

func status(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	path := fs.String("status-file", "", "local status file")
	fs.Parse(args)
	s, err := client.ReadStatus(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "not connected:", err)
		os.Exit(1)
	}
	fmt.Println("pid:", s.PID)
	fmt.Println("server:", s.Server)
	if s.UIURL != "" {
		fmt.Println("status:", s.UIURL)
	}
	for _, address := range s.LocalAddresses {
		fmt.Println("local:", address)
	}
}

func disconnect(args []string) {
	fs := flag.NewFlagSet("disconnect", flag.ExitOnError)
	path := fs.String("status-file", "", "local status file")
	fs.Parse(args)
	s, err := client.ReadStatus(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "not connected:", err)
		os.Exit(1)
	}
	p, err := os.FindProcess(s.PID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = p.Signal(os.Interrupt); err != nil {
		fmt.Fprintln(os.Stderr, "disconnect:", err)
		os.Exit(1)
	}
}
func connect(args []string) {
	settings, configPath := settingsFor(args)
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	verbose := fs.Bool("v", false, "show connection diagnostics")
	fs.String("config", configPath, "persistent client configuration")
	key := fs.String("i", settings.IdentityFile, "SSH private key")
	ca := fs.String("ca", settings.CAFile, "PEM CA certificate")
	insecure := fs.Bool("insecure", settings.Insecure, "skip TLS certificate verification")
	known := fs.String("known-servers", "", "known servers file")
	noBrowser := fs.Bool("no-browser", settings.NoBrowser, "do not open a browser (local status UI, and SSO login falls back to the device flow)")
	sso := fs.Bool("sso", settings.SSO, "use SSO (OIDC) authentication instead of an SSH key")
	provider := fs.String("provider", settings.Provider, "oidc issuer name (when the server advertises more than one)")
	tokenCache := fs.String("token-cache", "", "SSO token cache file")
	websocket := fs.Bool("websocket", false, "use the WebSocket WireGuard transport")
	collect := fs.String("collect-exec", settings.CollectExec, "command that emits JSON client-info fields")
	mappings := multiFlag{}
	fs.Var(&mappings, "port", "name=local-port (repeatable)")
	fs.Parse(args)
	server := settings.Server
	if fs.NArg() == 1 {
		server = fs.Arg(0)
	}
	if *key == "" && !*sso {
		*key = client.DefaultIdentityFile()
	}
	if server == "" || fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "No server is configured.\n1. Run: ntwire keygen\n2. Send ~/.ntwire/id_ed25519.pub to your administrator\n3. Run: ntwire connect <server>")
		os.Exit(2)
	}
	ports := map[string]int{}
	for n, p := range settings.Ports {
		ports[n] = p
	}
	for _, m := range mappings {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "invalid --port")
			os.Exit(2)
		}
		var p int
		if _, e := fmt.Sscanf(parts[1], "%d", &p); e != nil || p < 1 || p > 65535 {
			fmt.Fprintln(os.Stderr, "invalid --port")
			os.Exit(2)
		}
		ports[parts[0]] = p
	}
	info, e := collectedInfo(*collect)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	o := client.Options{
		Ports: ports, CAFile: *ca, Insecure: *insecure, KnownServersFile: *known, NoWebUI: *noBrowser, UseWebSocket: *websocket,
		SSO: *sso, Provider: *provider, NoBrowser: *noBrowser, TokenCacheFile: *tokenCache,
	}
	if *verbose {
		o.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		o.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	c, e := client.ConnectWithOptions(server, *key, info, o)
	var unknown *client.UnknownCertificateError
	if errors.As(e, &unknown) {
		if !trustPrompt(unknown, *known) {
			fmt.Fprintln(os.Stderr, "server certificate was not trusted")
			os.Exit(1)
		}
		c, e = client.ConnectWithOptions(server, *key, info, o)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if !*insecure {
		if changed, err := client.UpdateSettings(configPath, client.Settings{Server: server, IdentityFile: *key, SSO: c.AuthMethod() == "oidc", Provider: *provider}); err != nil {
			fmt.Fprintln(os.Stderr, "could not save connection settings:", err)
		} else if changed {
			fmt.Printf("saved connection settings to %s (next time just run: ntwire connect)\n", configPath)
		}
	}
	if len(c.Response.Tunnels) == 0 {
		fmt.Printf("authenticated as %s but no tunnels are allowed for this identity; ask the admin to add it to a tunnel's allow list.\n", c.Response.Identity)
	}
	defer c.Close()
	for i, t := range c.Response.Tunnels {
		fmt.Printf("%s  %s\n", t.Name, c.LocalAddresses[i])
	}
	fmt.Println("connected; press Ctrl-C to disconnect")
	if c.UIURL != "" {
		fmt.Println("status:", c.UIURL)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
func list(args []string) {
	settings, configPath := settingsFor(args)
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	verbose := fs.Bool("v", false, "show connection diagnostics")
	fs.String("config", configPath, "persistent client configuration")
	key := fs.String("i", settings.IdentityFile, "SSH private key")
	ca := fs.String("ca", settings.CAFile, "PEM CA certificate")
	insecure := fs.Bool("insecure", settings.Insecure, "skip TLS certificate verification")
	known := fs.String("known-servers", "", "known servers file")
	noBrowser := fs.Bool("no-browser", settings.NoBrowser, "do not open a browser; SSO login falls back to the device flow")
	sso := fs.Bool("sso", settings.SSO, "use SSO (OIDC) authentication instead of an SSH key")
	provider := fs.String("provider", settings.Provider, "oidc issuer name (when the server advertises more than one)")
	tokenCache := fs.String("token-cache", "", "SSO token cache file")
	collect := fs.String("collect-exec", settings.CollectExec, "command that emits JSON client-info fields")
	fs.Parse(args)
	server := settings.Server
	if fs.NArg() == 1 {
		server = fs.Arg(0)
	}
	if *key == "" && !*sso {
		*key = client.DefaultIdentityFile()
	}
	if server == "" || fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: ntwire list [-i key | --sso] https://server:8443")
		os.Exit(2)
	}
	info, err := collectedInfo(*collect)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	o := client.Options{
		CAFile: *ca, Insecure: *insecure, KnownServersFile: *known,
		SSO: *sso, Provider: *provider, NoBrowser: *noBrowser, TokenCacheFile: *tokenCache,
	}
	if *verbose {
		o.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		o.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	r, err := client.AuthenticateWithOptions(server, *key, info, o)
	var unknown *client.UnknownCertificateError
	if errors.As(err, &unknown) {
		if !trustPrompt(unknown, *known) {
			fmt.Fprintln(os.Stderr, "server certificate was not trusted")
			os.Exit(1)
		}
		r, err = client.AuthenticateWithOptions(server, *key, info, o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(r.Tunnels) == 0 {
		fmt.Printf("authenticated as %s but no tunnels are allowed for this identity; ask the admin to add it to a tunnel's allow list.\n", r.Identity)
	}
	for _, t := range r.Tunnels {
		fmt.Printf("%-20s %5d  %s\n", t.Name, t.VirtualPort, t.Description)
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
func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("o", client.DefaultGeneratedIdentityFile(), "private key output")
	fs.Parse(args)
	fingerprint, err := client.GenerateIdentity(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	pub, _ := os.ReadFile(*out + ".pub")
	fmt.Printf("Identity created: %s\nFingerprint: %s\nSend this line to your administrator:\n%sNext: ntwire connect <server>\n", *out, fingerprint, pub)
}
