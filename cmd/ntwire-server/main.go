package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"github.com/nmaguiar/ntwire/pkg/ui"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	config := flag.String("config", "ntwire.yaml", "server configuration file")
	printSampleConfig := flag.Bool("print-sample-config", false, "print a fully commented sample YAML configuration and exit")
	printVersion := flag.Bool("version", false, "print the build version and exit")
	generateRelayKey := flag.String("generate-relay-key", "", "generate an Ed25519 identity for relay.identity_file at this path, print setup instructions, and exit")
	generateWireGuardKey := flag.String("generate-wireguard-key", "", "generate a WireGuard key pair at this path (and path.pub) for a native_wireguard peer, print setup instructions, and exit")
	logFormat := flag.String("log-format", "", "log output format: text or json (default: config file, then NTWIRE_LOG_FORMAT, then text)")
	logLevel := flag.String("log-level", "", "log level: debug, info, warn, error (default: config file, then NTWIRE_LOG_LEVEL, then info)")
	noColor := flag.Bool("no-color", false, "disable ANSI colors in text-format logs (or set NO_COLOR)")
	flag.Usage = func() {
		ui.Spec{
			Tool:    "ntwire-server",
			Tagline: "ntwire tunnel server",
			Flags:   ui.FlagsOf(flag.CommandLine),
			Examples: []string{
				"ntwire-server -config ntwire.yaml",
				"ntwire-server -print-sample-config > ntwire.yaml",
				"ntwire-server -generate-relay-key relay_id_ed25519",
				"ntwire-server -generate-wireguard-key client_wg",
				"ntwire-server -version",
			},
		}.Fprint(os.Stderr, ui.New(os.Stdout, os.Stderr, false))
	}
	flag.Parse()
	if *printVersion {
		fmt.Println(buildinfo.String())
		return
	}
	if *printSampleConfig {
		fmt.Print(server.SampleConfig())
		return
	}
	if *generateRelayKey != "" {
		generateRelayKeyAndExit(*generateRelayKey, ui.New(os.Stdout, os.Stderr, *noColor))
	}
	if *generateWireGuardKey != "" {
		generateWireGuardKeyAndExit(*generateWireGuardKey, ui.New(os.Stdout, os.Stderr, *noColor))
	}

	caps := ui.Detect(os.Stderr, *noColor)
	flagLogOpts := logging.Options{Format: *logFormat, Level: *logLevel}
	bootstrap := logging.Resolve(flagLogOpts, logging.Options{}, logging.EnvOptions("NTWIRE"))
	slog.SetDefault(slog.New(logging.NewHandler(os.Stderr, bootstrap, caps)))

	c, err := server.LoadConfig(*config)
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(2)
	}
	final := logging.Resolve(flagLogOpts, c.Log.Options(), logging.EnvOptions("NTWIRE"))
	mainHandler := logging.NewHandler(os.Stderr, final, caps)
	slog.SetDefault(slog.New(mainHandler))

	tlsManager, err := server.NewTLSManager(c)
	if err != nil {
		slog.Error("TLS configuration error", "error", err)
		os.Exit(2)
	}
	s := server.New(c, slog.Default())
	s.SetTLSManager(tlsManager)
	if c.MASQUE.Enabled {
		gateway, gatewayErr := server.NewMASQUEGateway(s, tlsManager.Config())
		if gatewayErr != nil {
			slog.Error("MASQUE gateway configuration error", "error", gatewayErr)
			os.Exit(2)
		}
		go func() {
			slog.Info("ntwire MASQUE gateway listening", "https", c.MASQUE.Listen)
			if e := gateway.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
				slog.Error("MASQUE gateway stopped", "error", e)
			}
		}()
	}
	if c.Audit.LogFile != "" {
		f, err := os.OpenFile(c.Audit.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			slog.Error("audit log file error", "error", err)
			os.Exit(2)
		}
		defer f.Close()
		s.SetAuditLog(slog.New(logging.NewMultiHandler(mainHandler, logging.NewLogstashHandler(f, slog.LevelInfo))))
	}
	if err = s.StartDataPlane(); err != nil {
		slog.Error("data plane error", "error", err)
		os.Exit(2)
	}
	defer s.Close()
	if _, err = server.WatchConfig(*config, s, slog.Default()); err != nil {
		slog.Warn("config watch disabled", "error", err)
	}
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		for range ch {
			next, e := server.LoadConfig(*config)
			if e != nil {
				slog.Warn("SIGHUP reload rejected", "error", e)
				continue
			}
			s.Reload(next)
		}
	}()
	// IdleTimeout only bounds idle keep-alive connections between requests; it
	// does not apply once /v1/wg's WebSocket has hijacked the connection, so
	// long-running data-plane sessions are unaffected. ReadTimeout/WriteTimeout
	// are deliberately not set: they would also cut off that hijacked stream.
	if c.Listen.Metrics != "" {
		mh := &http.Server{Addr: c.Listen.Metrics, Handler: s.MetricsHandler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			slog.Info("ntwire metrics listening", "metrics", c.Listen.Metrics, "endpoint", "/metrics")
			if e := mh.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
				slog.Error("metrics server stopped", "error", e)
			}
		}()
	}
	h := &http.Server{Addr: c.Listen.HTTPS, Handler: s.Handler(), TLSConfig: tlsManager.Config(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	if c.Relay.Enabled {
		pool, err := server.NewRelayPool(c.Relay, slog.Default())
		if err != nil {
			slog.Error("relay configuration error", "error", err)
			os.Exit(2)
		}
		if c.Relay.AdvertiseDirect {
			pool.OnReflectAddr = s.EnableDirectUpgrade
		}
		// Unconditional, unlike AdvertiseDirect above: the UDP-relay
		// forwarding tier never reveals this server's real address (the
		// relay stays in the data path throughout), so there is no matching
		// trust step-change to opt into. See RelayConfig.AdvertiseDirect's
		// doc comment.
		pool.OnUDPRelayAddr = func(agent *server.RelayAgent, addr string) {
			s.EnableUDPRelay(agent, addr)
		}
		pool.OnNativeWireGuard = s.EnableNativeWireGuardRelay
		go pool.Run(context.Background())
		defer pool.Close()
		slog.Info("ntwire server relaying", "relay_url", c.Relay.URL, "relay_endpoints", len(c.Relay.Endpoints), "relay_name", c.Relay.Name, "version", buildinfo.String(), "tls_fingerprint", tlsManager.Fingerprint())
		if err = h.ServeTLS(pool.Listener(), "", ""); err != nil {
			slog.Error("server stopped", "error", err)
			os.Exit(1)
		}
		return
	}
	slog.Info("ntwire server listening", "https", c.Listen.HTTPS, "wireguard", c.Listen.WireGuard, "version", buildinfo.String(), "tls_fingerprint", tlsManager.Fingerprint())
	if err = h.ListenAndServeTLS("", ""); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// generateRelayKeyAndExit creates the Ed25519 identity relay.identity_file
// points at -- a key separate from auth.authorized_keys_dir, used only to
// sign this server's registration with an ntwire-relay (see PLAN-RELAY.md
// and docs/RELAY.md) -- and prints the two follow-up edits an operator needs
// to wire it in: a registrations[] entry on the relay, and the relay: block
// here. It never touches *config, since relay.enabled with no
// identity_file yet is exactly the state LoadConfig rejects.
func generateRelayKeyAndExit(path string, u *ui.UI) {
	fingerprint, err := sshkey.GenerateIdentityFile(path)
	if err != nil {
		u.Errorf("generate-relay-key: %v", err)
		os.Exit(1)
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		u.Errorf("generate-relay-key: %v", err)
		os.Exit(1)
	}
	u.Success("Relay identity created: %s (fingerprint %s)", path, fingerprint)
	fmt.Fprintf(u.Out, `
This key only authenticates this server's registration with an
ntwire-relay; it is unrelated to auth.authorized_keys_dir and this
server's own TLS certificate (which is generated automatically).

1. Give the relay operator this authorized_keys line to add as a
   registrations[] entry in ntwire-relay.yaml, choosing <name> as the
   first DNS label this server will be reached at (<name>.<relay domain>):

     - name: <name>
       public_key: "%s"

2. In this server's config, add:

     relay:
       enabled: true
       url: "wss://<relay-host>:<relay listen.agents port>"
       name: <name>                 # must match the registrations[] entry above
       identity_file: %s
       fingerprint: ""              # optional SHA256:... pin of the relay's own
                                     # cert, obtained from the relay operator

See docs/RELAY.md for the full walkthrough.
`, strings.TrimSpace(string(pub)), path)
	os.Exit(0)
}

// generateWireGuardKeyAndExit creates an ordinary WireGuard key pair for a
// client that will be admitted as a native peer (see docs/NATIVE-WIREGUARD.md),
// so an operator never needs "wg genkey"/"wg pubkey" from wireguard-tools
// installed anywhere. It never touches *config or this server's own
// persistent key (network.wireguard_private_key_file): the two keys are
// unrelated, and this one is meant to leave the server for the client.
func generateWireGuardKeyAndExit(path string, u *ui.UI) {
	key, err := wgnet.GenerateKey()
	if err != nil {
		u.Errorf("generate-wireguard-key: %v", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, []byte(key.Private), 0600); err != nil {
		u.Errorf("generate-wireguard-key: %v", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path+".pub", []byte(key.Public), 0644); err != nil {
		u.Errorf("generate-wireguard-key: %v", err)
		os.Exit(1)
	}
	u.Success("WireGuard key pair created: %s (public key %s)", path, key.Public)
	fmt.Fprintf(u.Out, `
This is an ordinary WireGuard key pair, unrelated to auth.authorized_keys_dir
and this server's own persistent key (network.wireguard_private_key_file).
It's meant for a client that will be admitted as a native WireGuard peer.

1. %s (mode 0600) holds the private key. It belongs on the client, not here:
   move or copy it there, delete it from this server once transferred, and
   treat it as sensitive from that point on. On the client, it goes into the
   profile's [Interface] PrivateKey:

     [Interface]
     PrivateKey = <contents of %s>
     Address = <tunnel_ip>/32

     [Peer]
     PublicKey = <this server's public key, from network.wireguard_private_key_file>
     Endpoint = <this server's address>:<listen.wireguard port, default 51820>
     AllowedIPs = <network.tunnel_cidr>
     PersistentKeepalive = 25

2. Add the public key (%s, also saved to %s.pub) to this server's config:

     native_wireguard:
       enabled: true
       peers:
         - name: <name>
           public_key: "%s"
           tunnel_ip: <tunnel_ip from step 1>
           tunnels: [<tunnel name>]

See docs/NATIVE-WIREGUARD.md for the full walkthrough, and
docs/RELAY.md#native-wireguard-udp-endpoints if this server is reached
through ntwire-relay instead of directly.
`, path, path, key.Public, path, key.Public)
	os.Exit(0)
}
