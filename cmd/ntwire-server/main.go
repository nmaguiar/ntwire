package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/ui"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config := flag.String("config", "ntwire.yaml", "server configuration file")
	printSampleConfig := flag.Bool("print-sample-config", false, "print a fully commented sample YAML configuration and exit")
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
			},
		}.Fprint(os.Stderr, ui.New(os.Stdout, os.Stderr, false))
	}
	flag.Parse()
	if *printSampleConfig {
		fmt.Print(server.SampleConfig())
		return
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
		agent, err := server.NewRelayAgent(c.Relay, slog.Default())
		if err != nil {
			slog.Error("relay configuration error", "error", err)
			os.Exit(2)
		}
		go agent.Run(context.Background())
		defer agent.Close()
		slog.Info("ntwire server relaying", "relay_url", c.Relay.URL, "relay_name", c.Relay.Name, "version", buildinfo.String(), "tls_fingerprint", tlsManager.Fingerprint())
		if err = h.ServeTLS(agent.Listener(), "", ""); err != nil {
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
