package main

import (
	"flag"
	"github.com/nmaguiar/ntwire/pkg/server"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config := flag.String("config", "ntwire.yaml", "server configuration file")
	flag.Parse()
	c, err := server.LoadConfig(*config)
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(2)
	}
	tlsManager, err := server.NewTLSManager(c)
	if err != nil {
		slog.Error("TLS configuration error", "error", err)
		os.Exit(2)
	}
	s := server.New(c, slog.Default())
	s.SetTLSManager(tlsManager)
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
	h := &http.Server{Addr: c.Listen.HTTPS, Handler: s.Handler(), TLSConfig: tlsManager.Config(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	slog.Info("ntwire server listening", "https", c.Listen.HTTPS, "wireguard", c.Listen.WireGuard)
	if err = h.ListenAndServeTLS("", ""); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
