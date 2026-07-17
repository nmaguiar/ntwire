package main

import (
	"flag"
	"github.com/nmaguiar/nwire/pkg/server"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config := flag.String("config", "nwire.yaml", "server configuration file")
	flag.Parse()
	c, err := server.LoadConfig(*config)
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(2)
	}
	s := server.New(c, slog.Default())
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
	tlsConfig, err := server.TLSConfig(c)
	if err != nil {
		slog.Error("TLS configuration error", "error", err)
		os.Exit(2)
	}
	h := &http.Server{Addr: c.Listen.HTTPS, Handler: s.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 10e9}
	slog.Info("nwire server listening", "https", c.Listen.HTTPS, "wireguard", c.Listen.WireGuard)
	if err = h.ListenAndServeTLS("", ""); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
