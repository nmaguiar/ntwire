package main

import (
	"flag"
	"github.com/nmaguiar/nwire/pkg/server"
	"log/slog"
	"net/http"
	"os"
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
	if _, err = server.WatchConfig(*config, s, slog.Default()); err != nil {
		slog.Warn("config watch disabled", "error", err)
	}
	slog.Info("nwire server listening", "https", c.Listen.HTTPS)
	if err = http.ListenAndServe(c.Listen.HTTPS, s.Handler()); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
