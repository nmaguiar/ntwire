package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"github.com/nmaguiar/ntwire/pkg/relay"
)

func main() {
	config := flag.String("config", "ntwire-relay.yaml", "relay configuration file")
	printSampleConfig := flag.Bool("print-sample-config", false, "print a fully commented sample YAML configuration and exit")
	flag.Parse()
	if *printSampleConfig {
		fmt.Print(relay.SampleConfig())
		return
	}
	c, err := relay.LoadConfig(*config)
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(2)
	}
	r, err := relay.New(c, slog.Default())
	if err != nil {
		slog.Error("relay configuration error", "error", err)
		os.Exit(2)
	}
	if err = r.Start(); err != nil {
		slog.Error("relay start error", "error", err)
		os.Exit(2)
	}
	defer r.Close()
	slog.Info("ntwire-relay started", "version", buildinfo.String())

	reload := func() {
		next, e := relay.LoadConfig(*config)
		if e != nil {
			slog.Warn("configuration reload rejected", "error", e)
			return
		}
		if e = r.ReloadRegistrations(next.Registrations); e != nil {
			slog.Warn("registrations reload rejected", "error", e)
			return
		}
		slog.Info("registrations reloaded")
	}

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		for range ch {
			reload()
		}
	}()

	if w, err := fsnotify.NewWatcher(); err == nil {
		if err = w.Add(filepath.Dir(*config)); err == nil {
			go func() {
				for {
					select {
					case e, ok := <-w.Events:
						if !ok {
							return
						}
						if filepath.Clean(e.Name) == filepath.Clean(*config) && e.Has(fsnotify.Write|fsnotify.Create|fsnotify.Rename) {
							reload()
						}
					case _, ok := <-w.Errors:
						if !ok {
							return
						}
					}
				}
			}()
		} else {
			w.Close()
			slog.Warn("config watch disabled", "error", err)
		}
	} else {
		slog.Warn("config watch disabled", "error", err)
	}

	select {}
}
