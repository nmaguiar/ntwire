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
	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func main() {
	config := flag.String("config", "ntwire-relay.yaml", "relay configuration file")
	printSampleConfig := flag.Bool("print-sample-config", false, "print a fully commented sample YAML configuration and exit")
	printVersion := flag.Bool("version", false, "print the build version and exit")
	logFormat := flag.String("log-format", "", "log output format: text or json (default: config file, then NTWIRE_LOG_FORMAT, then text)")
	logLevel := flag.String("log-level", "", "log level: debug, info, warn, error (default: config file, then NTWIRE_LOG_LEVEL, then info)")
	noColor := flag.Bool("no-color", false, "disable ANSI colors in text-format logs (or set NO_COLOR)")
	flag.Usage = func() {
		ui.Spec{
			Tool:    "ntwire-relay",
			Tagline: "NAT-traversal relay for ntwire-server",
			Flags:   ui.FlagsOf(flag.CommandLine),
			Examples: []string{
				"ntwire-relay -config ntwire-relay.yaml",
				"ntwire-relay -print-sample-config > ntwire-relay.yaml",
				"ntwire-relay -version",
			},
		}.Fprint(os.Stderr, ui.New(os.Stdout, os.Stderr, false))
	}
	flag.Parse()
	if *printVersion {
		fmt.Println(buildinfo.String())
		return
	}
	if *printSampleConfig {
		fmt.Print(relay.SampleConfig())
		return
	}

	caps := ui.Detect(os.Stderr, *noColor)
	flagLogOpts := logging.Options{Format: *logFormat, Level: *logLevel}
	bootstrap := logging.Resolve(flagLogOpts, logging.Options{}, logging.EnvOptions("NTWIRE"))
	slog.SetDefault(slog.New(logging.NewHandler(os.Stderr, bootstrap, caps)))

	c, err := relay.LoadConfig(*config)
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(2)
	}
	final := logging.Resolve(flagLogOpts, c.Log.Options(), logging.EnvOptions("NTWIRE"))
	slog.SetDefault(slog.New(logging.NewHandler(os.Stderr, final, caps)))

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
