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
	"github.com/nmaguiar/ntwire/pkg/completion"
	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/relay"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "completion" {
		runCompletion(os.Args[2:], ui.New(os.Stdout, os.Stderr, false))
		return
	}

	config := flag.String("config", "ntwire-relay.yaml", "relay configuration file")
	printSampleConfig := flag.Bool("print-sample-config", false, "print a fully commented sample YAML configuration and exit")
	printVersion := flag.Bool("version", false, "print the build version and exit")
	logFormat := flag.String("log-format", "", "log output format: text or json (default: config file, then NTWIRE_LOG_FORMAT, then text)")
	logLevel := flag.String("log-level", "", "log level: debug, info, warn, error (default: config file, then NTWIRE_LOG_LEVEL, then info)")
	noColor := flag.Bool("no-color", false, "disable ANSI colors in text-format logs (or set NO_COLOR)")
	completionShell := flag.String("completion", "", "generate shell completion script (bash, zsh, fish, powershell) and exit")
	flag.Usage = func() {
		ui.Spec{
			Tool:    "ntwire-relay",
			Tagline: "NAT-traversal relay for ntwire-server",
			Flags:   ui.FlagsOf(flag.CommandLine),
			Examples: []string{
				"ntwire-relay -config ntwire-relay.yaml",
				"ntwire-relay -print-sample-config > ntwire-relay.yaml",
				"ntwire-relay -completion bash > /etc/bash_completion.d/ntwire-relay",
				"ntwire-relay -version",
			},
		}.Fprint(os.Stderr, ui.New(os.Stdout, os.Stderr, false))
	}
	flag.Parse()
	if *printVersion {
		fmt.Println(buildinfo.String())
		return
	}
	if *completionShell != "" {
		runCompletion([]string{*completionShell}, ui.New(os.Stdout, os.Stderr, *noColor))
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

func runCompletion(args []string, u *ui.UI) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		ui.Spec{
			Tool:    "ntwire-relay completion",
			Tagline: "generate shell completion script for bash, zsh, fish, or powershell",
			Commands: []ui.Command{
				{Name: "bash", Summary: "generate completion script for bash"},
				{Name: "zsh", Summary: "generate completion script for zsh"},
				{Name: "fish", Summary: "generate completion script for fish"},
				{Name: "powershell", Summary: "generate completion script for powershell"},
			},
			Examples: []string{
				"ntwire-relay completion bash > /etc/bash_completion.d/ntwire-relay",
				"source <(ntwire-relay completion zsh)",
				"ntwire-relay -completion fish | source",
			},
		}.Fprint(os.Stderr, u)
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
	if err := completion.Generate(sh, completion.RelayCommand(), u.Out); err != nil {
		u.Errorf("completion: %v", err)
		os.Exit(1)
	}
}
