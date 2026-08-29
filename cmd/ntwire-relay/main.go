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
	if len(os.Args) > 1 && os.Args[1] == "help" {
		if len(os.Args) > 2 && os.Args[2] == "completion" {
			runCompletion([]string{"-h"}, ui.New(os.Stdout, os.Stderr, false))
			return
		}
		flag.Usage()
		return
	}

	config := flag.String("config", "ntwire-relay.yaml", "relay configuration file")
	printSampleConfig := flag.Bool("print-sample-config", false, "print a fully commented sample YAML configuration and exit")
	printConfigGuide := flag.Bool("print-config-guide", false, "print the self-contained Markdown configuration guide and exit")
	configGuideFormat := flag.String("config-guide-format", "markdown", "format for -print-config-guide: markdown or json-schema")
	writeConfigSkill := flag.String("write-config-skill", "", "create a self-contained Agent Skill folder at this new directory and exit")
	checkConfig := flag.Bool("check-config", false, "validate the configuration and exit without starting listeners")
	printVersion := flag.Bool("version", false, "print the build version and exit")
	logFormat := flag.String("log-format", "", "log output format: text or json (default: config file, then NTWIRE_LOG_FORMAT, then text)")
	logLevel := flag.String("log-level", "", "log level: debug, info, warn, error (default: config file, then NTWIRE_LOG_LEVEL, then info)")
	noColor := flag.Bool("no-color", false, "disable ANSI colors in text-format logs (or set NO_COLOR)")
	completionShell := flag.String("completion", "", "generate shell completion script (bash, zsh, fish, powershell) and exit")
	flag.Usage = func() {
		ui.Spec{
			Tool:    "ntwire-relay",
			Tagline: "NAT-traversal relay for ntwire-server",
			Commands: []ui.Command{
				{Name: "completion", Summary: "generate shell completion script"},
			},
			Flags: ui.FlagsOf(flag.CommandLine),
			Examples: []string{
				"ntwire-relay -config ntwire-relay.yaml",
				"ntwire-relay -print-sample-config > ntwire-relay.yaml",
				"ntwire-relay -print-config-guide > docs/relay-config-guide.md",
				"ntwire-relay -print-config-guide -config-guide-format=json-schema > relay-config.schema.json",
				"ntwire-relay -write-config-skill .github/skills/ntwire-relay-config",
				"ntwire-relay -check-config -config ntwire-relay.yaml",
				"ntwire-relay completion bash > /etc/bash_completion.d/ntwire-relay",
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
	if *printConfigGuide {
		var out string
		var err error
		switch *configGuideFormat {
		case "markdown":
			out, err = relay.ConfigGuide()
		case "json-schema":
			var schema []byte
			schema, err = relay.ConfigJSONSchema()
			out = string(schema) + "\n"
		default:
			fmt.Fprintf(os.Stderr, "configuration guide format must be markdown or json-schema, got %q\n", *configGuideFormat)
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "configuration guide error: %v\n", err)
			os.Exit(2)
		}
		fmt.Print(out)
		return
	}
	if *writeConfigSkill != "" {
		if err := relay.WriteConfigSkill(*writeConfigSkill); err != nil {
			fmt.Fprintf(os.Stderr, "configuration skill error: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("wrote configuration skill: %s\n", *writeConfigSkill)
		return
	}
	if *checkConfig {
		if _, err := relay.LoadConfig(*config); err != nil {
			fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("configuration is valid: %s\n", *config)
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
	if err := completion.Generate(sh, completion.RelayCommand(), u.Out); err != nil {
		u.Errorf("completion: %v", err)
		os.Exit(1)
	}
}
