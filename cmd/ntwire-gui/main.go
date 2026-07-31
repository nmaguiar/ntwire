// Command ntwire-gui is ntwire's tray/menu-bar client: the same
// functionality as `ntwire connect`, for one or more server profiles at
// once, run from a system tray icon instead of a terminal.
//
// It has three modes, chosen by flag:
//
//   - (no flags): the core process. Builds the connection manager and its
//     loopback settings API, then blocks running the tray on the main
//     thread. This is what a user launches. Before doing any of that, it
//     checks internal/gui/singleinstance's lock: if a live instance is
//     already running against the same gui.yaml, it raises that
//     instance's settings window instead and exits, rather than starting
//     a second connection manager that would double-connect every
//     profile.
//   - --headless: the same manager and API, with no tray, and no
//     single-instance check -- for automation and for testing this
//     binary end-to-end without a real display or tray backend (see
//     main_test.go).
//   - --window <url>: hosts the settings window at url -- a native webview
//     when built with `go build -tags gui`, a plain browser tab
//     otherwise (see internal/gui/window). The core process spawns this
//     as a child re-executing the same binary; url carries only the bare
//     origin, with the API's access token passed via the
//     NTWIRE_GUI_TOKEN environment variable instead of argv, which
//     (unlike environ) any local user can read via ps or
//     /proc/<pid>/cmdline.
//
// --autostart marks a launch as having come from the OS's own login-item
// mechanism (internal/gui/autostart registers the entry with this flag
// baked in) rather than an interactive user; it is what triggers
// auto-connecting profiles with ConnectOnStart set. It has no effect in
// --headless or --window mode.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nmaguiar/ntwire/internal/gui/api"
	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/internal/gui/singleinstance"
	"github.com/nmaguiar/ntwire/internal/gui/tray"
	"github.com/nmaguiar/ntwire/internal/gui/window"
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"github.com/nmaguiar/ntwire/pkg/logging"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

const windowTokenEnvVar = "NTWIRE_GUI_TOKEN"

// init runs on the process's guaranteed-main goroutine before anything
// else does, which is what locking it to the main OS thread here actually
// requires: main() itself may have already been resumed on a different M
// by the time a blocking call (file I/O, net.Listen) returns, and pinning
// the wrong thread means [NSApp run] later runs on a thread AppKit never
// expects it on -- silently: the process stays alive with no icon, which
// a liveness check can't tell apart from success. See internal/gui/tray's
// package doc for why the tray needs this thread to never change.
func init() {
	runtime.LockOSThread()
}

func main() {
	var (
		headless  = flag.Bool("headless", false, "run the connection manager and settings API without a tray icon")
		windowURL = flag.String("window", "", "internal: host a native settings window at this URL (spawned by the core process, not for direct use)")
		version   = flag.Bool("version", false, "print the version and exit")
		guiConfig = flag.String("gui-config", "", "path to gui.yaml (default ~/.ntwire/gui.yaml)")
		cliConfig = flag.String("cli-config", "", "path to the CLI's config.yaml, imported once on first run (default ~/.ntwire/config.yaml)")
		autostart = flag.Bool("autostart", false, "the process was launched by the OS's own login-item mechanism (set automatically by the registered autostart entry; not for interactive use)")
	)
	flag.Parse()

	if *version {
		fmt.Println(buildinfo.String())
		return
	}

	slog.SetDefault(slog.New(logging.NewHandler(os.Stderr, logging.EnvOptions("NTWIRE"), ui.Detect(os.Stderr, false))))

	if *windowURL != "" {
		runWindow(*windowURL)
		return
	}

	guiConfigPath := *guiConfig
	if guiConfigPath == "" {
		guiConfigPath = config.DefaultPath()
	}

	// Single-instance check: only for the tray's own launch, not
	// --headless, which is what this repo's own end-to-end checks drive
	// and would otherwise collide with a tray instance a developer
	// happens to have running. A second tray launch that finds a live
	// instance raises its settings window and exits before touching
	// anything else -- in particular, before connecting any profile.
	if !*headless {
		if existing := findExistingInstance(guiConfigPath); existing != nil {
			openWindowFor(existing.URL, existing.Token)
			return
		}
	}

	mgr, err := manager.New(manager.NewConnector(), *guiConfig, *cliConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ntwire-gui:", err)
		os.Exit(1)
	}
	defer mgr.Close()

	srv, err := api.New(mgr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ntwire-gui:", err)
		os.Exit(1)
	}

	if *headless {
		runHeadless(srv)
		return
	}

	if lockPath, err := singleinstance.LockPath(guiConfigPath); err == nil {
		info := singleinstance.Info{PID: os.Getpid(), URL: "http://" + srv.Addr(), Token: srv.Token()}
		if err := singleinstance.Write(lockPath, info); err != nil {
			slog.Warn("could not write single-instance lock file; a second launch will not detect this one", "error", err)
		} else {
			defer func() { _ = singleinstance.Remove(lockPath) }()
		}
	}

	go func() {
		if err := srv.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("settings API server stopped unexpectedly", "error", err)
		}
	}()
	defer srv.Close()

	// Deliberately after srv.Serve has started: a ConnectOnStart profile
	// with an encrypted key parks in StateAwaitingPassphrase, answerable
	// only through the settings window, which needs the API serving.
	// mgr.Connect is asynchronous, so ordering this before Serve wouldn't
	// have deadlocked either -- promptTimeout's five minutes comfortably
	// outlasts the two-line race -- but there's no reason to leave that
	// race in place when moving three lines removes the question.
	if *autostart {
		for _, p := range mgr.Profiles() {
			if p.ConnectOnStart {
				if err := mgr.Connect(p.ID); err != nil {
					slog.Warn("could not auto-connect profile at login", "profile", p.Name, "error", err)
				}
			}
		}
	}

	tray.Run(mgr, openSettingsFunc(srv))
}

// findExistingInstance reports a live instance's Info, or nil if none is
// found or the lock path can't be resolved -- both treated the same way
// by the caller: proceed to start normally.
func findExistingInstance(guiConfigPath string) *singleinstance.Info {
	lockPath, err := singleinstance.LockPath(guiConfigPath)
	if err != nil {
		return nil
	}
	probeClient := &http.Client{Timeout: 2 * time.Second}
	existing, _ := singleinstance.Existing(lockPath, probeClient)
	return existing
}

// openWindowFor spawns a --window child at origin, with token passed via
// env. It is the one operation both "Settings…" (against this process's
// own API) and a second launch finding a live instance (against that
// instance's API) need, so both go through it.
func openWindowFor(origin, token string) {
	self, err := os.Executable()
	if err != nil {
		slog.Error("could not resolve ntwire-gui's own path to open the settings window", "error", err)
		return
	}
	var spawner window.Spawner
	env := []string{windowTokenEnvVar + "=" + token}
	if err := spawner.Open(self, []string{"--window", origin}, env); err != nil {
		slog.Error("failed to open the settings window", "error", err)
	}
}

// openSettingsFunc builds the tray's "Settings…" action against srv's own
// bare origin.
func openSettingsFunc(srv *api.Server) func() {
	return func() { openWindowFor("http://"+srv.Addr(), srv.Token()) }
}

// runHeadless serves the settings API in the foreground with no tray,
// until interrupted. It prints the API's URL (including its access token)
// to stdout so a test harness or automation script can reach it without
// scraping logs.
func runHeadless(srv *api.Server) {
	fmt.Println(srv.URL())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		srv.Close()
	}()

	if err := srv.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "ntwire-gui:", err)
		os.Exit(1)
	}
}

// runWindow hosts the settings window at the bare origin the core process
// passed in argv, reassembling the full token-bearing URL from
// NTWIRE_GUI_TOKEN itself rather than trusting it to have arrived in argv
// (see this file's package doc for why).
func runWindow(origin string) {
	full := origin
	if token := os.Getenv(windowTokenEnvVar); token != "" {
		sep := "?"
		if strings.Contains(full, "?") {
			sep = "&"
		}
		full += sep + "token=" + token
	}
	if err := window.Run(full); err != nil {
		fmt.Fprintln(os.Stderr, "ntwire-gui: opening settings window:", err)
		os.Exit(1)
	}
}
