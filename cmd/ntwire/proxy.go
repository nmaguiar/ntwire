package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nmaguiar/ntwire/internal/egressattach"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
	"github.com/nmaguiar/ntwire/pkg/ui"
	"gopkg.in/yaml.v3"
)

func readProxyConfig(path string) (egressrouter.Config, error) {
	var file struct {
		SmartProxy egressrouter.Config `yaml:"smart_proxy"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return file.SmartProxy, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err = decoder.Decode(&file); err != nil {
		return file.SmartProxy, err
	}
	return file.SmartProxy.Normalized()
}

func proxyCommand(args []string, u *ui.UI) error {
	operation := ""
	if len(args) > 0 {
		switch args[0] {
		case "status", "reload", "pac", "prefer", "exclude", "include", "clear-preference":
			operation, args = args[0], args[1:]
		}
	}
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(u.Err)
	path := fs.String("config", "", "router YAML configuration file")
	group := fs.String("group", "default", "proxy group")
	profile := fs.String("profile", "", "egress profile ID")
	tunnel := fs.String("tunnel", "", "egress tunnel name")
	outputJSON := fs.Bool("json", false, "print JSON status")
	_ = fs.Bool("no-color", false, "disable colors")
	fs.Usage = func() {
		fmt.Fprintln(u.Err, "Usage: ntwire proxy [status|reload|pac|prefer|exclude|include|clear-preference] --config egress.yaml [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("proxy requires --config egress.yaml")
	}
	absolute, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	root, err := egressattach.Root()
	if err != nil {
		return err
	}
	controlPath := filepath.Join(root, "routers", egressattach.ControlID(absolute))
	if operation == "pac" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, err := egressattach.Call(ctx, controlPath, "pac:"+*group)
		if err != nil {
			return err
		}
		var script string
		if err = json.Unmarshal(result, &script); err != nil {
			return err
		}
		_, err = fmt.Fprint(u.Out, script)
		return err
	}
	switch operation {
	case "prefer", "exclude", "include", "clear-preference":
		change := proxyPreference{Group: *group, ID: egressrouter.MemberID{ProfileID: *profile, Tunnel: *tunnel}}
		if operation != "clear-preference" && (!egressrouter.ValidProfileID(*profile) || *tunnel == "" || len(*tunnel) > 255) {
			return errors.New("preference commands require --profile and --tunnel")
		}
		if operation == "clear-preference" {
			change.ID = egressrouter.MemberID{}
		}
		if operation == "exclude" || operation == "include" {
			excluded := operation == "exclude"
			change.Exclude = &excluded
		}
		body, err := json.Marshal(change)
		if err != nil {
			return err
		}
		operation = "preference:" + base64.RawURLEncoding.EncodeToString(body)
	}
	if operation != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, err := egressattach.Call(ctx, controlPath, operation)
		if err != nil {
			return err
		}
		if *outputJSON {
			fmt.Fprintln(u.Out, string(result))
		} else {
			var status egressrouter.Status
			if err := json.Unmarshal(result, &status); err != nil {
				return err
			}
			if status.Listening == "" {
				fmt.Fprintln(u.Out, "Smart Egress Proxy disabled")
			} else {
				fmt.Fprintf(u.Out, "Smart Egress Proxy %s (%s)\n", status.Listening, status.Selection)
			}
			printProxyMembers(u, status)
			names := make([]string, 0, len(status.Groups))
			for name := range status.Groups {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				group := status.Groups[name]
				fmt.Fprintf(u.Out, "%s %s (%s)\n", name, group.Listening, group.Selection)
				printProxyMembers(u, group)
			}
		}
		return nil
	}
	cfg, err := readProxyConfig(absolute)
	if err != nil {
		return err
	}
	if !cfg.AnyEnabled() {
		return errors.New("set smart_proxy.enabled to true to run the router")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	registry := egressattach.NewRegistry(root)
	router := egressrouter.NewDiscoveredGroupSet(registry.Candidate, registry.Discover)
	defer router.Close()
	var mu sync.Mutex
	service, err := egressattach.Start(controlPath, nil, func(op string) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		if name, ok := strings.CutPrefix(op, "pac:"); ok {
			return router.PAC(name)
		}
		if preference, ok := strings.CutPrefix(op, "preference:"); ok {
			var change proxyPreference
			raw, err := base64.RawURLEncoding.DecodeString(preference)
			if err != nil {
				return nil, err
			}
			if err = json.Unmarshal(raw, &change); err != nil {
				return nil, err
			}
			if err = router.SetPreference(change.Group, change.ID, change.Exclude); err != nil {
				return nil, err
			}
		}
		if op == "reload" {
			next, err := readProxyConfig(absolute)
			if err != nil {
				return nil, err
			}
			if err = router.Apply(next, nil); err != nil {
				return nil, err
			}
			cfg = next
		}
		return router.Status(), nil
	})
	if err != nil {
		return err
	}
	defer service.Close()
	mu.Lock()
	err = router.Apply(cfg, nil)
	mu.Unlock()
	if err != nil {
		return err
	}
	refresh := func() {
		mu.Lock()
		members, enrollment := cfg.Members(), cfg.Enrollments()
		mu.Unlock()
		refreshCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		registry.Refresh(refreshCtx, members, enrollment...)
	}
	refresh()
	status := router.Status()
	if status.Listening != "" {
		fmt.Fprintf(u.Out, "Smart Egress Proxy listening on %s\n", status.Listening)
	}
	for name, group := range status.Groups {
		if group.Listening != "" {
			fmt.Fprintf(u.Out, "Smart Egress Proxy group %s listening on %s\n", name, group.Listening)
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refresh()
		}
	}
}

func printProxyMembers(u *ui.UI, status egressrouter.Status) {
	if status.Listening != "" {
		fmt.Fprintf(u.Out, "  %d active, %d/%d failovers recovered\n", status.Active, status.Recovered, status.Failovers)
	}
	if status.Selected != nil {
		fmt.Fprintf(u.Out, "  last selected %s/%s (%s)\n", status.Selected.ProfileID, status.Selected.Tunnel, status.SelectionReason)
	}
	for _, m := range status.Members {
		parts := []string{m.ProfileID + "/" + m.Tunnel, m.Circuit}
		if m.Transport != "" {
			parts = append(parts, m.Transport)
		}
		if m.RTT > 0 {
			parts = append(parts, fmt.Sprintf("%.1f ms RTT", float64(m.RTT)/float64(time.Millisecond)))
		}
		if m.ConnectMillis > 0 {
			parts = append(parts, fmt.Sprintf("%.1f ms CONNECT", m.ConnectMillis))
		}
		if m.RecentSamples > 0 {
			parts = append(parts, fmt.Sprintf("%.1f%% success (%d recent)", 100*m.SuccessRate, m.RecentSamples))
		}
		if m.Reason != "" {
			parts = append(parts, m.Reason)
		}
		fmt.Fprintln(u.Out, "  "+strings.Join(parts, " | "))
	}
}

type proxyPreference struct {
	Group   string
	ID      egressrouter.MemberID
	Exclude *bool
}
