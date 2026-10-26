package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"github.com/nmaguiar/ntwire/pkg/ui"
	"github.com/nmaguiar/ntwire/pkg/updater"
	"golang.org/x/term"
)

func updateCmd(args []string, u *ui.UI) {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(u.Err)
	check := fs.Bool("check", false, "check for a signed stable update without downloading")
	yes := fs.Bool("yes", false, "install without confirmation; never prompt for administrator access")
	setUsage(fs, u, "check for or install a signed stable client update", "ntwire update --check", "ntwire update", "ntwire update --yes")
	if e := fs.Parse(args); e != nil {
		if !errors.Is(e, flag.ErrHelp) {
			os.Exit(2)
		}
		return
	}
	if fs.NArg() != 0 {
		u.Errorf("update accepts no positional arguments")
		os.Exit(2)
	}
	if e := performUpdate(*check, *yes, u); e != nil {
		u.Errorf("update: %v", e)
		os.Exit(1)
	}
}
func performUpdate(check, yes bool, u *ui.UI) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	c := updater.NewClient()
	current := buildinfo.String()
	r, e := c.Check(ctx, "ntwire", current)
	if e != nil {
		return e
	}
	if r == nil {
		fmt.Fprintln(u.Out, "ntwire", current, "is up to date.")
		return nil
	}
	fmt.Fprintf(u.Out, "Current: %s\nLatest: %s\n%s\n", current, r.Manifest.Version, r.Notes)
	if check {
		return nil
	}
	if e = updater.CanInstall(current); e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	target, e := updater.Target(self, "ntwire")
	if e != nil {
		return e
	}
	if e = updater.Writable(target); e != nil {
		return fmt.Errorf("%w; use your package manager or rerun this explicit command from an administrator terminal", e)
	}
	if !yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("confirmation requires a terminal; use --yes for unattended installation")
		}
		fmt.Fprint(u.Out, "Install this update? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return nil
		}
	}
	cache, e := os.UserCacheDir()
	if e != nil {
		return e
	}
	dir, e := os.MkdirTemp(filepath.Join(cache), "ntwire-update-*")
	if e != nil {
		return e
	}
	archive, e := c.Download(ctx, r, dir, nil)
	if e != nil {
		os.RemoveAll(dir)
		return e
	}
	j := updater.Job{Release: *r, Archive: archive, Target: target, Current: current}
	if runtime.GOOS == "windows" {
		j.Result = filepath.Join(dir, "result.json")
		if e = updater.StartHelper(j, dir, false); e != nil {
			return e
		}
		fmt.Fprintln(u.Out, "Update verified. Installation starts after this command exits; result:", j.Result)
		return nil
	}
	defer os.RemoveAll(dir)
	if e = c.Install(j); e != nil {
		return e
	}
	fmt.Fprintln(u.Out, "Update installed. The previous installation is at", target+".previous-"+strings.TrimPrefix(current, "v"))
	return nil
}
