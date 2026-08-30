// Package tray builds ntwire-gui's system tray / menu bar UI on top of
// fyne.io/systray, driven by an internal/gui/manager.Manager. It owns no
// networking of its own -- everything it shows or triggers goes through
// the manager, exactly as the settings window (internal/gui/api) does, so
// the two front ends can never see inconsistent state.
package tray

import (
	"runtime"
	"time"

	"fyne.io/systray"

	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/internal/gui/tray/icons"
)

// pickRegularIcon returns the non-macOS icon format SetTemplateIcon needs
// on the current platform: a genuine .ico on Windows (GDI's LoadImage
// requires the real container, see icons.RegularICO's doc comment), a
// plain PNG everywhere else (systray_unix.go's DBus StatusNotifierItem
// backend decodes it with image/png).
func pickRegularIcon(s icons.State) []byte {
	if runtime.GOOS == "windows" {
		return icons.RegularICO(s)
	}
	return icons.RegularPNG(s)
}

// Run builds the tray menu and blocks until the user quits (via the tray's
// own Quit item) or onExit is otherwise triggered. It must be called from
// the process's main goroutine, with runtime.LockOSThread already called
// by the caller: systray.Run pumps the platform's native event loop on
// whatever goroutine calls it, and that must be the one the OS's UI
// APIs were first touched from.
//
// openSettings is called (never blocking the caller) whenever the user
// asks to open the settings window, from the "Settings…" item or from a
// profile row that has nothing else useful to do with a click -- e.g. one
// parked awaiting a trust or passphrase decision, which only the settings
// window can render and answer. A nil openSettings disables "Settings…"
// instead of silently doing nothing.
func Run(mgr *manager.Manager, openSettings, openSetup func()) {
	systray.Run(func() { onReady(mgr, openSettings, openSetup) }, func() {})
}

func onReady(mgr *manager.Manager, openSettings, openSetup func()) {
	systray.SetTemplateIcon(icons.TemplatePNG(icons.StateNone), pickRegularIcon(icons.StateNone))
	systray.SetTooltip("ntwire")

	m := newMenu(mgr, openSettings, openSetup)
	m.render(mgr.Snapshots())

	updates, unsubscribe := mgr.Subscribe()
	go func() {
		defer unsubscribe()
		// Coalesce bursts of updates (e.g. several profiles connecting at
		// once) into one menu rebuild every tick, rather than one rebuild
		// per event -- each rebuild touches systray, and on macOS every
		// mutation is a synchronous cross-thread call.
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		dirty := false
		for {
			select {
			case _, ok := <-updates:
				if !ok {
					return
				}
				dirty = true
			case <-ticker.C:
				if dirty {
					m.render(mgr.Snapshots())
					dirty = false
				}
			}
		}
	}()

	// Auto-connecting Profile.ConnectOnStart profiles is deliberately not
	// done here: the plan (§6, Phase 6) ties that to the --autostart flag,
	// not to every tray launch, so it belongs in cmd/ntwire-gui's startup
	// logic, which knows how it was invoked.
}
