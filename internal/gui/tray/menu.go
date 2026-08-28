package tray

import (
	"fmt"
	"os"
	"sync"

	"fyne.io/systray"

	"github.com/nmaguiar/ntwire/internal/gui/autostart"
	"github.com/nmaguiar/ntwire/internal/gui/manager"
	"github.com/nmaguiar/ntwire/internal/gui/tray/icons"
	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// maxProfiles and maxTunnelsPerProfile bound the fixed pool of menu items
// pre-created at startup -- fyne.io/systray has no way to remove a menu
// item once added, so the menu can never grow past what was created here.
// A profile or tunnel beyond these limits is simply not shown in the tray;
// the settings window (all of them, always) is the uncapped view.
const (
	maxProfiles          = 16
	maxTunnelsPerProfile = 8

	dashboardSlotID  = "dashboard"
	connectSlotID    = "connect"
	disconnectSlotID = "disconnect"
)

// profileSlot is one pre-created row in the tray's fixed profile pool: the
// row itself (click toggles connect/disconnect), single-item pools for its
// "Open dashboard…", "Connect" and "Disconnect" entries, and its own small
// pool of tunnel rows (click copies that tunnel's local address). Each of
// these single-item pools is a slotPool of size one, rather than a bare
// *systray.MenuItem, purely so its click dispatch goes through the same
// tested acquire/release/setAction machinery as everything else instead of
// a bespoke bind-once path.
type profileSlot struct {
	item          *systray.MenuItem
	dashboard     *slotPool
	connect       *slotPool
	disconnect    *slotPool
	tunnelsHeader *systray.MenuItem
	tunnelsShown  bool // guards tunnelsHeader.Hide(); see hideTunnelsHeader
	tunnels       *slotPool
	browserHeader *systray.MenuItem
	browserShown  bool // guards browserHeader.Hide(); see hideBrowserHeader
	browser       *slotPool
}

// hideTunnelsHeader hides tunnelsHeader only if it isn't already hidden.
// Unlike the pool-backed slots (dashboard, tunnels), tunnelsHeader has no
// acquire/release bookkeeping to make repeat Hide() calls a no-op, and
// render/clearProfileChildren call it on every tick regardless of current
// state. On Windows, Hide() removes the item from its parent's native menu
// by ID; calling it again once already removed logs a spurious systray
// error, so this tracks shown state explicitly instead.
func (s *profileSlot) hideTunnelsHeader() {
	if !s.tunnelsShown {
		return
	}
	s.tunnelsHeader.Hide()
	s.tunnelsShown = false
}

func (s *profileSlot) showTunnelsHeader() {
	s.tunnelsHeader.Show()
	s.tunnelsShown = true
}

// hideBrowserHeader/showBrowserHeader are hideTunnelsHeader/
// showTunnelsHeader's counterparts for browserHeader, guarding repeat
// Hide() calls for the same Windows-specific reason.
func (s *profileSlot) hideBrowserHeader() {
	if !s.browserShown {
		return
	}
	s.browserHeader.Hide()
	s.browserShown = false
}

func (s *profileSlot) showBrowserHeader() {
	s.browserHeader.Show()
	s.browserShown = true
}

// menu owns the tray's entire fixed structure and the live state needed to
// render it: the last snapshot's state per profile (so a click handler
// knows whether to connect or disconnect) and the aggregate icon
// currently shown (so redundant SetTemplateIcon calls -- each one a
// cross-thread call on macOS -- are skipped when nothing changed).
type menu struct {
	mgr          *manager.Manager
	openSettings func()

	profiles *slotPool // keyed by profile ID
	slots    [maxProfiles]profileSlot

	mu          sync.Mutex
	lastState   map[string]manager.State
	currentIcon icons.State
	iconSetOnce bool

	startAtLogin *systray.MenuItem
	quit         *systray.MenuItem
}

func newMenu(mgr *manager.Manager, openSettings func()) *menu {
	m := &menu{mgr: mgr, openSettings: openSettings, lastState: map[string]manager.State{}}

	profileItems := make([]Slot, maxProfiles)
	for i := range m.slots {
		// Build each item's full subtree before hiding anything, and hide
		// bottom-up (leaves, then containers, then the row itself). On
		// Windows, Hide() removes the item from its parent's native menu by
		// ID via RemoveMenu. If a child is then added to that now-removed
		// item, winTray.convertToSubMenu's SetMenuItemInfo call (which would
		// attach the child's menu to the parent's id) fails and returns
		// early without ever recording the parent's new submenu handle in
		// winTray.menus -- so every later call for that item (Hide, or
		// converting a grandchild) reads back a zero handle and fails with
		// "Invalid menu handle" (Windows error 1401). See
		// fyne.io/systray@v1.12.2/systray_windows.go's addOrUpdateMenuItem
		// and convertToSubMenu.
		item := systray.AddMenuItem("", "")

		dashboardItem := item.AddSubMenuItem("Open dashboard…", "Open this profile's local status page")
		connectItem := item.AddSubMenuItem("Connect", "Connect this profile")
		disconnectItem := item.AddSubMenuItem("Disconnect", "Disconnect this profile")

		tunnelsHeader := item.AddSubMenuItem("Tunnels", "")
		tunnelSlots := make([]Slot, maxTunnelsPerProfile)
		for j := 0; j < maxTunnelsPerProfile; j++ {
			row := tunnelsHeader.AddSubMenuItem("", "Click to copy the local address")
			row.Hide()
			tunnelSlots[j] = menuItemSlot{row}
		}
		tunnelsHeader.Hide()

		browserHeader := item.AddSubMenuItem("Open in browser", "")
		browserSlots := make([]Slot, maxTunnelsPerProfile)
		for j := 0; j < maxTunnelsPerProfile; j++ {
			row := browserHeader.AddSubMenuItem("", "Open a browser configured for this SOCKS tunnel")
			row.Hide()
			browserSlots[j] = menuItemSlot{row}
		}
		browserHeader.Hide()

		dashboardItem.Hide()
		connectItem.Hide()
		disconnectItem.Hide()

		m.slots[i] = profileSlot{
			item:          item,
			dashboard:     newSlotPool([]Slot{menuItemSlot{dashboardItem}}),
			connect:       newSlotPool([]Slot{menuItemSlot{connectItem}}),
			disconnect:    newSlotPool([]Slot{menuItemSlot{disconnectItem}}),
			tunnelsHeader: tunnelsHeader,
			tunnels:       newSlotPool(tunnelSlots),
			browserHeader: browserHeader,
			browser:       newSlotPool(browserSlots),
		}
		profileItems[i] = menuItemSlot{item}
		item.Hide()
	}
	m.profiles = newSlotPool(profileItems)

	systray.AddSeparator()
	settings := systray.AddMenuItem("Settings…", "Open the settings window")
	if openSettings != nil {
		go func() {
			for range settings.ClickedCh {
				openSettings()
			}
		}()
	} else {
		settings.Disable()
	}
	// The OS's own registration is the source of truth, not whatever
	// gui.yaml happens to say -- a user could have removed the login item
	// by hand outside this app. Sync gui.yaml to match on every launch
	// rather than trust a possibly-stale stored value -- but only when
	// Enabled() actually answered: if it errored, "couldn't tell" must not
	// get treated as "not enabled" and overwrite a true stored in
	// gui.yaml with a false the OS state doesn't actually confirm.
	enabled, enabledErr := autostart.Enabled()
	checkboxState := enabled
	if enabledErr != nil {
		checkboxState = mgr.Settings().StartAtLogin
	}
	m.startAtLogin = systray.AddMenuItemCheckbox("Start at login", "Launch ntwire-gui automatically", checkboxState)
	if enabledErr == nil {
		if settings := mgr.Settings(); settings.StartAtLogin != enabled {
			settings.StartAtLogin = enabled
			_ = mgr.SetSettings(settings)
		}
	}
	m.quit = systray.AddMenuItem("Quit", "Disconnect every profile and exit")

	go m.watchStartAtLogin()
	go m.watchQuit()

	return m
}

// render rebuilds the visible menu from the manager's current snapshots.
// It is safe to call repeatedly -- every item it touches belongs to the
// fixed pool created in newMenu, so this only shows, hides, relabels and
// rebinds click actions; nothing is ever added or removed after startup.
func (m *menu) render(snaps []manager.Snapshot) {
	keep := make(map[string]bool, len(snaps))
	m.mu.Lock()
	for _, s := range snaps {
		keep[s.Profile.ID] = true
		m.lastState[s.Profile.ID] = s.State
	}
	m.mu.Unlock()

	m.profiles.releaseAllExceptFunc(keep, m.clearProfileChildren)

	shown := 0
	for _, snap := range snaps {
		if shown >= maxProfiles {
			break // beyond the fixed pool; visible in the settings window only
		}
		m.renderProfile(snap)
		shown++
	}

	m.setIcon(aggregateState(snaps))
}

func (m *menu) renderProfile(snap manager.Snapshot) {
	slotIface, ok := m.profiles.acquire(snap.Profile.ID)
	if !ok {
		return // pool exhausted; see maxProfiles
	}
	item, ok := slotIface.(menuItemSlot)
	if !ok {
		return
	}
	slot := m.slotFor(item.item)
	if slot == nil {
		return
	}

	item.SetTitle(profileTitle(snap))
	item.Show()
	id := snap.Profile.ID
	m.profiles.setAction(id, func() { m.toggleConnect(id) })

	m.renderDashboardItem(slot, snap)
	m.renderConnectDisconnectItems(slot, snap)
	m.renderTunnels(slot, snap)
	m.renderBrowserTunnels(slot, snap)
}

// slotFor finds the profileSlot a given *systray.MenuItem belongs to. The
// pool only exposes the Slot interface (so its own tests need no systray
// dependency), so code that needs the concrete item's nested children
// looks it up here by identity instead.
func (m *menu) slotFor(item *systray.MenuItem) *profileSlot {
	for i := range m.slots {
		if m.slots[i].item == item {
			return &m.slots[i]
		}
	}
	return nil
}

// clearProfileChildren tears down a profile row's nested dashboard and
// tunnel entries just before the row itself is released for reuse by a
// different profile, so nothing stale lingers under a now-hidden parent.
func (m *menu) clearProfileChildren(id string) {
	slotIface, ok := m.profiles.acquire(id) // still bound; fetches, doesn't rebind
	if !ok {
		return
	}
	item, ok := slotIface.(menuItemSlot)
	if !ok {
		return
	}
	slot := m.slotFor(item.item)
	if slot == nil {
		return
	}
	slot.dashboard.release(dashboardSlotID)
	slot.connect.release(connectSlotID)
	slot.disconnect.release(disconnectSlotID)
	slot.tunnels.releaseAllExcept(nil)
	slot.hideTunnelsHeader()
	slot.browser.releaseAllExcept(nil)
	slot.hideBrowserHeader()
}

func (m *menu) renderDashboardItem(slot *profileSlot, snap manager.Snapshot) {
	if snap.State != manager.StateConnected && snap.State != manager.StateReconnecting {
		slot.dashboard.release(dashboardSlotID)
		return
	}
	s, ok := slot.dashboard.acquire(dashboardSlotID)
	if !ok {
		return
	}
	s.Show()
	id := snap.Profile.ID
	slot.dashboard.setAction(dashboardSlotID, func() {
		url, err := m.mgr.DashboardURL(id)
		if err == nil && url != "" {
			_ = browseropen.Open(portalDashboardURL(url))
		}
	})
}

func portalDashboardURL(url string) string { return url + "#portal" }

// renderConnectDisconnectItems shows exactly one of "Connect"/"Disconnect"
// per profile row, mirroring toggleConnect's own state reasoning: neither
// is shown mid-attempt (StateConnecting or an awaiting-prompt state), since
// Manager.Disconnect fails silently before a session reaches StateConnected
// and there is nothing for Connect to do while an attempt is already
// running.
func (m *menu) renderConnectDisconnectItems(slot *profileSlot, snap manager.Snapshot) {
	id := snap.Profile.ID
	switch snap.State {
	case manager.StateConnected, manager.StateReconnecting:
		slot.connect.release(connectSlotID)
		if s, ok := slot.disconnect.acquire(disconnectSlotID); ok {
			s.Show()
			slot.disconnect.setAction(disconnectSlotID, func() { _ = m.mgr.Disconnect(id) })
		}
	case manager.StateConnecting, manager.StateAwaitingTrust, manager.StateAwaitingPassphrase:
		slot.connect.release(connectSlotID)
		slot.disconnect.release(disconnectSlotID)
	default:
		slot.disconnect.release(disconnectSlotID)
		if s, ok := slot.connect.acquire(connectSlotID); ok {
			s.Show()
			slot.connect.setAction(connectSlotID, func() { _ = m.mgr.Connect(id) })
		}
	}
}

func (m *menu) renderTunnels(slot *profileSlot, snap manager.Snapshot) {
	var tunnels []client.ListenerState
	if snap.Connection != nil {
		tunnels = snap.Connection.Tunnels
	}
	if len(tunnels) > maxTunnelsPerProfile {
		tunnels = tunnels[:maxTunnelsPerProfile]
	}

	// Release stale rows before acquiring new ones -- the same order
	// render() uses for profiles, and for the same reason: acquiring
	// first can spuriously fail to seat a new tunnel name while the slot
	// it needs is still held by a departing one, and that failure would
	// otherwise persist until some later render happens to retry it.
	tunnelKeep := make(map[string]bool, len(tunnels))
	for _, t := range tunnels {
		tunnelKeep[t.Name] = true
	}
	slot.tunnels.releaseAllExcept(tunnelKeep)

	if len(tunnels) == 0 {
		slot.hideTunnelsHeader()
		return
	}
	slot.showTunnelsHeader()
	for _, t := range tunnels {
		row, ok := slot.tunnels.acquire(t.Name)
		if !ok {
			continue
		}
		row.SetTitle(fmt.Sprintf("%s → %s", t.Name, t.LocalAddress))
		row.Show()
		addr := t.LocalAddress
		slot.tunnels.setAction(t.Name, func() { _ = copyToClipboard(addr) })
	}
}

// renderBrowserTunnels populates the "Open in browser" submenu with one row
// per SOCKS egress tunnel -- the tray's per-target counterpart to
// renderDashboardItem's per-profile "Open dashboard…" action, using
// manager.Manager.OpenBrowser instead of browseropen.Open directly since it
// needs to look the tunnel's current local address up by name first.
func (m *menu) renderBrowserTunnels(slot *profileSlot, snap manager.Snapshot) {
	var tunnels []client.ListenerState
	if snap.Connection != nil {
		for _, t := range snap.Connection.Tunnels {
			if protocol.IsBrowserSocksTarget(t.TargetHint) {
				tunnels = append(tunnels, t)
			}
		}
	}
	if len(tunnels) > maxTunnelsPerProfile {
		tunnels = tunnels[:maxTunnelsPerProfile]
	}

	tunnelKeep := make(map[string]bool, len(tunnels))
	for _, t := range tunnels {
		tunnelKeep[t.Name] = true
	}
	slot.browser.releaseAllExcept(tunnelKeep)

	if len(tunnels) == 0 {
		slot.hideBrowserHeader()
		return
	}
	slot.showBrowserHeader()
	id := snap.Profile.ID
	for _, t := range tunnels {
		row, ok := slot.browser.acquire(t.Name)
		if !ok {
			continue
		}
		row.SetTitle("Open browser: " + t.Name)
		row.Show()
		name := t.Name
		slot.browser.setAction(t.Name, func() { _ = m.mgr.OpenBrowser(id, name) })
	}
}

func (m *menu) toggleConnect(id string) {
	m.mu.Lock()
	state := m.lastState[id]
	m.mu.Unlock()
	switch state {
	case manager.StateConnected, manager.StateReconnecting:
		_ = m.mgr.Disconnect(id)
	case manager.StateConnecting, manager.StateAwaitingTrust, manager.StateAwaitingPassphrase:
		// Nothing to toggle mid-attempt -- calling Disconnect here would
		// just fail silently, since s.handle is nil until the attempt
		// reaches StateConnected (see manager.Manager.Disconnect). The one
		// actionable thing is whatever prompt might be waiting, and only
		// the settings window can render and answer it.
		if m.openSettings != nil {
			m.openSettings()
		}
	default:
		_ = m.mgr.Connect(id)
	}
}

func (m *menu) setIcon(s icons.State) {
	m.mu.Lock()
	if m.iconSetOnce && m.currentIcon == s {
		m.mu.Unlock()
		return
	}
	m.currentIcon = s
	m.iconSetOnce = true
	m.mu.Unlock()
	systray.SetTemplateIcon(icons.TemplatePNG(s), pickRegularIcon(s))
}

// watchStartAtLogin reflects clicks into the real OS autostart
// registration, not just gui.yaml -- and, on failure, leaves both the
// checkbox and gui.yaml exactly as they were rather than recording a
// preference the OS doesn't actually have registered.
func (m *menu) watchStartAtLogin() {
	for range m.startAtLogin.ClickedCh {
		wantEnabled := !m.startAtLogin.Checked()

		var err error
		if wantEnabled {
			var self string
			if self, err = os.Executable(); err == nil {
				err = autostart.Enable(self, []string{"--autostart"})
			}
		} else {
			err = autostart.Disable()
		}
		if err != nil {
			continue
		}

		if wantEnabled {
			m.startAtLogin.Check()
		} else {
			m.startAtLogin.Uncheck()
		}
		settings := m.mgr.Settings()
		settings.StartAtLogin = wantEnabled
		_ = m.mgr.SetSettings(settings)
	}
}

func (m *menu) watchQuit() {
	<-m.quit.ClickedCh
	m.mgr.Close()
	systray.Quit()
}

func profileTitle(snap manager.Snapshot) string {
	switch snap.State {
	case manager.StateConnected:
		if snap.Connection != nil {
			return fmt.Sprintf("%s — connected · %dms", snap.Profile.Name, snap.Connection.LatencyMillis)
		}
		return snap.Profile.Name + " — connected"
	case manager.StateReconnecting:
		return snap.Profile.Name + " — reconnecting…"
	case manager.StateConnecting:
		return snap.Profile.Name + " — connecting…"
	case manager.StateAwaitingTrust:
		return snap.Profile.Name + " — needs trust decision"
	case manager.StateAwaitingPassphrase:
		return snap.Profile.Name + " — needs passphrase"
	case manager.StateFailed:
		return snap.Profile.Name + " — failed: " + snap.Err
	default:
		return snap.Profile.Name + " — disconnected"
	}
}
