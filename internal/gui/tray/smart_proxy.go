package tray

import (
	"log/slog"
	"slices"

	"fyne.io/systray"

	"github.com/nmaguiar/ntwire/internal/gui/manager"
)

const maxSmartProxyGroups = 17 // default plus 16 named groups

type smartProxySlot struct {
	menuItemSlot
	actions   *slotPool
	groupMenu *systray.MenuItem
	groups    *slotPool
}

func newSmartProxySlot() *smartProxySlot {
	parent := systray.AddMenuItem("Smart Proxy", "Manage Smart Proxy")
	dashboard := menuItemSlot{parent.AddSubMenuItem("Open dashboard…", "View traffic and tunnel status for this group")}
	toggle := menuItemSlot{parent.AddSubMenuItem("Activate", "Start or stop this Smart Proxy group")}
	groupMenu := parent.AddSubMenuItem("Group", "Choose which Smart Proxy group to manage")
	rows := make([]Slot, maxSmartProxyGroups)
	for i := range rows {
		rows[i] = menuItemSlot{groupMenu.AddSubMenuItemCheckbox("", "Switch the tray to this group", false)}
	}
	browser := menuItemSlot{parent.AddSubMenuItem("Open isolated browser…", "Browse through this Smart Proxy group")}
	for _, row := range rows {
		row.Hide()
	}
	groupMenu.Hide()
	for _, item := range []Slot{toggle, browser, dashboard} {
		item.Hide()
	}
	parent.Hide()
	return &smartProxySlot{menuItemSlot{parent}, newSlotPool([]Slot{dashboard, toggle, browser}), groupMenu, newSlotPool(rows)}
}

func selectedSmartProxyGroup(groups []manager.SmartProxyGroupState, name string) manager.SmartProxyGroupState {
	if i := slices.IndexFunc(groups, func(group manager.SmartProxyGroupState) bool { return group.Name == name }); i >= 0 {
		return groups[i]
	}
	if len(groups) == 0 {
		return manager.SmartProxyGroupState{}
	}
	return groups[0]
}

func smartGroupTitle(name string) string {
	if name == "default" {
		return "Default"
	}
	return name
}

func smartProxyMenuLabels(group manager.SmartProxyGroupState) (title, toggle string) {
	title = "Smart Proxy"
	if group.Name != "default" {
		title += ": " + group.Name
	}
	switch {
	case group.Listening:
		title += " · Active"
	case group.Enabled:
		title += " · Unavailable"
	default:
		title += " · Inactive"
	}
	if group.Enabled {
		return title, "Disconnect"
	}
	return title, "Activate"
}

func (m *menu) renderSmartProxy() {
	groups := m.mgr.SmartProxyGroups()
	m.mu.Lock()
	group := selectedSmartProxyGroup(groups, m.smartGroup)
	if group.Name != "" {
		m.smartGroup = group.Name
	}
	m.mu.Unlock()
	if slices.Equal(groups, m.lastSmart) && group.Name == m.lastSmartName {
		return
	}
	m.lastSmart, m.lastSmartName = groups, group.Name
	slot := m.smartProxy
	if len(groups) == 0 {
		slot.groups.releaseAllExcept(nil)
		slot.groupMenu.Hide()
		slot.actions.releaseAllExcept(nil)
		slot.Hide()
		return
	}

	title, toggle := smartProxyMenuLabels(group)
	slot.SetTitle(title)
	slot.Show()
	slot.showAction("dashboard", "Open dashboard…", m.openSmartDashboard != nil, func() {
		m.runSmartProxyAction(group.Name, "open dashboard", func() error {
			return m.openSmartDashboard(group.Name)
		})
	})
	slot.showAction("toggle", toggle, true, func() {
		m.runSmartProxyAction(group.Name, toggle, func() error {
			return m.mgr.SetSmartProxyGroupEnabled(group.Name, !group.Enabled)
		})
	})
	slot.groupMenu.SetTitle("Group: " + smartGroupTitle(group.Name))
	slot.groupMenu.Show()
	groupIDs := make(map[string]bool, len(groups))
	for _, choice := range groups {
		groupIDs[choice.Name] = true
	}
	slot.groups.releaseAllExcept(groupIDs)
	for _, choice := range groups {
		row, ok := slot.groups.acquire(choice.Name)
		if !ok {
			continue
		}
		item := row.(menuItemSlot).item
		item.SetTitle(smartGroupTitle(choice.Name))
		item.Show()
		if choice.Name == group.Name {
			item.Check()
		} else {
			item.Uncheck()
		}
		slot.groups.setAction(choice.Name, func() {
			m.mu.Lock()
			m.smartGroup = choice.Name
			m.mu.Unlock()
		})
	}
	slot.showAction("browser", "Open isolated browser…", group.Listening, func() {
		m.runSmartProxyAction(group.Name, "open browser", func() error {
			return m.mgr.OpenSmartProxyGroupBrowser(group.Name)
		})
	})
}

func (s *smartProxySlot) showAction(id, title string, enabled bool, action func()) {
	item, ok := s.actions.acquire(id)
	if !ok {
		return
	}
	item.SetTitle(title)
	item.Show()
	if enabled {
		s.actions.setAction(id, action)
		item.Enable()
	} else {
		s.actions.setAction(id, nil)
		item.Disable()
	}
}

func (m *menu) runSmartProxyAction(group, action string, run func() error) {
	if err := run(); err != nil {
		slog.Warn("Smart Proxy tray action failed", "group", group, "action", action, "error", err)
		if m.openSettings != nil {
			m.openSettings()
		}
	}
}
