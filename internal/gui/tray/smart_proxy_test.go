package tray

import (
	"testing"

	"github.com/nmaguiar/ntwire/internal/gui/manager"
)

func TestSmartProxyMenuLabels(t *testing.T) {
	for _, tc := range []struct {
		group  manager.SmartProxyGroupState
		title  string
		action string
	}{
		{manager.SmartProxyGroupState{Name: "default"}, "Smart Proxy · Inactive", "Activate"},
		{manager.SmartProxyGroupState{Name: "office", Enabled: true, Listening: true}, "Smart Proxy: office · Active", "Disconnect"},
		{manager.SmartProxyGroupState{Name: "office", Enabled: true}, "Smart Proxy: office · Unavailable", "Disconnect"},
	} {
		title, action := smartProxyMenuLabels(tc.group)
		if title != tc.title || action != tc.action {
			t.Errorf("%+v gave %q / %q, want %q / %q", tc.group, title, action, tc.title, tc.action)
		}
	}
}

func TestSelectedSmartProxyGroup(t *testing.T) {
	groups := []manager.SmartProxyGroupState{{Name: "default"}, {Name: "office", Enabled: true}}
	if got := selectedSmartProxyGroup(groups, "office"); got != groups[1] {
		t.Fatalf("selection = %+v", got)
	}
	if got := selectedSmartProxyGroup(groups, "removed"); got != groups[0] {
		t.Fatalf("fallback = %+v", got)
	}
	if got := selectedSmartProxyGroup(nil, "office"); got.Name != "" {
		t.Fatalf("disabled proxy still has a menu group: %+v", got)
	}
}
