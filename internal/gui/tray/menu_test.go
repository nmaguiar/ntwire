package tray

import "testing"

func TestPortalDashboardURL(t *testing.T) {
	if got, want := portalDashboardURL("http://127.0.0.1:4321/?token=test"), "http://127.0.0.1:4321/?token=test#portal"; got != want {
		t.Errorf("portalDashboardURL() = %q, want %q", got, want)
	}
}
