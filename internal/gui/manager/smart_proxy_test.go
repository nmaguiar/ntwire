package manager

import (
	"net"
	"slices"
	"testing"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

func TestOpenSmartProxyGroupBrowser_PrefersHTTPWhenAvailable(t *testing.T) {
	original := openSmartProxyBrowser
	t.Cleanup(func() { openSmartProxyBrowser = original })
	var launchedProxy string
	var blockLocalDNS bool
	openSmartProxyBrowser = func(options browseropen.LaunchOptions, _, proxy string) error {
		launchedProxy = proxy
		blockLocalDNS = options.BlockLocalDNS
		return nil
	}

	m, _ := newTestManager(t, &fakeConnector{})
	t.Cleanup(m.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.SetSmartProxyEnabled(true); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		protocols []string
		scheme    string
		blockDNS  bool
	}{
		{"default protocols", nil, "http", false},
		{"both protocols", []string{"socks5", "http"}, "http", false},
		{"HTTP only with DNS blocking", []string{"http"}, "http", true},
		{"SOCKS5 only with DNS blocking", []string{"socks5"}, "socks5", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := egressrouter.Config{Enabled: true, Listen: address, Protocols: tc.protocols, BrowserBlockLocalDNS: tc.blockDNS}
			cfg := egressrouter.Config{Groups: map[string]egressrouter.Config{"office": group}}
			if err := m.SetSmartProxy(cfg); err != nil {
				t.Fatal(err)
			}
			launchedProxy = ""
			if err := m.OpenSmartProxyGroupBrowser("office"); err != nil {
				t.Fatal(err)
			}
			if want := tc.scheme + "://" + address; launchedProxy != want {
				t.Fatalf("launched with proxy %q, want %q", launchedProxy, want)
			}
			if blockLocalDNS != tc.blockDNS {
				t.Fatalf("launched with BlockLocalDNS = %t, want %t", blockLocalDNS, tc.blockDNS)
			}
		})
	}
}

func TestSmartProxyMasterControlsAllListenersAndPersists(t *testing.T) {
	m, path := newTestManager(t, &fakeConnector{})
	t.Cleanup(m.Close)
	ports := make([]net.Listener, 3)
	for i := range ports {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		ports[i] = ln
	}
	cfg := egressrouter.Config{Enabled: true, Listen: ports[0].Addr().String(),
		PACListen: ports[2].Addr().String(),
		Groups:    map[string]egressrouter.Config{"office": {Enabled: true, Listen: ports[1].Addr().String()}}}
	if err := m.SetSmartProxy(cfg); err != nil {
		t.Fatalf("master off should allow saving without binding: %v", err)
	}
	if err := m.SetSmartProxyEnabled(true); err == nil {
		t.Fatal("master activation should fail while addresses are occupied")
	}
	if got := m.SmartProxyGroups(); len(got) != 0 {
		t.Fatalf("failed activation exposed tray groups: %+v", got)
	}
	for _, ln := range ports {
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.SetSmartProxyEnabled(true); err != nil {
		t.Fatal(err)
	}
	if got := m.SmartProxyStatus(); !got.MasterEnabled || got.Listening != cfg.Listen ||
		got.Groups["office"].Listening != cfg.Groups["office"].Listen || got.PACListen != cfg.PACListen {
		t.Fatalf("unexpected master on state: %+v", got)
	}
	settings := m.Settings()
	settings.Notifications = !settings.Notifications
	if err := m.SetSettings(settings); err != nil {
		t.Fatal(err)
	}
	if stored, err := config.Load(path); err != nil || !stored.SmartProxyEnabled {
		t.Fatalf("master setting lost after saving other settings: %v", err)
	}
	if err := m.SetSmartProxyEnabled(false); err != nil {
		t.Fatal(err)
	}
	if got := m.SmartProxyStatus(); got.MasterEnabled || got.Listening != "" || got.PACListen != "" ||
		got.Groups["office"].Listening != "" || !got.Enabled || !got.Groups["office"].Enabled {
		t.Fatalf("master off must stop listening and preserve group choices: %+v", got)
	}
	if got := m.SmartProxyGroups(); len(got) != 0 {
		t.Fatalf("master off exposed tray groups: %+v", got)
	}
}

func TestSetSmartProxyGroupEnabled_PreservesOtherSettingsAndRollsBackOnBindError(t *testing.T) {
	m, path := newTestManager(t, &fakeConnector{})
	t.Cleanup(m.Close)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })
	cfg := egressrouter.Config{
		Listen: busy.Addr().String(),
		Groups: map[string]egressrouter.Config{"office": {Listen: "127.0.0.1:1081", Protocols: []string{"http"}}},
	}
	if err := m.SetSmartProxy(cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.SetSmartProxyEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := m.SetSmartProxyGroupEnabled("default", true); err == nil {
		t.Fatal("activation should fail on an occupied port")
	}
	if initial := m.SmartProxyGroups(); !slices.Equal(initial, []SmartProxyGroupState{{Name: "default"}, {Name: "office"}}) {
		t.Fatalf("activation failure changed group state: %+v", initial)
	}
	if err := busy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.SetSmartProxyGroupEnabled("default", true); err != nil {
		t.Fatal(err)
	}
	if got := m.SmartProxyGroups(); !slices.Equal(got, []SmartProxyGroupState{{Name: "default", Enabled: true, Listening: true}, {Name: "office"}}) {
		t.Fatalf("unexpected active state: %+v", got)
	}
	if err := m.SetSmartProxyGroupEnabled("missing", true); err == nil {
		t.Fatal("unexpected success activating a missing group")
	}
	stored, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.SmartProxy.Enabled || !slices.Equal(stored.SmartProxy.Groups["office"].Protocols, []string{"http"}) {
		t.Fatalf("unexpected saved settings: %+v", stored.SmartProxy)
	}
	if err := m.SetSmartProxyGroupEnabled("default", false); err != nil {
		t.Fatal(err)
	}
	if got := m.SmartProxyGroups(); got[0].Enabled || got[0].Listening {
		t.Fatalf("default group is still active: %+v", got)
	}
}
