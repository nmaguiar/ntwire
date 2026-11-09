package manager

import (
	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/pkg/browseropen"
	"github.com/nmaguiar/ntwire/pkg/client"
	"reflect"
	"testing"
	"time"
)

func TestBrowserArgsSavedChangesWhileConnected(t *testing.T) {
	old := openSocksWithOptions
	t.Cleanup(func() { openSocksWithOptions = old })
	var launched browseropen.LaunchOptions
	openSocksWithOptions = func(o browseropen.LaunchOptions, key, addr string, urls ...string) error { launched = o; return nil }
	captured := make(chan client.Options, 1)
	fc := &fakeConnector{connectFunc: func(server, key string, opts client.Options) (Handle, error) {
		captured <- opts
		return &fakeHandle{state: client.ConnectionState{Connected: true, Tunnels: []client.ListenerState{{Name: "socks", LocalAddress: "127.0.0.1:1080", TargetHint: "socks"}}}}, nil
	}}
	m, path := newTestManager(t, fc)
	if err := m.SetSettings(config.Settings{BrowserArgs: []string{"--global"}}); err != nil {
		t.Fatal(err)
	}
	p, err := m.AddProfile(config.Profile{Name: "test", Server: "https://example.com", BrowserArgs: []string{"--local"}, BrowserArgsMode: "append"})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Connect(p.ID); err != nil {
		t.Fatal(err)
	}
	waitForState(t, m, p.ID, StateConnected, time.Second*5)
	opts := <-captured
	for _, mode := range []string{"inherit", "append", "replace"} {
		p.BrowserArgsMode = mode
		if err = m.UpdateProfile(p); err != nil {
			t.Fatal(err)
		}
		globals := []string{"--updated=a b"}
		if err = m.SetSettings(config.Settings{BrowserArgs: globals}); err != nil {
			t.Fatal(err)
		}
		globals[0] = "--mutated"
		got, err := opts.ResolveBrowserOptions()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"--updated=a b"}
		if mode == "append" {
			want = append(want, "--local")
		}
		if mode == "replace" {
			want = []string{"--local"}
		}
		if err = m.OpenBrowser(p.ID, "socks"); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(launched.ExtraArgs, want) {
			t.Fatalf("manager launched %q want %q", launched.ExtraArgs, want)
		}
		if !reflect.DeepEqual(got.ExtraArgs, want) {
			t.Fatalf("%s: %q want %q", mode, got.ExtraArgs, want)
		}
	}
	p.BrowserArgs = nil
	if err = m.UpdateProfile(p); err != nil {
		t.Fatal(err)
	}
	got, err := opts.ResolveBrowserOptions()
	if err != nil || len(got.ExtraArgs) != 0 {
		t.Fatalf("empty replace %+v %v", got, err)
	}
	cfg, err := config.Load(path)
	if err != nil || cfg.Profiles[0].BrowserArgsMode != "replace" {
		t.Fatalf("persisted %+v %v", cfg, err)
	}
	p.BrowserArgsMode = "bad"
	if m.UpdateProfile(p) == nil {
		t.Fatal("accepted bad mode")
	}
	p.BrowserArgsMode = "inherit"
	p.BrowserArgs = []string{"--proxy-server=x"}
	if m.UpdateProfile(p) == nil {
		t.Fatal("accepted hidden invalid arguments")
	}
	if m.SetSettings(config.Settings{BrowserArgs: []string{"--"}}) == nil {
		t.Fatal("accepted bad globals")
	}
}
