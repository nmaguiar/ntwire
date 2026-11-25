//go:build gui

package window

import (
	"net/url"
	"time"

	webview "github.com/webview/webview_go"
)

// Run opens a native OS webview (WKWebView on macOS, WebView2 on Windows,
// WebKitGTK on Linux) at url and blocks until the user closes it.
//
// This file only builds with `go build -tags gui`. That is deliberate: it
// is what keeps the default, untagged `go build ./...` -- and so this
// repo's existing CI build/test jobs -- free of webview_go's cgo
// requirement. cmd/ntwire-gui's own CGO_ENABLED=0 cross-builds for linux
// and windows (see its package doc) only hold as long as nothing in the
// default build graph imports this file.
func Run(settingsURL string) error {
	w := webview.New(false)
	defer w.Destroy()
	type browserLaunch struct {
		timer   *time.Timer
		cleanup func()
	}
	var browserLaunches []browserLaunch
	defer func() {
		for _, launch := range browserLaunches {
			if launch.timer.Stop() {
				launch.cleanup()
			}
		}
	}()
	w.SetTitle("ntwire settings")
	w.SetSize(960, 720, webview.HintNone)
	launch := func(target string, err error) error {
		if err != nil {
			return err
		}
		cleanup, err := launchPrivateBrowser(target)
		if err != nil {
			return err
		}
		browserLaunches = append(browserLaunches, browserLaunch{time.AfterFunc(30*time.Second, cleanup), cleanup})
		return nil
	}
	if err := w.Bind("openSmartProxyDashboard", func(group string) error {
		return launch(smartProxyDashboardURL(settingsURL, group))
	}); err != nil {
		return err
	}
	if err := w.Bind("openSmartProxyExport", func() error {
		return launch(smartProxyBrowserURL(settingsURL, "/api/smart-proxy/export", url.Values{}))
	}); err != nil {
		return err
	}
	w.Navigate(settingsURL)
	w.Run()
	return nil
}
