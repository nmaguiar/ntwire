//go:build gui

package window

import (
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
func Run(url string) error {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("ntwire settings")
	w.SetSize(960, 720, webview.HintNone)
	w.Navigate(url)
	w.Run()
	return nil
}
