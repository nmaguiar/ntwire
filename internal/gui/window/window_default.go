//go:build !gui

package window

import "github.com/nmaguiar/ntwire/pkg/browseropen"

// Run is the fallback used by every build that doesn't opt into the
// native webview (see window_gui.go's `gui` build tag): it just opens url
// in the default browser and returns immediately. There is no window to
// keep this process alive for, so unlike the gui-tagged Run, this one
// does not block -- the core process's Spawner still won't launch a
// second child while this one is running, briefly, but a plain browser
// tab needs no process of its own to stay open once opened.
func Run(url string) error {
	return browseropen.Open(url)
}
