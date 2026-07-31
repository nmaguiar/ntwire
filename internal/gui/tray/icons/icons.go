// Package icons renders ntwire-gui's four tray-icon states (all profiles
// connected, some connected, none connected, needs attention) as pixels,
// entirely in Go with no bundled asset files. That matters on macOS in
// particular: fyne.io/systray.SetTemplateIcon marks the image NSImage
// .template=true, and AppKit then discards its RGB channels entirely,
// tinting the shape from the alpha channel alone so it adapts to light/dark
// menubars. Four same-colored circles would be visually identical there --
// so the states are differentiated by shape (filled disc / half disc / ring
// / diamond), which survives that transform; color is only meaningful on
// the Windows/Linux fallback (SetTemplateIcon's regularIconBytes).
package icons

import (
	"bytes"
	"image"
	"image/png"
	"sync"
)

// State is one of the four aggregate states the tray icon can show.
type State int

const (
	// StateNone means no profile is connected (idle, disconnected, or
	// still connecting) and none needs attention.
	StateNone State = iota
	// StateSome means at least one profile is connected but not all of
	// them.
	StateSome
	// StateAll means every profile is connected.
	StateAll
	// StateError means at least one profile has failed or is blocked on a
	// trust or passphrase prompt. Takes priority over the other three.
	StateError
)

func (s State) String() string {
	switch s {
	case StateNone:
		return "none"
	case StateSome:
		return "some"
	case StateAll:
		return "all"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// canvas is the square pixel size every generated icon is rendered at. It
// is large enough to look sharp on a @2x menu-bar icon slot and small
// enough that generating it at startup is instant.
const canvas = 44

type rendered struct {
	templatePNG []byte
	regularPNG  []byte
	regularICO  []byte
}

var (
	cacheOnce sync.Once
	cache     map[State]rendered
)

func ensureCache() {
	cacheOnce.Do(func() {
		cache = make(map[State]rendered, 4)
		for _, s := range []State{StateNone, StateSome, StateAll, StateError} {
			img := renderShape(s, canvas)
			tmplImg := toTemplate(img)
			ico, err := encodeICO(img)
			if err != nil {
				// encoding an in-memory, just-generated image can only fail
				// on an I/O error, which bytes.Buffer never returns.
				panic("gui/tray/icons: encoding ico: " + err.Error())
			}
			cache[s] = rendered{
				templatePNG: encodePNG(tmplImg),
				regularPNG:  encodePNG(img),
				regularICO:  ico,
			}
		}
	})
}

// TemplatePNG returns the alpha-shaped, color-irrelevant PNG macOS uses via
// SetTemplateIcon's first argument.
func TemplatePNG(s State) []byte {
	ensureCache()
	return cache[s].templatePNG
}

// RegularPNG returns a colored PNG suitable for Linux (SetTemplateIcon's
// second argument on that platform; see systray_unix.go, which ignores the
// template bytes entirely and always calls SetIcon(regularIconBytes)).
func RegularPNG(s State) []byte {
	ensureCache()
	return cache[s].regularPNG
}

// RegularICO returns a colored Windows .ico suitable for
// SetTemplateIcon's second argument on that platform: Windows' LoadImage
// with IMAGE_ICON requires a genuine ICO container, not a raw PNG.
func RegularICO(s State) []byte {
	ensureCache()
	return cache[s].regularICO
}

func encodePNG(img image.Image) []byte {
	var buf bytes.Buffer
	// Encoding a freshly generated in-memory image cannot fail.
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
