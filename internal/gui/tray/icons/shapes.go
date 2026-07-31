package icons

import (
	"image"
	"image/color"
	"math"
)

// stateColor is only used for the Windows/Linux "regular" variant --
// macOS's template variant (toTemplate) discards it entirely.
func stateColor(s State) color.NRGBA {
	switch s {
	case StateAll:
		return color.NRGBA{0x2e, 0xa0, 0x43, 0xff} // green: fully connected
	case StateSome:
		return color.NRGBA{0xd9, 0x9a, 0x1b, 0xff} // amber: partially connected
	case StateError:
		return color.NRGBA{0xd6, 0x33, 0x2f, 0xff} // red: needs attention
	default: // StateNone
		return color.NRGBA{0x6b, 0x6b, 0x6b, 0xff} // gray: idle
	}
}

// renderShape draws one of four shapes, chosen so each is distinguishable
// by silhouette alone (not color): a filled disc (StateAll), a disc filled
// only on its right half (StateSome), a ring (StateNone), and a diamond
// (StateError). That distinction is what makes the template-icon variant
// (see toTemplate) legible once macOS strips its color.
func renderShape(s State, size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	fg := stateColor(s)
	cx, cy := float64(size)/2, float64(size)/2
	r := float64(size)/2 - 2 // small margin so the shape isn't clipped

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			a := shapeAlpha(s, float64(x)+0.5, float64(y)+0.5, cx, cy, r)
			if a <= 0 {
				continue
			}
			c := fg
			c.A = uint8(float64(c.A) * a)
			img.SetNRGBA(x, y, c)
		}
	}
	return img
}

// shapeAlpha returns the coverage (0..1) of the given state's shape at
// pixel center (x, y), with a ~1px antialiased edge.
func shapeAlpha(s State, x, y, cx, cy, r float64) float64 {
	dx, dy := x-cx, y-cy
	dist := math.Hypot(dx, dy)

	switch s {
	case StateAll:
		return edgeCoverage(r - dist)
	case StateSome:
		if dx < 0 {
			return 0
		}
		return edgeCoverage(r - dist)
	case StateNone:
		const stroke = 6.0
		outer := edgeCoverage(r - dist)
		inner := edgeCoverage((r - stroke) - dist)
		a := outer - inner
		if a < 0 {
			return 0
		}
		return a
	case StateError:
		manhattan := math.Abs(dx) + math.Abs(dy)
		return edgeCoverage(r - manhattan)
	default:
		return 0
	}
}

// edgeCoverage turns a signed distance-inside-the-shape (positive means
// inside) into an antialiased coverage value over a 1px band at the edge.
func edgeCoverage(insideBy float64) float64 {
	if insideBy >= 1 {
		return 1
	}
	if insideBy <= 0 {
		return 0
	}
	return insideBy
}

// toTemplate keeps a rendered shape's alpha channel but forces its color to
// black, matching what a macOS template image effectively becomes once
// AppKit applies its own tint (SetTemplateIcon's first argument, per
// systray_darwin.go / systray_darwin.m: image.template = true).
func toTemplate(img *image.NRGBA) *image.NRGBA {
	b := img.Bounds()
	out := image.NewNRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			a := img.NRGBAAt(x, y).A
			if a == 0 {
				continue
			}
			out.SetNRGBA(x, y, color.NRGBA{0, 0, 0, a})
		}
	}
	return out
}
