package icons

import (
	"bytes"
	"image"
	"image/png"
	"testing"
)

func decodePNG(t *testing.T, b []byte) *image.NRGBA {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("decoding PNG: %v", err)
	}
	nrgba, ok := img.(*image.NRGBA)
	if !ok {
		// png.Decode may return a different concrete type depending on the
		// source pixel format; convert explicitly rather than assume.
		b := img.Bounds()
		out := image.NewNRGBA(b)
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				out.Set(x, y, img.At(x, y))
			}
		}
		return out
	}
	return nrgba
}

func TestTemplatePNGDecodesAndHasExpectedSize(t *testing.T) {
	for _, s := range []State{StateNone, StateSome, StateAll, StateError} {
		img := decodePNG(t, TemplatePNG(s))
		b := img.Bounds()
		if b.Dx() != canvas || b.Dy() != canvas {
			t.Errorf("state %s: got size %dx%d, want %dx%d", s, b.Dx(), b.Dy(), canvas, canvas)
		}
	}
}

func TestTemplatePNGIsColorless(t *testing.T) {
	// AppKit ignores RGB on a template image, so every opaque-ish pixel
	// must be pure black -- only alpha should vary.
	for _, s := range []State{StateNone, StateSome, StateAll, StateError} {
		img := decodePNG(t, TemplatePNG(s))
		b := img.Bounds()
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				c := img.NRGBAAt(x, y)
				if c.A == 0 {
					continue
				}
				if c.R != 0 || c.G != 0 || c.B != 0 {
					t.Fatalf("state %s: pixel (%d,%d) = %+v, want R=G=B=0", s, x, y, c)
				}
			}
		}
	}
}

func TestRegularPNGIsColored(t *testing.T) {
	for _, s := range []State{StateNone, StateSome, StateAll, StateError} {
		img := decodePNG(t, RegularPNG(s))
		want := stateColor(s)
		center := img.NRGBAAt(canvas/2, canvas/2)
		if s == StateNone {
			// StateNone is a ring: its center is hollow, so sample a point
			// on the stroke instead.
			center = img.NRGBAAt(canvas/2, 2)
		}
		if center.A == 0 {
			t.Fatalf("state %s: sample pixel is fully transparent", s)
		}
		if center.R != want.R || center.G != want.G || center.B != want.B {
			t.Errorf("state %s: sample pixel = %+v, want color %+v", s, center, want)
		}
	}
}

// TestShapesAreDistinguishableByAlphaAlone is the actual invariant this
// package exists to satisfy: on macOS, only the alpha channel survives
// (see toTemplate), so the four states must differ in shape, not color.
// Three probe points, chosen from the shapes' geometry (r = canvas/2-2 =
// 20, ring stroke = 6), separate all four:
//   - center: hollow only for the ring (StateNone)
//   - left-of-center, dist 10 (inside the ring's hollow inner circle,
//     dist < r-stroke): hollow only for the right-half disc (StateSome)
//   - (12,12) off-center, dist ~17 < r but manhattan 24 > r: hollow only
//     for the diamond (StateError)
func TestShapesAreDistinguishableByAlphaAlone(t *testing.T) {
	type probe struct{ x, y int }
	points := []probe{
		{canvas / 2, canvas / 2},       // center
		{canvas/2 - 10, canvas / 2},    // left of center, inside ring's hole
		{canvas/2 + 12, canvas/2 + 12}, // inside the circle, outside the diamond
	}

	signature := func(s State) [3]bool {
		img := decodePNG(t, TemplatePNG(s))
		var sig [3]bool
		for i, p := range points {
			sig[i] = img.NRGBAAt(p.x, p.y).A > 0
		}
		return sig
	}

	seen := map[[3]bool]State{}
	for _, s := range []State{StateNone, StateSome, StateAll, StateError} {
		sig := signature(s)
		if prev, ok := seen[sig]; ok {
			t.Fatalf("state %s has the same alpha signature %v as state %s -- indistinguishable once color is stripped", s, sig, prev)
		}
		seen[sig] = s
	}
}

func TestRegularICODecodesEachFrame(t *testing.T) {
	for _, s := range []State{StateNone, StateSome, StateAll, StateError} {
		b := RegularICO(s)
		frames := parseICOForTest(t, b)
		if len(frames) != 1 {
			t.Fatalf("state %s: got %d frames, want 1", s, len(frames))
		}
		if _, err := png.Decode(bytes.NewReader(frames[0])); err != nil {
			t.Errorf("state %s: embedded frame does not decode as PNG: %v", s, err)
		}
	}
}
