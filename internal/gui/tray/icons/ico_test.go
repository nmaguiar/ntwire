package icons

import (
	"encoding/binary"
	"image"
	"image/color"
	"testing"
)

// parseICOForTest is an independent, from-scratch ICO reader (deliberately
// not reusing encodeICO's own field layout) so the encoder tests actually
// exercise the on-disk format rather than round-tripping through the same
// assumptions twice.
func parseICOForTest(t *testing.T, b []byte) [][]byte {
	t.Helper()
	if len(b) < 6 {
		t.Fatalf("ico too short: %d bytes", len(b))
	}
	reserved := binary.LittleEndian.Uint16(b[0:2])
	imageType := binary.LittleEndian.Uint16(b[2:4])
	count := binary.LittleEndian.Uint16(b[4:6])
	if reserved != 0 {
		t.Fatalf("ICONDIR.reserved = %d, want 0", reserved)
	}
	if imageType != 1 {
		t.Fatalf("ICONDIR.type = %d, want 1 (icon)", imageType)
	}

	frames := make([][]byte, 0, count)
	for i := 0; i < int(count); i++ {
		entry := b[6+i*16 : 6+i*16+16]
		size := binary.LittleEndian.Uint32(entry[8:12])
		offset := binary.LittleEndian.Uint32(entry[12:16])
		if int(offset+size) > len(b) {
			t.Fatalf("entry %d: offset+size %d exceeds file length %d", i, offset+size, len(b))
		}
		frames = append(frames, b[offset:offset+size])
	}
	return frames
}

func TestEncodeICORejectsNothingSpecial(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	img.Set(0, 0, color.NRGBA{1, 2, 3, 255})
	b, err := encodeICO(img)
	if err != nil {
		t.Fatalf("encodeICO: %v", err)
	}
	frames := parseICOForTest(t, b)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
}

func TestEncodeICOMultipleFrames(t *testing.T) {
	a := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	b := image.NewNRGBA(image.Rect(0, 0, 8, 8))
	out, err := encodeICO(a, b)
	if err != nil {
		t.Fatalf("encodeICO: %v", err)
	}
	frames := parseICOForTest(t, out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
}
