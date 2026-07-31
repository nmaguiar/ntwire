package icons

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
)

// encodeICO wraps PNG-encoded images in a minimal Windows ICO container
// (ICONDIR + one ICONDIRENTRY per image, followed by the raw PNG bytes).
// Since Windows Vista, an ICO directory entry may hold a full PNG image
// instead of a legacy BMP DIB, and GDI's LoadImage(..., IMAGE_ICON,
// LR_LOADFROMFILE) -- what fyne.io/systray's Windows backend calls in
// loadIconFrom -- accepts that form. This is the only route to a real .ico
// available without cgo or a bundled image converter.
func encodeICO(imgs ...*image.NRGBA) ([]byte, error) {
	pngs := make([][]byte, len(imgs))
	for i, img := range imgs {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return nil, err
		}
		pngs[i] = buf.Bytes()
	}

	var out bytes.Buffer
	writeU16 := func(v uint16) { binary.Write(&out, binary.LittleEndian, v) } //nolint:errcheck
	writeU32 := func(v uint32) { binary.Write(&out, binary.LittleEndian, v) } //nolint:errcheck

	// ICONDIR
	writeU16(0) // reserved, must be 0
	writeU16(1) // image type: 1 == icon
	writeU16(uint16(len(pngs)))

	offset := uint32(6 + 16*len(pngs)) // ICONDIR + ICONDIRENTRY table
	for i, img := range imgs {
		b := img.Bounds()
		w, h := b.Dx(), b.Dy()
		// A dimension of 256 or more is encoded as 0 (ICO's "256" sentinel).
		wByte, hByte := byte(w), byte(h)
		if w >= 256 {
			wByte = 0
		}
		if h >= 256 {
			hByte = 0
		}
		out.WriteByte(wByte)
		out.WriteByte(hByte)
		out.WriteByte(0) // color palette: none
		out.WriteByte(0) // reserved
		writeU16(1)      // color planes
		writeU16(32)     // bits per pixel
		writeU32(uint32(len(pngs[i])))
		writeU32(offset)
		offset += uint32(len(pngs[i]))
	}
	for _, p := range pngs {
		out.Write(p)
	}
	return out.Bytes(), nil
}
