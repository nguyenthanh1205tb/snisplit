// Package logo draws the snisplit logo: a rounded square with a colour
// gradient and a white bar cut diagonally into two offset halves - a data
// stream being split, which is what snisplit does to the TLS ClientHello.
//
// Everything is drawn from shapes at the requested size (supersampled), so
// small icons stay sharp instead of being scaled down from a large bitmap.
package logo

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// State selects the colour scheme.
type State int

const (
	Running State = iota // teal to blue
	Stopped              // grey
	Failing              // amber to orange
)

type rgb struct{ r, g, b float64 }

func hex(h uint32) rgb { return rgb{float64(h >> 16 & 255), float64(h >> 8 & 255), float64(h & 255)} }

var palettes = map[State][2]rgb{
	Running: {hex(0x14B8A6), hex(0x2563EB)},
	Stopped: {hex(0x9CA3AF), hex(0x6B7280)},
	Failing: {hex(0xF59E0B), hex(0xEA580C)},
}

// IconSizes are the image sizes put into .ico files.
var IconSizes = []int{16, 20, 24, 32, 40, 48, 64, 256}

// geometry of the mark, in units of the icon size
type geometry struct {
	box, barW, barH, gap, shift float64
}

var (
	regular = geometry{box: 0.47, barW: 0.29, barH: 0.105, gap: 0.035, shift: 0.055}
	compact = geometry{box: 0.50, barW: 0.36, barH: 0.15, gap: 0.05, shift: 0.06} // bigger mark for tiny icons
)

// sdRoundBox is the signed distance from (x,y) to a box centred at 0 with
// half-size (bx,by) and corner radius r.
func sdRoundBox(x, y, bx, by, r float64) float64 {
	qx, qy := math.Abs(x)-bx+r, math.Abs(y)-by+r
	return math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) + math.Min(math.Max(qx, qy), 0) - r
}

// shade returns the colour and coverage at unit coordinates (u,v).
func shade(u, v float64, pal [2]rgb, g geometry) (rgb, float64) {
	x, y := u-0.5, v-0.5
	if sdRoundBox(x, y, g.box, g.box, g.box*0.28) > 0 {
		return rgb{}, 0
	}
	t := (u + v) / 2
	bg := rgb{pal[0].r + (pal[1].r-pal[0].r)*t, pal[0].g + (pal[1].g-pal[0].g)*t, pal[0].b + (pal[1].b-pal[0].b)*t}
	s := x - 0.45*y // which side of the diagonal cut
	if math.Abs(s) < g.gap {
		return bg, 1
	}
	shift := g.shift
	if s > 0 {
		shift = -shift // right half moves up, left half moves down
	}
	if sdRoundBox(x, y-shift, g.barW, g.barH, g.barH) <= 0 {
		return rgb{255, 255, 255}, 1
	}
	return bg, 1
}

// Render draws the logo at n x n pixels. compactMark enlarges the mark, which
// reads better at tray-icon sizes.
func Render(n int, st State, compactMark bool) *image.NRGBA {
	const ss = 6 // supersampling per axis
	g := regular
	if compactMark {
		g = compact
	}
	pal := palettes[st]
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	for py := 0; py < n; py++ {
		for px := 0; px < n; px++ {
			var acc rgb
			var cover float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					u := (float64(px) + (float64(sx)+0.5)/ss) / float64(n)
					v := (float64(py) + (float64(sy)+0.5)/ss) / float64(n)
					c, a := shade(u, v, pal, g)
					acc.r += c.r * a
					acc.g += c.g * a
					acc.b += c.b * a
					cover += a
				}
			}
			if cover > 0 {
				img.SetNRGBA(px, py, color.NRGBA{
					uint8(math.Round(acc.r / cover)), uint8(math.Round(acc.g / cover)), uint8(math.Round(acc.b / cover)),
					uint8(math.Round(cover / ss / ss * 255)),
				})
			}
		}
	}
	return img
}

// PNG returns Render as PNG bytes.
func PNG(n int, st State, compactMark bool) []byte {
	var b bytes.Buffer
	png.Encode(&b, Render(n, st, compactMark))
	return b.Bytes()
}

// ICO returns a multi-size .ico (PNG-compressed entries). The compact mark is
// used for sizes up to compactUpTo.
func ICO(st State, compactUpTo int, sizes ...int) []byte {
	if len(sizes) == 0 {
		sizes = IconSizes
	}
	images := make([][]byte, len(sizes))
	for i, n := range sizes {
		images[i] = PNG(n, st, n <= compactUpTo)
	}
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, []uint16{0, 1, uint16(len(sizes))})
	offset := 6 + 16*len(sizes)
	for i, n := range sizes {
		dim := byte(n)
		if n >= 256 {
			dim = 0 // 0 means 256
		}
		out.Write([]byte{dim, dim, 0, 0})
		binary.Write(&out, binary.LittleEndian, []uint16{1, 32})
		binary.Write(&out, binary.LittleEndian, []uint32{uint32(len(images[i])), uint32(offset)})
		offset += len(images[i])
	}
	for _, img := range images {
		out.Write(img)
	}
	return out.Bytes()
}
