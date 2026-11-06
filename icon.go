package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// makeIcon draws the tray icon - a filled circle cut by a diagonal gap, i.e.
// a "split" - in the given colour and returns it as a Windows .ico file
// (one 32x32 PNG image, supported since Windows Vista).
func makeIcon(c color.RGBA) []byte {
	const n = 32
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)-15.5, float64(y)-15.5
			edge := clamp01(15 - math.Hypot(dx, dy)) // anti-aliased rim
			if edge == 0 {
				continue
			}
			px := c
			if gap := math.Abs(dx+dy) / math.Sqrt2; gap < 2.2 { // the split
				px = mix(c, color.RGBA{255, 255, 255, 255}, clamp01(2.2-gap))
			}
			img.SetNRGBA(x, y, color.NRGBA{px.R, px.G, px.B, uint8(edge * 255)})
		}
	}
	var pngBuf bytes.Buffer
	png.Encode(&pngBuf, img)

	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, []uint16{0, 1, 1}) // reserved, type=icon, count
	ico.Write([]byte{n, n, 0, 0})                              // width, height, palette, reserved
	binary.Write(&ico, binary.LittleEndian, []uint16{1, 32})   // planes, bits per pixel
	binary.Write(&ico, binary.LittleEndian, []uint32{uint32(pngBuf.Len()), 22})
	ico.Write(pngBuf.Bytes())
	return ico.Bytes()
}

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }

func mix(a, b color.RGBA, t float64) color.RGBA {
	f := func(x, y uint8) uint8 { return uint8(float64(x)*(1-t) + float64(y)*t) }
	return color.RGBA{f(a.R, b.R), f(a.G, b.G), f(a.B, b.B), 255}
}

var (
	colorRunning = color.RGBA{0x2e, 0x9e, 0x5b, 255} // green
	colorStopped = color.RGBA{0x8a, 0x8a, 0x8a, 255} // grey
	colorFailing = color.RGBA{0xe0, 0x8e, 0x1b, 255} // amber: running, but connections fail
)
