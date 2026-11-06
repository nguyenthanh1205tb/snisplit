package logo

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"testing"
)

func TestICOStructure(t *testing.T) {
	sizes := []int{16, 32, 256}
	ico := ICO(Running, 24, sizes...)
	if binary.LittleEndian.Uint16(ico[2:]) != 1 || int(binary.LittleEndian.Uint16(ico[4:])) != len(sizes) {
		t.Fatalf("bad header % x", ico[:6])
	}
	for i, n := range sizes {
		e := ico[6+16*i:]
		dim := int(e[0])
		if dim == 0 {
			dim = 256
		}
		size, off := binary.LittleEndian.Uint32(e[8:]), binary.LittleEndian.Uint32(e[12:])
		if dim != n || int(off+size) > len(ico) {
			t.Fatalf("entry %d: dim %d size %d off %d", i, dim, size, off)
		}
		img, err := png.Decode(bytes.NewReader(ico[off : off+size]))
		if err != nil || img.Bounds().Dx() != n || img.Bounds().Dy() != n {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
}

func at(img image.Image, u, v float64) (r, g, b, a uint32) {
	n := float64(img.Bounds().Dx())
	r, g, b, a = img.At(int(u*n), int(v*n)).RGBA()
	return r >> 8, g >> 8, b >> 8, a >> 8
}

func TestRenderShapes(t *testing.T) {
	img := Render(128, Running, false)
	if _, _, _, a := at(img, 0.005, 0.005); a != 0 {
		t.Error("corner should be transparent (rounded square)")
	}
	if r, g, b, a := at(img, 0.15, 0.5); a != 255 || !(g > r && b > r) {
		t.Errorf("background should be teal/blue, got %d,%d,%d,%d", r, g, b, a)
	}
	// left half of the bar is shifted down, right half up
	if r, g, b, _ := at(img, 0.30, 0.5+regular.shift); r < 250 || g < 250 || b < 250 {
		t.Errorf("left half of the bar should be white, got %d,%d,%d", r, g, b)
	}
	if r, g, b, _ := at(img, 0.72, 0.5-regular.shift); r < 250 || g < 250 || b < 250 {
		t.Errorf("right half of the bar should be white, got %d,%d,%d", r, g, b)
	}
	if r, _, _, _ := at(img, 0.5, 0.5); r > 200 {
		t.Error("centre should be the diagonal gap, not white")
	}
	// state colours differ
	stopped, failing := Render(32, Stopped, true), Render(32, Failing, true)
	if r, g, b, _ := at(stopped, 0.15, 0.5); max(r, g, b)-min(r, g, b) > 20 { // cool grey, low saturation
		t.Errorf("stopped should be grey, got %d,%d,%d", r, g, b)
	}
	if r, g, b, _ := at(failing, 0.15, 0.5); !(r > g && g > b) {
		t.Errorf("failing should be amber, got %d,%d,%d", r, g, b)
	}
}
