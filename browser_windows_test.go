//go:build windows

package main

import (
	"testing"
	"unsafe"
)

// The structs passed to WinINet must match the 64-bit Windows layout.
func TestPerConnLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("only 64-bit Windows is released")
	}
	if s := unsafe.Sizeof(perConnOption{}); s != 16 {
		t.Errorf("INTERNET_PER_CONN_OPTIONW size %d, want 16", s)
	}
	if s := unsafe.Sizeof(perConnList{}); s != 32 {
		t.Errorf("INTERNET_PER_CONN_OPTION_LISTW size %d, want 32", s)
	}
	var o perConnOption
	o.setDword(5)
	if o.dword() != 5 {
		t.Error("dword round trip")
	}
}

// Reading the current settings must work (it changes nothing).
func TestProxySettingsReadable(t *testing.T) {
	flags, _, err := proxySettings()
	if err != nil || flags&proxyTypeDirect == 0 && flags == 0 {
		t.Fatalf("flags %#x, err %v", flags, err)
	}
}
