//go:build windows

package main

import (
	"os/exec"
	"testing"
)

// The PAC setting round-trips through the registry (a scratch key, not the
// real Internet Settings).
func TestSystemPACRoundTrip(t *testing.T) {
	old := inetKey
	inetKey = `HKCU\Software\snisplit-test`
	defer func() {
		exec.Command("reg", "delete", inetKey, "/f").Run()
		inetKey = old
	}()
	if v, _ := systemPAC(); v != "" {
		t.Fatalf("empty key reads %q", v)
	}
	if err := setSystemPAC(browserPAC()); err != nil {
		t.Fatal(err)
	}
	if v, _ := systemPAC(); v != browserPAC() {
		t.Fatalf("read back %q", v)
	}
	if err := setSystemPAC(""); err != nil {
		t.Fatal(err)
	}
	if v, _ := systemPAC(); v != "" {
		t.Fatalf("after removal %q", v)
	}
}
