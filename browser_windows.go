//go:build windows

package main

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

var inetKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// systemPAC returns the current "Use setup script" address ("" if none).
func systemPAC() (string, error) {
	cmd := exec.Command("reg", "query", inetKey, "/v", "AutoConfigURL")
	cmd.SysProcAttr = detachAttr()
	out, err := cmd.Output()
	if err != nil {
		return "", nil // value not present
	}
	return regValue(string(out)), nil
}

// setSystemPAC sets (or with "" removes) the per-user PAC address and tells
// running programs that the proxy settings changed.
func setSystemPAC(u string) error {
	var cmd *exec.Cmd
	if u == "" {
		cmd = exec.Command("reg", "delete", inetKey, "/v", "AutoConfigURL", "/f")
	} else {
		cmd = exec.Command("reg", "add", inetKey, "/v", "AutoConfigURL", "/t", "REG_SZ", "/d", u, "/f")
	}
	cmd.SysProcAttr = detachAttr()
	if out, err := cmd.CombinedOutput(); err != nil && u != "" {
		return fmt.Errorf("%v: %s", err, out)
	}
	set := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")
	if set.Find() == nil {
		const settingsChanged, refresh = 39, 37
		set.Call(0, settingsChanged, 0, 0)
		set.Call(0, refresh, 0, 0)
	}
	return nil
}
