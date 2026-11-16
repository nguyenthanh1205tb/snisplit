//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const firewallRule = "snisplit (share with phones)"

func hasFirewall() bool { return true }

// firewallAllow lets devices on the local network (and only those) reach
// snisplit's proxy port. Needs administrator rights.
func firewallAllow() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := quoteName(exe); err != nil {
		return err
	}
	netsh(fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, firewallRule)) // no duplicates
	return netsh(fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=in action=allow protocol=TCP localport=%s remoteip=localsubnet profile=any program="%s" enable=yes`,
		firewallRule, strconv.Itoa(defaultPort), exe))
}

// currentSSID is the Wi-Fi network this computer is on ("" on a cable).
func currentSSID() string {
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "SSID" { // not "BSSID"
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firewallRemove() error {
	return netsh(fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, firewallRule))
}
