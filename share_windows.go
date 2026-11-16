//go:build windows

package main

import (
	"fmt"
	"os"
	"strconv"
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

func firewallRemove() error {
	return netsh(fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, firewallRule))
}
