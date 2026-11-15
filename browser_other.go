//go:build !windows

package main

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

// systemPAC returns the automatic proxy configuration URL ("" if none).
func systemPAC() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		svcs, err := macServices()
		if err != nil || len(svcs) == 0 {
			return "", err
		}
		out, err := exec.Command("networksetup", "-getautoproxyurl", svcs[0]).Output()
		if err != nil {
			return "", err
		}
		// "URL: http://...\nEnabled: Yes"
		var url string
		enabled := false
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(l, "URL: "); ok && v != "(null)" {
				url = strings.TrimSpace(v)
			}
			if strings.TrimSpace(l) == "Enabled: Yes" {
				enabled = true
			}
		}
		if !enabled {
			return "", nil
		}
		return url, nil
	case "linux":
		mode, err := exec.Command("gsettings", "get", "org.gnome.system.proxy", "mode").Output()
		if err != nil {
			return "", errors.New("only GNOME proxy settings are supported; set the PAC URL in your browser")
		}
		if strings.Trim(strings.TrimSpace(string(mode)), "'") != "auto" {
			return "", nil
		}
		out, err := exec.Command("gsettings", "get", "org.gnome.system.proxy", "autoconfig-url").Output()
		return strings.Trim(strings.TrimSpace(string(out)), "'"), err
	}
	return "", errors.New("not supported on " + runtime.GOOS)
}

func setSystemPAC(u string) error {
	switch runtime.GOOS {
	case "darwin":
		svcs, err := macServices()
		if err != nil {
			return err
		}
		for _, s := range svcs {
			if u == "" {
				exec.Command("networksetup", "-setautoproxystate", s, "off").Run()
				continue
			}
			if out, err := exec.Command("networksetup", "-setautoproxyurl", s, u).CombinedOutput(); err != nil {
				return errors.New(strings.TrimSpace(string(out)))
			}
		}
		return nil
	case "linux":
		if u == "" {
			return exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
		}
		if err := exec.Command("gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", u).Run(); err != nil {
			return errors.New("only GNOME proxy settings are supported")
		}
		return exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "auto").Run()
	}
	return errors.New("not supported on " + runtime.GOOS)
}

// macServices lists the enabled network services ("Wi-Fi", "Ethernet", ...).
func macServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	for _, l := range strings.Split(string(out), "\n")[1:] { // first line is a notice
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "*") {
			svcs = append(svcs, l)
		}
	}
	return svcs, nil
}
