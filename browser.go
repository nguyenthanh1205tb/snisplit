package main

import (
	"fmt"
	"strconv"
)

// browserPAC is the PAC file that sends every public site through snisplit.
func browserPAC() string {
	return "http://127.0.0.1:" + strconv.Itoa(defaultPort) + "/proxy.pac?all=1"
}

// cmdBrowser turns browser mode on or off: the system proxy settings point at
// snisplit's PAC file, so browsers send every site through snisplit, which
// splits only the connections that get reset and remembers those sites.
func cmdBrowser(args []string) error {
	s := loadSettings()
	if len(args) == 0 {
		cur, _ := systemPAC()
		fmt.Printf("browser mode: %s\n", onOff(s.Browser && cur == browserPAC()))
		fmt.Println("turn on with:  snisplit browser on    (browsers then reach any site that is blocked by name)")
		fmt.Println("turn off with: snisplit browser off")
		return nil
	}
	switch args[0] {
	case "on":
		cur, err := systemPAC()
		if err != nil {
			return err
		}
		if cur != browserPAC() {
			s.PrevPAC = cur
		}
		if err := setSystemPAC(browserPAC()); err != nil {
			return fmt.Errorf("%v\nSet the automatic proxy configuration URL by hand to %s", err, browserPAC())
		}
		s.Browser = true
		if err := saveSettings(s); err != nil {
			return err
		}
		fmt.Println("browser mode on: browsers now go through snisplit (restart the browser if it was open)")
		if _, err := getStatus(defaultPort); err != nil {
			return cmdStart(nil)
		}
	case "off":
		if err := setSystemPAC(s.PrevPAC); err != nil {
			return err
		}
		s.Browser, s.PrevPAC = false, ""
		if err := saveSettings(s); err != nil {
			return err
		}
		fmt.Println("browser mode off")
	default:
		return fmt.Errorf("usage: snisplit browser on|off")
	}
	return nil
}
