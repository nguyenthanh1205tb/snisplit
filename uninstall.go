package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// cmdUninstall undoes everything snisplit changed: browser mode, the login
// entry, the hosts file entries, its files and (for install.ps1 installs) the
// program itself and its PATH entry.
func cmdUninstall(args []string) error {
	s := loadSettings()
	if s.Browser {
		if err := cmdBrowser([]string{"off"}); err != nil {
			fmt.Println("browser mode:", err)
		}
	}
	cmdStop(nil)
	stopOtherCopies() // the tray icon, and a proxy started on another port
	if runtime.GOOS == "windows" {
		cmdAutostart([]string{"off"})
	}

	ok := true
	cur, _ := os.ReadFile(hostsPath())
	if len(installedNames(string(cur))) > 0 {
		if err := cmdHosts([]string{"remove"}); err != nil {
			if runtime.GOOS == "windows" {
				fmt.Println("Windows will ask for administrator rights to clean the hosts file...")
				err = runElevatedWait("hosts", "remove")
			}
			if err != nil {
				ok = false
				fmt.Println("hosts file:", err)
			} else {
				fmt.Println("hosts: snisplit entries removed")
			}
		}
	}

	for _, dir := range []string{filepath.Dir(logPath()), filepath.Dir(settingsPath())} {
		os.RemoveAll(dir) // log, learned sites, ad block list, settings
	}

	exe, _ := os.Executable()
	switch pm := packageManager(exe); {
	case pm == "Homebrew":
		fmt.Println("Last step: brew uninstall snisplit")
	case pm == "Scoop":
		fmt.Println("Last step: scoop uninstall snisplit")
	case runtime.GOOS == "windows" && strings.EqualFold(filepath.Base(filepath.Dir(exe)), "snisplit"):
		dir := filepath.Dir(exe)
		removeFromUserPath(dir)
		deleteAfterExit(dir)
		fmt.Println("removed", dir)
	default:
		fmt.Println("You can now delete", exe)
	}
	if !ok {
		return fmt.Errorf("the hosts file still has snisplit entries: run 'snisplit hosts remove' as administrator / with sudo")
	}
	fmt.Println("snisplit is uninstalled.")
	return nil
}
