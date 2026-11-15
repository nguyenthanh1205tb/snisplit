//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// grantLowPorts lets the snisplit binary listen on ports 443 and 80 without
// root on Linux. "sudo snisplit hosts install" calls it, so setup needs no
// separate setcap command. (macOS allows these ports already.)
func grantLowPorts() {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if out, err := exec.Command("setcap", "cap_net_bind_service=+ep", exe).CombinedOutput(); err != nil {
		fmt.Printf("note: could not let snisplit use ports 443/80 (%v %s); install libcap2-bin and run this again\n", err, out)
	}
}

// runElevatedWait runs snisplit with args as administrator. Elsewhere than
// Windows the user has to use sudo.
func runElevatedWait(args ...string) error {
	return fmt.Errorf("run it with sudo: sudo snisplit %s", strings.Join(args, " "))
}

func stopOtherCopies()          {}
func removeFromUserPath(string) {}
func deleteAfterExit(string)    {}
