//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func grantLowPorts() {} // Windows lets any user listen on ports 443 and 80

// stopOtherCopies ends every other snisplit process (tray, supervisor, proxy).
func stopOtherCopies() {
	exec.Command("taskkill", "/F", "/FI", "IMAGENAME eq snisplit.exe", "/FI", fmt.Sprintf("PID ne %d", os.Getpid())).Run()
}

// removeFromUserPath drops dir from the user PATH (added by install.ps1).
func removeFromUserPath(dir string) {
	script := `$p = [Environment]::GetEnvironmentVariable('Path','User'); if ($p) {
  $n = ($p -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ne $env:SNISPLIT_DIR.TrimEnd('\') }) -join ';'
  if ($n -ne $p) { [Environment]::SetEnvironmentVariable('Path', $n, 'User') } }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "SNISPLIT_DIR="+dir)
	cmd.SysProcAttr = detachAttr()
	cmd.Run()
}

// deleteAfterExit removes dir a moment after this process has exited (a
// running .exe cannot delete itself).
func deleteAfterExit(dir string) {
	cmd := exec.Command("cmd.exe", "/c", "ping -n 3 127.0.0.1 >nul & rmdir /s /q \""+dir+"\"")
	cmd.SysProcAttr = detachAttr()
	cmd.Start()
}

// runElevatedWait runs snisplit with args as administrator (one UAC prompt)
// and waits for it to finish.
func runElevatedWait(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
	}
	script := `$p = Start-Process -FilePath $env:SNISPLIT_EXE -ArgumentList ` + strings.Join(quoted, ",") +
		` -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "SNISPLIT_EXE="+exe)
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "canceled by the user") {
			return fmt.Errorf("administrator rights were refused")
		}
		return fmt.Errorf("%v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
