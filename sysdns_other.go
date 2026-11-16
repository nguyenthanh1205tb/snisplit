//go:build !windows

package main

import (
	"errors"
	"os"
)

func isElevated() bool { return os.Geteuid() == 0 }

var errDNSWindowsOnly = errors.New("dns mode is only available on Windows for now")

func applySystemDNS(string) error   { return errDNSWindowsOnly }
func restoreSystemDNS(string) error { return errDNSWindowsOnly }

func systemDNSStatus() (here, other []string) { return nil, nil }
