//go:build !windows

package main

import "errors"

// autostartValue: there is no Windows login entry on this platform.
func autostartValue() string { return "" }

func cmdTray(args []string) error {
	return errors.New("the tray icon is only available on Windows; on macOS/Linux use: brew services start snisplit")
}
