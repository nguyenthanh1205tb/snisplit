//go:build !windows

package main

import "errors"

func cmdTray(args []string) error {
	return errors.New("the tray icon is only available on Windows; on macOS/Linux use: brew services start snisplit")
}
