//go:build !windows

package main

// On macOS and Linux the firewall is usually off or asks by itself.
func hasFirewall() bool     { return false }
func firewallAllow() error  { return nil }
func firewallRemove() error { return nil }
