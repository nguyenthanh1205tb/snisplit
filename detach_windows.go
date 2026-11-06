//go:build windows

package main

import "syscall"

func detachAttr() *syscall.SysProcAttr {
	const (
		detachedProcess       = 0x00000008
		createNewProcessGroup = 0x00000200
	)
	return &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNewProcessGroup,
		HideWindow:    true,
	}
}
