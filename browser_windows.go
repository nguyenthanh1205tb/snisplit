//go:build windows

package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The per-user proxy settings are changed through WinINet's per-connection
// options, the way the Windows Settings app does it. Writing only the
// AutoConfigURL registry value is not enough: the "Use setup script" switch
// lives in a binary blob (DefaultConnectionSettings) that Chrome and Edge
// follow, and only this API keeps the two in step.

const (
	optPerConnectionOption = 75 // INTERNET_OPTION_PER_CONNECTION_OPTION
	optSettingsChanged     = 39 // INTERNET_OPTION_SETTINGS_CHANGED
	optRefresh             = 37 // INTERNET_OPTION_REFRESH

	perConnFlags         = 1 // INTERNET_PER_CONN_FLAGS
	perConnAutoConfigURL = 4 // INTERNET_PER_CONN_AUTOCONFIG_URL

	proxyTypeDirect       = 0x1
	proxyTypeAutoProxyURL = 0x4
)

// perConnOption is INTERNET_PER_CONN_OPTIONW on 64-bit Windows (the only
// Windows builds released): a DWORD and an 8-byte union.
type perConnOption struct {
	option uint32
	value  *uint16 // a UTF-16 string, or (for flags) a DWORD stored in the same 8 bytes
}

func (o *perConnOption) dword() uint32     { return *(*uint32)(unsafe.Pointer(&o.value)) }
func (o *perConnOption) setDword(v uint32) { *(*uintptr)(unsafe.Pointer(&o.value)) = uintptr(v) }

// perConnList is INTERNET_PER_CONN_OPTION_LISTW.
type perConnList struct {
	size     uint32
	conn     *uint16 // nil: the LAN / default connection
	count    uint32
	errIndex uint32
	options  *perConnOption
}

var (
	wininet         = windows.NewLazySystemDLL("wininet.dll")
	procQueryOption = wininet.NewProc("InternetQueryOptionW")
	procSetOption   = wininet.NewProc("InternetSetOptionW")
	procGlobalFree  = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
)

// proxySettings returns the current flags and setup-script address.
func proxySettings() (flags uint32, pac string, err error) {
	opts := []perConnOption{{option: perConnFlags}, {option: perConnAutoConfigURL}}
	list := perConnList{count: uint32(len(opts)), options: &opts[0]}
	list.size = uint32(unsafe.Sizeof(list))
	size := list.size
	r, _, e := procQueryOption.Call(0, optPerConnectionOption, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return 0, "", fmt.Errorf("reading the proxy settings: %v", e)
	}
	flags = opts[0].dword()
	if p := opts[1].value; p != nil {
		pac = windows.UTF16PtrToString(p)
		procGlobalFree.Call(uintptr(unsafe.Pointer(p)))
	}
	return flags, pac, nil
}

func setProxySettings(flags uint32, pac string) error {
	pacPtr, err := windows.UTF16PtrFromString(pac)
	if err != nil {
		return err
	}
	opts := []perConnOption{{option: perConnFlags}, {option: perConnAutoConfigURL, value: pacPtr}}
	opts[0].setDword(flags)
	list := perConnList{count: uint32(len(opts)), options: &opts[0]}
	list.size = uint32(unsafe.Sizeof(list))
	r, _, e := procSetOption.Call(0, optPerConnectionOption, uintptr(unsafe.Pointer(&list)), uintptr(list.size))
	runtime.KeepAlive(opts)
	runtime.KeepAlive(pacPtr)
	if r == 0 {
		return fmt.Errorf("changing the proxy settings: %v", e)
	}
	procSetOption.Call(0, optSettingsChanged, 0, 0)
	procSetOption.Call(0, optRefresh, 0, 0)
	return nil
}

// systemPAC returns the setup-script address in use ("" if the switch is off).
func systemPAC() (string, error) {
	flags, pac, err := proxySettings()
	if err != nil {
		return "", err
	}
	if flags&proxyTypeAutoProxyURL == 0 {
		return "", nil
	}
	return pac, nil
}

// setSystemPAC turns "Use setup script" on with u, or off when u is "". The
// other switches (automatic detection, a manual proxy) are left as they are.
func setSystemPAC(u string) error {
	flags, _, err := proxySettings()
	if err != nil {
		return err
	}
	flags |= proxyTypeDirect
	if u == "" {
		flags &^= proxyTypeAutoProxyURL
	} else {
		flags |= proxyTypeAutoProxyURL
	}
	return setProxySettings(flags, u)
}
