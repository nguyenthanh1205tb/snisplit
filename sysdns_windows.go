//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// adapterInfo is a connected network adapter (one with a default gateway).
type adapterInfo struct {
	Name string   // friendly name, as netsh and Settings show it
	GUID string   // "{...}"
	DNS  []string // servers in use
}

func activeAdapters() ([]adapterInfo, error) {
	size := uint32(16 << 10)
	for try := 0; try < 4; try++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []adapterInfo
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.FirstGatewayAddress == nil {
				continue
			}
			info := adapterInfo{Name: windows.UTF16PtrToString(a.FriendlyName), GUID: windows.BytePtrToString(a.AdapterName)}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip := d.Address.IP(); ip != nil {
					info.DNS = append(info.DNS, ip.String())
				}
			}
			out = append(out, info)
		}
		return out, nil
	}
	return nil, errors.New("network adapter list too large")
}

// staticServers returns the DNS servers typed into an adapter's settings
// (empty when they come from DHCP).
func staticServers(guid string, v6 bool) []string {
	stack := "Tcpip"
	if v6 {
		stack = "Tcpip6"
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+stack+`\Parameters\Interfaces\`+guid, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetStringValue("NameServer")
	if err != nil {
		return nil
	}
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })
}

func dohKeyPath(guid string) string {
	return `SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\` + guid + `\DohInterfaceSettings`
}

// readDoh returns the adapter's per-server DNS-over-HTTPS settings.
func readDoh(guid string) []dohSetting {
	var out []dohSetting
	for _, family := range []string{"Doh", "Doh6"} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, dohKeyPath(guid)+`\`+family, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, n := range names {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, dohKeyPath(guid)+`\`+family+`\`+n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			v, typ, err := sk.GetIntegerValue("DohFlags")
			sk.Close()
			if err == nil {
				out = append(out, dohSetting{Key: family + `\` + n, Flags: v, QWord: typ == registry.QWORD})
			}
		}
	}
	return out
}

// clearDoh removes the adapter's per-server DNS-over-HTTPS settings.
func clearDoh(guid string, list []dohSetting) {
	for _, d := range list {
		registry.DeleteKey(registry.LOCAL_MACHINE, dohKeyPath(guid)+`\`+d.Key)
	}
}

// restoreDoh puts saved per-server DNS-over-HTTPS settings back.
func restoreDoh(guid string, list []dohSetting) error {
	for _, d := range list {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, dohKeyPath(guid)+`\`+d.Key, registry.SET_VALUE)
		if err != nil {
			return err
		}
		if d.QWord {
			err = k.SetQWordValue("DohFlags", d.Flags)
		} else {
			err = k.SetDWordValue("DohFlags", uint32(d.Flags))
		}
		k.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func withoutOurs(list []string) []string {
	var out []string
	for _, s := range list {
		if !isOurDNS(s) {
			out = append(out, s)
		}
	}
	return out
}

// netsh runs netsh with a raw command line, so adapter names with spaces
// can be quoted the way netsh expects.
func netsh(args string) error {
	cmd := exec.Command("netsh")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "netsh " + args, HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %v %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func quoteName(n string) (string, error) {
	if strings.ContainsAny(n, "\"\r\n") {
		return "", fmt.Errorf("adapter name %q cannot be used", n)
	}
	return `"` + n + `"`, nil
}

// setServers sets an adapter's IPv4 or IPv6 DNS servers (none: from DHCP).
func setServers(name string, v6 bool, servers []string) error {
	q, err := quoteName(name)
	if err != nil {
		return err
	}
	family := "ipv4"
	if v6 {
		family = "ipv6"
	}
	if len(servers) == 0 {
		return netsh(fmt.Sprintf("interface %s set dnsservers name=%s source=dhcp", family, q))
	}
	if err := netsh(fmt.Sprintf("interface %s set dnsservers name=%s source=static address=%s register=primary validate=no", family, q, servers[0])); err != nil {
		return err
	}
	for i, s := range servers[1:] {
		if err := netsh(fmt.Sprintf("interface %s add dnsservers name=%s address=%s index=%d validate=no", family, q, s, i+2)); err != nil {
			return err
		}
	}
	return nil
}

// applySystemDNS points every connected adapter at snisplit (127.0.0.1, ::1),
// with the adapter's previous IPv4 server second as a fallback for when
// snisplit is not running. The previous settings are saved to path first.
func applySystemDNS(path string) error {
	adapters, err := activeAdapters()
	if err != nil {
		return err
	}
	if len(adapters) == 0 {
		return errors.New("no connected network adapter")
	}
	old := map[string]adapterDNS{}
	for _, b := range loadDNSBackup(path) {
		old[b.GUID] = b
	}
	var backup []adapterDNS
	for _, a := range adapters {
		b, ok := old[a.GUID]
		if !ok { // first time: remember what it was
			b = adapterDNS{GUID: a.GUID, V4: withoutOurs(staticServers(a.GUID, false)),
				V6: withoutOurs(staticServers(a.GUID, true)), Used: withoutOurs(a.DNS), Doh: readDoh(a.GUID)}
		}
		if len(b.Doh) == 0 { // saved by an earlier version, or set again since
			b.Doh = readDoh(a.GUID)
		}
		b.Name = a.Name
		backup = append(backup, b)
		delete(old, a.GUID)
	}
	for _, b := range old { // not connected now: keep, so "dns off" can still restore it
		backup = append(backup, b)
	}
	if err := saveDNSBackup(path, backup); err != nil {
		return err
	}
	var errs []string
	for _, b := range backup[:len(adapters)] {
		fallback := "1.1.1.1"
		for _, s := range append(append([]string(nil), b.V4...), b.Used...) {
			if ip := strings.TrimSpace(s); !isOurDNS(ip) && strings.Count(ip, ".") == 3 {
				fallback = ip
				break
			}
		}
		clearDoh(b.GUID, readDoh(b.GUID)) // "encrypted only" would make Windows skip 127.0.0.1
		if err := setServers(b.Name, false, []string{"127.0.0.1", fallback}); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		setServers(b.Name, true, []string{"::1"}) // fails harmlessly where IPv6 is off
	}
	exec.Command("ipconfig", "/flushdns").Run()
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// restoreSystemDNS puts back what applySystemDNS saved in path. Connected
// adapters still pointing at snisplit without a saved setting go back to DHCP.
func restoreSystemDNS(path string) error {
	backup := loadDNSBackup(path)
	saved := map[string]bool{}
	var errs []string
	for _, b := range backup {
		saved[b.GUID] = true
		if err := restoreDoh(b.GUID, b.Doh); err != nil {
			errs = append(errs, "DNS over HTTPS setting: "+err.Error())
		}
		if err := setServers(b.Name, false, b.V4); err != nil {
			errs = append(errs, err.Error())
		}
		setServers(b.Name, true, b.V6)
	}
	if adapters, err := activeAdapters(); err == nil {
		for _, a := range adapters {
			if !saved[a.GUID] && len(a.DNS) > 0 && isOurDNS(a.DNS[0]) {
				if err := setServers(a.Name, false, nil); err != nil {
					errs = append(errs, err.Error())
				}
				setServers(a.Name, true, nil)
			}
		}
	}
	exec.Command("ipconfig", "/flushdns").Run()
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	os.Remove(path)
	return nil
}

// systemDNSStatus lists the connected adapters that use snisplit for DNS and
// those that do not.
func systemDNSStatus() (here, other []string) {
	adapters, _ := activeAdapters()
	for _, a := range adapters {
		if len(a.DNS) > 0 && isOurDNS(a.DNS[0]) {
			here = append(here, a.Name)
		} else {
			other = append(other, a.Name)
		}
	}
	return here, other
}
