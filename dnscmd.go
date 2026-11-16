package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// adapterDNS is one network adapter's DNS setting before "snisplit dns on",
// so "dns off" can put it back exactly.
type adapterDNS struct {
	Name string   `json:"name"`
	GUID string   `json:"guid"`
	V4   []string `json:"v4,omitempty"`   // static IPv4 servers; empty: from DHCP
	V6   []string `json:"v6,omitempty"`   // static IPv6 servers; empty: from DHCP
	Used []string `json:"used,omitempty"` // servers in use (static or DHCP), kept as a fallback

	// Windows 11 "DNS over HTTPS" settings of the adapter's servers. With one
	// set to "encrypted only", Windows skips 127.0.0.1, so they are put aside
	// while snisplit (which encrypts every lookup itself) is the DNS server.
	Doh []dohSetting `json:"doh,omitempty"`
}

type dohSetting struct {
	Key   string `json:"key"` // "Doh\8.8.8.8" or "Doh6\2001:..."
	Flags uint64 `json:"flags"`
	QWord bool   `json:"qword,omitempty"`
}

func dnsBackupPath() string { return filepath.Join(filepath.Dir(settingsPath()), "dns-backup.json") }

func loadDNSBackup(path string) []adapterDNS {
	var b []adapterDNS
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &b)
	}
	return b
}

func saveDNSBackup(path string, b []adapterDNS) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(b, "", "  ")
	return os.WriteFile(path, data, 0o644)
}

// isOurDNS reports whether s is snisplit's own DNS address.
func isOurDNS(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}

// dnsFallbacks lists the servers the computer used before, as "ip:53", for
// when no DoH server answers.
func dnsFallbacks(b []adapterDNS) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range b {
		for _, s := range a.Used {
			if isOurDNS(s) || net.ParseIP(s) == nil || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, net.JoinHostPort(s, "53"))
		}
	}
	return out[:min(3, len(out))]
}

func dnsStatsOf(d *dnsServer) *dnsStats {
	if d == nil {
		return nil
	}
	s := d.stats()
	return &s
}

// askLocalDNS checks that a DNS server answers on 127.0.0.1:53.
func askLocalDNS(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var err error
	for time.Now().Before(deadline) {
		var c net.Conn
		if c, err = net.DialTimeout("udp", "127.0.0.1:53", time.Second); err == nil {
			q := dnsQuery("example.com")
			rand.Read(q[:2])
			c.SetDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1500)
			var n int
			if _, err = c.Write(q); err == nil {
				if n, err = c.Read(buf); err == nil && (n < 12 || buf[0] != q[0] || buf[1] != q[1]) {
					err = errors.New("bad answer")
				}
			}
			c.Close()
			if err == nil {
				return nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return err
}

// asAdmin runs "snisplit <args>" with administrator rights: directly when
// this process has them, else through one UAC prompt. errPath receives the
// elevated process's error message.
func asAdmin(errPath string, run func() error, args ...string) error {
	if isElevated() {
		return run()
	}
	os.Remove(errPath)
	err := runElevatedWait(args...)
	if msg, rerr := os.ReadFile(errPath); rerr == nil && len(msg) > 0 {
		os.Remove(errPath)
		return errors.New(strings.TrimSpace(string(msg)))
	}
	return err
}

// writeErr records err for the process that asked for administrator rights.
func writeErr(path string, err error) error {
	if err != nil {
		os.WriteFile(path, []byte(err.Error()), 0o644)
	}
	return err
}

func startOrRestart() error {
	if _, err := getStatus(defaultPort); err != nil {
		return cmdStart(nil)
	}
	return restartIfRunning()
}

// cmdDNS turns "all apps" mode on or off: the computer's DNS points at
// snisplit, which answers over DoH, blocks ads for every app and sends sites
// blocked by name through its own listeners.
func cmdDNS(args []string) error {
	s := loadSettings()
	if len(args) == 0 || args[0] == "status" {
		fmt.Printf("dns mode: %s\n", onOff(s.DNS))
		if s.DNS {
			here, other := systemDNSStatus()
			if len(here) > 0 {
				fmt.Printf("  using snisplit: %s\n", strings.Join(here, ", "))
			}
			if len(other) > 0 {
				fmt.Printf("  NOT using snisplit: %s (run 'snisplit dns on' again)\n", strings.Join(other, ", "))
			}
		}
		fmt.Println("turn on with:  snisplit dns on    (every app, not just browsers: blocked sites open, ads blocked)")
		fmt.Println("turn off with: snisplit dns off")
		return nil
	}
	path := dnsBackupPath()
	errPath := path + ".err"
	switch args[0] {
	case "on":
		if runtime.GOOS != "windows" {
			return errors.New("dns mode is only available on Windows for now")
		}
		s.DNS = true
		if err := saveSettings(s); err != nil {
			return err
		}
		if err := startOrRestart(); err != nil {
			return err
		}
		if err := askLocalDNS(10 * time.Second); err != nil {
			s.DNS = false
			saveSettings(s)
			restartIfRunning()
			return fmt.Errorf("snisplit's DNS server did not start (%v); is another DNS program using port 53? See %s", err, logPath())
		}
		fmt.Println("Windows will ask for administrator rights to change the DNS setting...")
		if err := asAdmin(errPath, func() error { return applySystemDNS(path) }, "dns", "apply", path); err != nil {
			s.DNS = false
			saveSettings(s)
			restartIfRunning()
			return fmt.Errorf("could not change the DNS setting: %v", err)
		}
		reloadProxy()
		here, _ := systemDNSStatus()
		fmt.Printf("dns mode on (%s): every app now looks names up through snisplit.\n", strings.Join(here, ", "))
		fmt.Println("Sites blocked by name open in every app; with 'snisplit adblock on', ads are blocked in every app too.")
		fmt.Println("If snisplit stops, Windows falls back to your previous DNS server, so the internet keeps working.")
	case "off":
		if runtime.GOOS == "windows" {
			fmt.Println("Windows will ask for administrator rights to put the DNS setting back...")
			if err := asAdmin(errPath, func() error { return restoreSystemDNS(path) }, "dns", "restore", path); err != nil {
				return fmt.Errorf("could not put the DNS setting back: %v", err)
			}
		}
		s.DNS = false
		if err := saveSettings(s); err != nil {
			return err
		}
		restartIfRunning()
		fmt.Println("dns mode off: the DNS setting is back to what it was")
	case "apply": // internal: run as administrator by "dns on"
		if len(args) < 2 {
			return errors.New("usage: snisplit dns apply <backup file>")
		}
		return writeErr(args[1]+".err", applySystemDNS(args[1]))
	case "restore": // internal: run as administrator by "dns off"
		if len(args) < 2 {
			return errors.New("usage: snisplit dns restore <backup file>")
		}
		return writeErr(args[1]+".err", restoreSystemDNS(args[1]))
	default:
		return errors.New("usage: snisplit dns on|off")
	}
	return nil
}
