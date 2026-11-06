package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	hostsBegin = "# BEGIN snisplit"
	hostsEnd   = "# END snisplit"
)

func hostsPath() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// applyHostsBlock returns content with the snisplit block replaced by entries
// for names (or removed when names is empty). Other lines are kept as-is.
func applyHostsBlock(content string, names []string) string {
	nl := "\n"
	if strings.Contains(content, "\r\n") || (content == "" && runtime.GOOS == "windows") {
		nl = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var out []string
	inBlock := false
	for _, l := range lines {
		switch strings.TrimSpace(l) {
		case hostsBegin:
			inBlock = true
			continue
		case hostsEnd:
			inBlock = false
			continue
		}
		if !inBlock {
			out = append(out, l)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	if len(names) > 0 {
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, hostsBegin)
		for _, n := range names {
			out = append(out, "127.0.0.1 "+n)
		}
		out = append(out, hostsEnd)
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, nl) + nl
}

// installedNames lists the names currently in the snisplit block.
func installedNames(content string) []string {
	var names []string
	in := false
	for _, l := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == hostsBegin:
			in = true
		case t == hostsEnd:
			in = false
		case in:
			if f := strings.Fields(t); len(f) >= 2 {
				names = append(names, f[1:]...)
			}
		}
	}
	return names
}

// writeHosts writes the file in place (keeping its owner and ACL), after
// saving a backup, and verifies the result; on a bad write it restores the backup.
func writeHosts(path, content string) error {
	orig, err := os.ReadFile(path)
	if err != nil {
		return permHint(err)
	}
	backup := path + ".snisplit.bak"
	if len(orig) > 0 {
		if err := os.WriteFile(backup, orig, 0o644); err != nil {
			return permHint(err)
		}
	}
	var werr error
	for i := 0; i < 10; i++ { // antivirus / DNS client may hold the file briefly
		if werr = os.WriteFile(path, []byte(content), 0o644); werr == nil {
			break
		}
		if errors.Is(werr, fs.ErrPermission) && i > 2 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	got, rerr := os.ReadFile(path)
	if werr != nil || rerr != nil || string(got) != content {
		if len(orig) > 0 {
			os.WriteFile(path, orig, 0o644)
		}
		if werr != nil {
			return permHint(werr)
		}
		return fmt.Errorf("hosts file verification failed; original restored from %s", backup)
	}
	flushDNS()
	return nil
}

func permHint(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		if runtime.GOOS == "windows" {
			return fmt.Errorf("%v\n  -> run this in a terminal opened as Administrator", err)
		}
		return fmt.Errorf("%v\n  -> run it with sudo", err)
	}
	return err
}

func flushDNS() {
	switch runtime.GOOS {
	case "windows":
		exec.Command("ipconfig", "/flushdns").Run()
	case "darwin":
		exec.Command("dscacheutil", "-flushcache").Run()
		exec.Command("killall", "-HUP", "mDNSResponder").Run()
	default:
		exec.Command("resolvectl", "flush-caches").Run()
	}
}

func cmdHosts(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: snisplit hosts install|remove|show [flags]")
	}
	sub := args[0]
	fset := flag.NewFlagSet("hosts "+sub, flag.ExitOnError)
	preset := fset.String("preset", "steam", "built-in list to use ("+strings.Join(presets(), ", ")+")")
	list := fset.String("list", "", "use this file instead of a preset (one hostname per line)")
	file := fset.String("file", hostsPath(), "hosts file to edit")
	fset.Parse(args[1:])

	switch sub {
	case "show":
		names, err := loadNames(*preset, *list)
		if err != nil {
			return err
		}
		for _, n := range exactNames(names) {
			fmt.Println(n)
		}
		cur, _ := os.ReadFile(*file)
		fmt.Printf("\n%d names; %d currently installed in %s\n", len(exactNames(names)), len(installedNames(string(cur))), *file)
		return nil
	case "install":
		names, err := loadNames(*preset, *list)
		if err != nil {
			return err
		}
		names = exactNames(names)
		cur, err := os.ReadFile(*file)
		if err != nil {
			return permHint(err)
		}
		if err := writeHosts(*file, applyHostsBlock(string(cur), names)); err != nil {
			return err
		}
		fmt.Printf("hosts: %d names now point to 127.0.0.1 (%s)\n", len(names), *file)
		fmt.Printf("backup: %s.snisplit.bak\n", *file)
		fmt.Println("Keep the proxy running (snisplit start), otherwise these sites will not load.")
		return nil
	case "remove":
		cur, err := os.ReadFile(*file)
		if err != nil {
			return permHint(err)
		}
		if len(installedNames(string(cur))) == 0 && !strings.Contains(string(cur), hostsBegin) {
			fmt.Println("no snisplit entries in", *file)
			return nil
		}
		if err := writeHosts(*file, applyHostsBlock(string(cur), nil)); err != nil {
			return err
		}
		fmt.Println("snisplit entries removed from", *file)
		return nil
	}
	return fmt.Errorf("unknown hosts command %q (install, remove, show)", sub)
}
