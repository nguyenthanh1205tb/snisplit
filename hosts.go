package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// listBaseURL serves the newest built-in lists, so "hosts update" can pick up
// new Steam hostnames without a new release.
var listBaseURL = "https://raw.githubusercontent.com/" + repoSlug + "/main/lists/"

var nameRe = regexp.MustCompile(`^\.?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// validName accepts hostnames and ".domain" suffixes, nothing else.
func validName(n string) bool { return len(n) <= 253 && nameRe.MatchString(n) }

// fetchList downloads the latest version of a built-in list.
func fetchList(preset string) ([]string, error) {
	if !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(preset) {
		return nil, fmt.Errorf("invalid preset name %q", preset)
	}
	resp, err := httpGet(listBaseURL + preset + ".txt")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	names := parseNames(string(data))
	for _, n := range names {
		if !validName(n) {
			return nil, fmt.Errorf("the downloaded list contains an invalid entry %q", n)
		}
	}
	if len(exactNames(names)) == 0 {
		return nil, errors.New("the downloaded list is empty")
	}
	return names, nil
}

// listDiff compares a list with the list-managed (non-user) names in the
// hosts block.
func listDiff(list []string, hostsContent string) (added, removed []string) {
	have := map[string]bool{}
	for _, e := range parseBlock(hostsContent) {
		if !e.user {
			have[e.name] = true
		}
	}
	want := map[string]bool{}
	for _, n := range exactNames(list) {
		want[n] = true
		if !have[n] {
			added = append(added, n)
		}
	}
	for n := range have {
		if !want[n] {
			removed = append(removed, n)
		}
	}
	sort.Strings(removed)
	return added, removed
}

const (
	hostsBegin = "# BEGIN snisplit"
	hostsEnd   = "# END snisplit"
	userMark   = "# user" // names added with "snisplit hosts add"
)

type hostEntry struct {
	name string
	user bool // added by the user; kept when the list is reinstalled
}

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
// (or removed when entries is empty). Other lines are kept as-is.
func applyHostsBlock(content string, entries []hostEntry) string {
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
	if len(entries) > 0 {
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, hostsBegin)
		for _, e := range entries {
			line := "127.0.0.1 " + e.name
			if e.user {
				line += " " + userMark
			}
			out = append(out, line)
		}
		out = append(out, hostsEnd)
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, nl) + nl
}

// parseBlock returns the entries currently in the snisplit block.
func parseBlock(content string) []hostEntry {
	var entries []hostEntry
	in := false
	for _, l := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == hostsBegin:
			in = true
		case t == hostsEnd:
			in = false
		case in:
			comment := ""
			if i := strings.IndexByte(t, '#'); i >= 0 {
				comment, t = t[i:], t[:i]
			}
			if f := strings.Fields(t); len(f) >= 2 {
				for _, n := range f[1:] {
					entries = append(entries, hostEntry{n, strings.HasPrefix(comment, userMark)})
				}
			}
		}
	}
	return entries
}

func installedNames(content string) []string {
	var names []string
	for _, e := range parseBlock(content) {
		names = append(names, e.name)
	}
	return names
}

func userEntries(content string) []hostEntry {
	var out []hostEntry
	for _, e := range parseBlock(content) {
		if e.user {
			out = append(out, e)
		}
	}
	return out
}

// mergeEntries combines list names with entries to keep (user additions).
func mergeEntries(names []string, keep []hostEntry) []hostEntry {
	seen := map[string]bool{}
	var out []hostEntry
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, hostEntry{name: n})
		}
	}
	for _, e := range keep {
		if !seen[e.name] {
			seen[e.name] = true
			out = append(out, e)
		}
	}
	return out
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

const hostsUsage = `usage: snisplit hosts <command> [flags] [names]

  install          write the list(s) to the hosts file (keeps names you added)
  update [--check] download the newest list from GitHub and apply it
  add <name>...    add hostnames to the snisplit block
  del <name>...    remove hostnames from the snisplit block
  remove           remove the whole snisplit block
  show             print the names install would write

All but "show" need Administrator (Windows) or sudo.`

func cmdHosts(args []string) error {
	if len(args) == 0 {
		return errors.New(hostsUsage)
	}
	sub := args[0]
	fset := flag.NewFlagSet("hosts "+sub, flag.ExitOnError)
	preset := fset.String("preset", "steam", "built-in lists, comma-separated ("+strings.Join(presets(), ", ")+", none)")
	var lists listFlag
	fset.Var(&lists, "list", "extra list file, one hostname per line (repeatable)")
	file := fset.String("file", hostsPath(), "hosts file to edit")
	reset := fset.Bool("reset", false, "install: drop the names added with 'hosts add'")
	checkOnly := fset.Bool("check", false, "update: only show what would change")
	fset.Parse(args[1:])
	rest := fset.Args()

	readCur := func() (string, error) {
		b, err := os.ReadFile(*file)
		if err != nil {
			return "", permHint(err)
		}
		return string(b), nil
	}

	switch sub {
	case "show":
		names, err := loadAll(*preset, lists)
		if err != nil {
			return err
		}
		cur, _ := os.ReadFile(*file)
		entries := mergeEntries(exactNames(names), userEntries(string(cur)))
		for _, e := range entries {
			fmt.Println(e.name)
		}
		// summary on stderr so "snisplit hosts show > list.txt" gives a clean list
		fmt.Fprintf(os.Stderr, "\n%d names; %d currently installed in %s\n", len(entries), len(installedNames(string(cur))), *file)
		return nil

	case "install":
		names, err := loadAll(*preset, lists)
		if err != nil {
			return err
		}
		cur, err := readCur()
		if err != nil {
			return err
		}
		var keep []hostEntry
		if !*reset {
			keep = userEntries(cur)
		}
		entries := mergeEntries(exactNames(names), keep)
		if len(entries) == 0 {
			return errors.New("no hostnames to install (empty list); use 'snisplit hosts remove' to clear the block")
		}
		if err := writeHosts(*file, applyHostsBlock(cur, entries)); err != nil {
			return err
		}
		fmt.Printf("hosts: %d names now point to 127.0.0.1 (%d added by you) in %s\n", len(entries), len(keep), *file)
		fmt.Println("Keep the proxy running (snisplit start), otherwise these sites will not load.")
		return nil

	case "update":
		list, err := fetchList(*preset)
		if err != nil {
			return fmt.Errorf("cannot download the %s list: %v", *preset, err)
		}
		cur, err := readCur()
		if err != nil {
			return err
		}
		added, removed := listDiff(list, cur)
		if len(added) == 0 && len(removed) == 0 {
			fmt.Printf("the %s list is up to date (%d names)\n", *preset, len(exactNames(list)))
			return nil
		}
		for _, n := range added {
			fmt.Println("  + " + n)
		}
		for _, n := range removed {
			fmt.Println("  - " + n)
		}
		if *checkOnly {
			fmt.Printf("%d to add, %d to remove (run without --check to apply)\n", len(added), len(removed))
			return nil
		}
		entries := mergeEntries(exactNames(list), userEntries(cur))
		if err := writeHosts(*file, applyHostsBlock(cur, entries)); err != nil {
			return err
		}
		fmt.Printf("hosts updated: %d names (%d added, %d removed)\n", len(entries), len(added), len(removed))
		return nil

	case "add":
		if len(rest) == 0 {
			return errors.New("usage: snisplit hosts add <name>...")
		}
		cur, err := readCur()
		if err != nil {
			return err
		}
		entries := parseBlock(cur)
		have := map[string]bool{}
		for _, e := range entries {
			have[e.name] = true
		}
		var added []string
		for _, a := range rest {
			n := normalizeName(a)
			if n == "" || strings.ContainsAny(n, "* ") || strings.HasPrefix(n, ".") {
				return fmt.Errorf("%q: the hosts file needs exact hostnames (no wildcards)", a)
			}
			if !have[n] {
				have[n] = true
				entries = append(entries, hostEntry{n, true})
				added = append(added, n)
			}
		}
		if len(added) == 0 {
			fmt.Println("already in the hosts file:", strings.Join(rest, " "))
			return nil
		}
		if err := writeHosts(*file, applyHostsBlock(cur, entries)); err != nil {
			return err
		}
		fmt.Printf("added %s (%d names in total)\n", strings.Join(added, ", "), len(entries))
		return nil

	case "del":
		if len(rest) == 0 {
			return errors.New("usage: snisplit hosts del <name>...")
		}
		cur, err := readCur()
		if err != nil {
			return err
		}
		drop := map[string]bool{}
		for _, a := range rest {
			drop[normalizeName(a)] = true
		}
		var kept []hostEntry
		for _, e := range parseBlock(cur) {
			if !drop[e.name] {
				kept = append(kept, e)
			}
		}
		removed := len(parseBlock(cur)) - len(kept)
		if removed == 0 {
			fmt.Println("not in the hosts file:", strings.Join(rest, " "))
			return nil
		}
		if err := writeHosts(*file, applyHostsBlock(cur, kept)); err != nil {
			return err
		}
		fmt.Printf("removed %d name(s), %d left\n", removed, len(kept))
		return nil

	case "remove":
		cur, err := readCur()
		if err != nil {
			return err
		}
		if !strings.Contains(cur, hostsBegin) {
			fmt.Println("no snisplit entries in", *file)
			return nil
		}
		if err := writeHosts(*file, applyHostsBlock(cur, nil)); err != nil {
			return err
		}
		fmt.Println("snisplit entries removed from", *file)
		return nil
	}
	return fmt.Errorf("unknown hosts command %q\n\n%s", sub, hostsUsage)
}
