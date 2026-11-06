package main

import (
	"embed"
	"fmt"
	"os"
	"sort"
	"strings"
)

//go:embed lists/*.txt
var listFS embed.FS

// presets returns the names of the built-in lists.
func presets() []string {
	entries, _ := listFS.ReadDir("lists")
	var out []string
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(e.Name(), ".txt"))
	}
	sort.Strings(out)
	return out
}

// listFlag is a repeatable, comma-separated flag value.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

// loadAll merges built-in presets (comma-separated; "none" for none) with the
// given list files.
func loadAll(presetCSV string, files []string) ([]string, error) {
	var all []string
	for _, p := range strings.Split(presetCSV, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" || p == "none" {
			continue
		}
		data, err := listFS.ReadFile("lists/" + p + ".txt")
		if err != nil {
			return nil, fmt.Errorf("unknown preset %q (available: %s, none)", p, strings.Join(presets(), ", "))
		}
		all = append(all, parseNames(string(data))...)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		all = append(all, parseNames(string(data))...)
	}
	return dedupe(all), nil
}

func parseNames(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		line = strings.TrimPrefix(line, "*") // "*.example.com" == ".example.com"
		if line != "" {
			out = append(out, line)
		}
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// normalizeName turns user input like "https://Example.com:443/path" into "example.com".
func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

// exactNames drops ".suffix" entries, which the hosts file cannot express.
func exactNames(names []string) []string {
	var out []string
	for _, n := range names {
		if !strings.HasPrefix(n, ".") {
			out = append(out, n)
		}
	}
	return out
}
