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

// loadNames reads a list from a file, or from a built-in preset.
func loadNames(preset, file string) ([]string, error) {
	var data []byte
	var err error
	if file != "" {
		data, err = os.ReadFile(file)
	} else {
		data, err = listFS.ReadFile("lists/" + preset + ".txt")
		if err != nil {
			return nil, fmt.Errorf("unknown preset %q (available: %s)", preset, strings.Join(presets(), ", "))
		}
	}
	if err != nil {
		return nil, err
	}
	return parseNames(string(data)), nil
}

func parseNames(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		line = strings.TrimPrefix(line, "*") // "*.example.com" == ".example.com"
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
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
