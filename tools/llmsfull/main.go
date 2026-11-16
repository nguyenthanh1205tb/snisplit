// Command llmsfull writes docs/llms-full.txt, the README as plain Markdown
// for AI agents, with relative links made absolute so they work outside the
// repository. Run from the repository root after changing README.md:
//
//	go run ./tools/llmsfull
//
// A test fails when the two are out of step.
package main

import (
	"log"
	"os"
	"regexp"
	"strings"
)

const (
	blob = "https://github.com/nguyenthanh1205tb/snisplit/blob/main/"
	raw  = "https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/"
	repo = "https://github.com/nguyenthanh1205tb/snisplit"
)

const header = `<!-- Generated from README.md by "go run ./tools/llmsfull"; summary: https://nguyenthanh1205tb.github.io/snisplit/llms.txt -->

`

var (
	mdLink   = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	htmlAttr = regexp.MustCompile(`(href|src)="([^"]+)"`)
)

// absolute turns a link found in README.md into one that works anywhere.
func absolute(u string, image bool) string {
	switch {
	case strings.Contains(u, "://"), strings.HasPrefix(u, "mailto:"):
		return u
	case strings.HasPrefix(u, "#"):
		return repo + u
	case image:
		return raw + u
	}
	return blob + u
}

func build(readme string) string {
	out := mdLink.ReplaceAllStringFunc(readme, func(m string) string {
		u := mdLink.FindStringSubmatch(m)[1]
		return "](" + absolute(u, strings.HasSuffix(u, ".png")) + ")"
	})
	out = htmlAttr.ReplaceAllStringFunc(out, func(m string) string {
		p := htmlAttr.FindStringSubmatch(m)
		return p[1] + `="` + absolute(p[2], p[1] == "src") + `"`
	})
	return header + out
}

func main() {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		log.Fatal("run from the repository root: ", err)
	}
	if err := os.WriteFile("docs/llms-full.txt", []byte(build(string(readme))), 0o644); err != nil {
		log.Fatal(err)
	}
}
