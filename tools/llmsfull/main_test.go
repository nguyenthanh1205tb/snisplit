package main

import (
	"os"
	"strings"
	"testing"
)

// The published llms-full.txt must match README.md.
func TestLLMsFullInStep(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../docs/llms-full.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != build(string(readme)) {
		t.Fatal("docs/llms-full.txt is out of date: run go run ./tools/llmsfull")
	}
}

func TestAbsolute(t *testing.T) {
	out := build(`[a](install.ps1) [b](#install) [c](https://x.example/) <a href="LICENSE"><img src="docs/logo.png">`)
	for _, want := range []string{
		"[a](" + blob + "install.ps1)", "[b](" + repo + "#install)", "[c](https://x.example/)",
		`href="` + blob + `LICENSE"`, `src="` + raw + `docs/logo.png"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}
