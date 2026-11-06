package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const repoSlug = "nguyenthanh1205tb/snisplit"

type updateSource struct {
	apiLatest    string // GitHub "latest release" API URL
	downloadBase string // + "/<tag>/<asset>"
}

var githubSource = updateSource{
	apiLatest:    "https://api.github.com/repos/" + repoSlug + "/releases/latest",
	downloadBase: "https://github.com/" + repoSlug + "/releases/download",
}

func cmdUpdate(args []string) error {
	fset := flag.NewFlagSet("update", flag.ExitOnError)
	checkOnly := fset.Bool("check", false, "only report whether an update is available")
	fset.Parse(args)

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	tag, err := latestTag(githubSource)
	if err != nil {
		return fmt.Errorf("cannot check for updates: %v", err)
	}
	if tag == version {
		fmt.Printf("snisplit %s is the latest version\n", version)
		return nil
	}
	fmt.Printf("update available: %s -> %s\n", version, tag)
	if *checkOnly {
		return nil
	}
	if m := packageManager(exe); m != "" {
		fmt.Printf("snisplit was installed with %s; update it with:\n  %s\n", m, map[string]string{
			"Homebrew": "brew upgrade snisplit",
			"Scoop":    "scoop update snisplit",
		}[m])
		return nil
	}

	_, statusErr := getStatus(defaultPort)
	wasRunning := statusErr == nil
	if wasRunning {
		if err := cmdStop(nil); err != nil {
			return err
		}
	}
	if err := replaceBinary(githubSource, tag, exe); err != nil {
		if wasRunning {
			exec.Command(exe, "start").Run() // bring the old version back up
		}
		return err
	}
	fmt.Printf("updated %s -> %s (%s)\n", version, tag, exe)
	if wasRunning {
		cmd := exec.Command(exe, "start")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	return nil
}

func httpGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "snisplit/"+version)
	c := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return resp, nil
}

func latestTag(src updateSource) (string, error) {
	resp, err := httpGet(src.apiLatest)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", errors.New("no release found")
	}
	return rel.TagName, nil
}

func assetName(goos, goarch string) string {
	name := "snisplit_" + goos + "_" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// packageManager reports which package manager owns exe, if any.
func packageManager(exe string) string {
	p := strings.ToLower(filepath.ToSlash(exe))
	switch {
	case strings.Contains(p, "/cellar/") || strings.Contains(p, "/homebrew/") || strings.Contains(p, "/linuxbrew/"):
		return "Homebrew"
	case strings.Contains(p, "/scoop/apps/"):
		return "Scoop"
	}
	return ""
}

// checksumFor finds asset's SHA-256 in a sha256sum-style checksums file.
func checksumFor(sums, asset string) (string, bool) {
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

// replaceBinary downloads tag's binary for this platform, verifies it against
// checksums.txt and swaps it in for exe. A running exe cannot be overwritten on
// Windows, but it can be renamed, so the old file is moved to exe+".old".
func replaceBinary(src updateSource, tag, exe string) error {
	asset := assetName(runtime.GOOS, runtime.GOARCH)
	base := src.downloadBase + "/" + tag + "/"

	resp, err := httpGet(base + "checksums.txt")
	if err != nil {
		return err
	}
	sums, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return err
	}
	want, ok := checksumFor(string(sums), asset)
	if !ok {
		return fmt.Errorf("%s is not in the %s release", asset, tag)
	}

	resp, err = httpGet(base + asset)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return permHint(err)
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 200<<20))
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(tmp)
		return fmt.Errorf("checksum mismatch for %s (expected %s, got %s); nothing changed", asset, want, got)
	}

	old := exe + ".old"
	os.Remove(old) // left over from the previous update
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp)
		return permHint(err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe)
		os.Remove(tmp)
		return permHint(err)
	}
	if runtime.GOOS != "windows" {
		os.Remove(old) // on Unix the running process keeps its open file
	}
	return nil
}
