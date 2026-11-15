package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// A strategy says how to get around the ISP: the order "--mode auto" tries
// the split methods in, the pauses, which DoH servers to use and which hosts
// the health check probes. The built-in one can be replaced by a newer
// lists/strategy.json from GitHub, so a new way around a block reaches every
// user without a release.
type strategy struct {
	Version     int      `json:"version"`
	Modes       []string `json:"modes"`
	DelayMS     int      `json:"delay_ms"`
	SlowDelayMS int      `json:"slow_delay_ms"`
	DoH         []string `json:"doh"`
	Canary      []string `json:"canary"`
}

//go:embed lists/strategy.json
var builtinStrategy []byte

var strategyURL = func() string { return listBaseURL + "strategy.json" }

var strategyCachePath = func() string {
	return filepath.Join(filepath.Dir(logPath()), "strategy.json")
}

// parseStrategy decodes and checks a strategy file. Anything that could make
// things worse (unknown modes, DoH servers that need DNS, absurd pauses) is
// rejected rather than fixed up.
func parseStrategy(b []byte) (*strategy, error) {
	var s strategy
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Version < 1 {
		return nil, fmt.Errorf("strategy: missing version")
	}
	seen := map[string]bool{}
	for _, m := range s.Modes {
		if m == "none" || !validMode(m) || seen[m] {
			return nil, fmt.Errorf("strategy: bad mode %q", m)
		}
		seen[m] = true
	}
	if len(s.Modes) == 0 {
		return nil, fmt.Errorf("strategy: no modes")
	}
	if s.DelayMS < 0 || s.DelayMS > 1000 || s.SlowDelayMS < 0 || s.SlowDelayMS > 3000 {
		return nil, fmt.Errorf("strategy: delay out of range")
	}
	for _, d := range s.DoH {
		u, err := url.Parse(d)
		if err != nil || u.Scheme != "https" || net.ParseIP(u.Hostname()) == nil || u.RawQuery != "" {
			return nil, fmt.Errorf("strategy: DoH server %q must be an https URL with an IP address", d)
		}
	}
	for _, c := range s.Canary {
		if !validName(c) || strings.HasPrefix(c, ".") {
			return nil, fmt.Errorf("strategy: bad canary host %q", c)
		}
	}
	return &s, nil
}

// loadStrategy returns the cached download if it is valid and at least as new
// as the built-in strategy, else the built-in one.
func loadStrategy() *strategy {
	builtin, err := parseStrategy(builtinStrategy)
	if err != nil {
		panic("built-in strategy: " + err.Error())
	}
	if b, err := os.ReadFile(strategyCachePath()); err == nil {
		if s, err := parseStrategy(b); err == nil && s.Version >= builtin.Version {
			return s
		}
	}
	return builtin
}

// fetchStrategy downloads the strategy from GitHub. It returns the new
// strategy only when it is valid and newer than cur, and caches it.
func fetchStrategy(cur *strategy) (*strategy, error) {
	resp, err := httpGet(strategyURL())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", strategyURL(), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	s, err := parseStrategy(b)
	if err != nil {
		return nil, err
	}
	if s.Version <= cur.Version {
		return nil, nil
	}
	os.WriteFile(strategyCachePath(), b, 0o644)
	return s, nil
}
