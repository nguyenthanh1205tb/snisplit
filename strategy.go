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

	// For sites blocked by address: networks in other countries to ask DNS
	// as (EDNS client subnet), and per CDN, sample host names and address
	// ranges of its servers.
	Regions []string            `json:"regions,omitempty"`
	Edges   map[string][]string `json:"edges,omitempty"`
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
	for _, r := range s.Regions {
		if _, n, err := net.ParseCIDR(r); err != nil || n.IP.To4() == nil || maskBits(n) < 16 || maskBits(n) > 24 {
			return nil, fmt.Errorf("strategy: region %q must be an IPv4 network from /16 to /24", r)
		}
	}
	for cdn, entries := range s.Edges {
		if !cdnName(cdn) {
			return nil, fmt.Errorf("strategy: bad CDN name %q", cdn)
		}
		for _, e := range entries {
			if _, n, err := net.ParseCIDR(e); err == nil {
				if n.IP.To4() == nil || maskBits(n) < 8 {
					return nil, fmt.Errorf("strategy: %s range %q must be IPv4, /8 or smaller", cdn, e)
				}
			} else if !validName(e) || strings.HasPrefix(e, ".") {
				return nil, fmt.Errorf("strategy: %s entry %q is neither a host name nor a range", cdn, e)
			}
		}
	}
	return &s, nil
}

func cdnName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func maskBits(n *net.IPNet) int {
	b, _ := n.Mask.Size()
	return b
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
