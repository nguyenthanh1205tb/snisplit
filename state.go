package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// state is what the proxy remembers between runs: the route that last worked
// for each host, the sites it found blocked on its own (browser mode), and the
// last good DNS answers, used when every resolver fails.
type state struct {
	path string

	mu      sync.Mutex
	dirty   bool
	Routes  map[string]route     `json:"routes"`
	Learned map[string]time.Time `json:"learned"`
	DNS     map[string]dnsEntry  `json:"dns"`
}

type route struct {
	IP   string    `json:"ip,omitempty"`
	Mode string    `json:"mode"` // a fragModes value, or "upstream"
	At   time.Time `json:"at"`
}

type dnsEntry struct {
	IPs []string  `json:"ips"`
	At  time.Time `json:"at"`
}

const maxStateHosts = 2000

func statePath() string {
	return filepath.Join(filepath.Dir(logPath()), "state.json")
}

// loadState reads path; a missing or broken file gives an empty state. An
// empty path keeps everything in memory (tests).
func loadState(path string) *state {
	s := &state{path: path}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			json.Unmarshal(b, s)
		}
	}
	if s.Routes == nil {
		s.Routes = map[string]route{}
	}
	if s.Learned == nil {
		s.Learned = map[string]time.Time{}
	}
	if s.DNS == nil {
		s.DNS = map[string]dnsEntry{}
	}
	return s
}

func (s *state) route(host string) (route, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.Routes[host]
	return r, ok
}

func (s *state) setRoute(host, ip, mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.Routes[host]; ok && r.IP == ip && r.Mode == mode && time.Since(r.At) < time.Hour {
		return
	}
	s.Routes[host] = route{IP: ip, Mode: mode, At: time.Now()}
	s.dirty = true
}

func (s *state) forgetRoute(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Routes[host]; ok {
		delete(s.Routes, host)
		s.dirty = true
	}
}

func (s *state) learn(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Learned[host]; !ok {
		s.Learned[host] = time.Now()
		s.dirty = true
	}
}

func (s *state) isLearned(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Learned[host]
	return ok
}

// learnedNames returns the learned hosts, newest first.
func (s *state) learnedNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for h := range s.Learned {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return s.Learned[out[i]].After(s.Learned[out[j]]) })
	return out
}

func (s *state) saveDNS(host string, ips []net.IP) {
	var strs []string
	for _, ip := range ips {
		strs = append(strs, ip.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.DNS[host]; ok && time.Since(e.At) < 6*time.Hour && equalStrings(e.IPs, strs) {
		return
	}
	s.DNS[host] = dnsEntry{IPs: strs, At: time.Now()}
	s.dirty = true
}

// lastDNS returns the last answer seen for host, however old.
func (s *state) lastDNS(host string) []net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ips []net.IP
	if r, ok := s.Routes[host]; ok && r.IP != "" { // the address that last worked comes first
		ips = append(ips, net.ParseIP(r.IP))
	}
	for _, x := range s.DNS[host].IPs {
		if ip := net.ParseIP(x); ip != nil && (len(ips) == 0 || !ips[0].Equal(ip)) {
			ips = append(ips, ip)
		}
	}
	return ips
}

// save writes the state if it changed, dropping the oldest entries beyond
// maxStateHosts.
func (s *state) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || s.path == "" {
		return nil
	}
	trim(s.Routes, func(r route) time.Time { return r.At })
	trim(s.DNS, func(e dnsEntry) time.Time { return e.At })
	trim(s.Learned, func(t time.Time) time.Time { return t })
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

func trim[V any](m map[string]V, at func(V) time.Time) {
	if len(m) <= maxStateHosts {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return at(m[keys[i]]).Before(at(m[keys[j]])) })
	for _, k := range keys[:len(keys)-maxStateHosts] {
		delete(m, k)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
