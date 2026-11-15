package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Ad blocking: in browser mode every site goes through snisplit, so it can
// refuse connections to ad, tracker and malware domains. A blocked domain
// also blocks its subdomains. Like DNS blockers it works per domain: it
// cannot hide empty ad boxes or ads served from the site's own domain.

const hageziBase = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"

var adblockPresets = map[string]string{
	"light":  hageziBase + "light-onlydomains.txt",                                           // ~90k domains
	"normal": hageziBase + "multi-onlydomains.txt",                                           // ~220k domains
	"pro":    hageziBase + "pro-onlydomains.txt",                                             // stricter
	"vn":     "https://raw.githubusercontent.com/bigdargon/hostsVN/master/option/domain.txt", // Vietnamese sites
}

const defaultAdblockLists = "normal,vn"

// adblockURLs resolves a comma-separated list of preset names and https URLs
// ("" means normal,vn).
func adblockURLs(list string) ([]string, error) {
	if list == "" {
		list = defaultAdblockLists
	}
	var urls []string
	for _, l := range strings.Split(list, ",") {
		l = strings.TrimSpace(l)
		switch u, ok := adblockPresets[l]; {
		case ok:
			urls = append(urls, u)
		case strings.HasPrefix(l, "https://"):
			urls = append(urls, l)
		default:
			return nil, fmt.Errorf("unknown list %q: use light, normal, pro, vn or https:// URLs, comma-separated", l)
		}
	}
	return urls, nil
}

// adblockSource is how a set of lists is recorded in the cache file.
func adblockSource(list string) (string, error) {
	urls, err := adblockURLs(list)
	return strings.Join(urls, " "), err
}

var adblockCachePath = func() string {
	return filepath.Join(filepath.Dir(logPath()), "adblock.txt")
}

const sourceMark = "# snisplit-source: "

// parseBlocklist reads plain domain lists, hosts files ("0.0.0.0 domain"),
// "*.domain" wildcards and adblock-style "||domain^" rules.
func parseBlocklist(r io.Reader) (map[string]struct{}, error) {
	set := map[string]struct{}{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#!"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if f := strings.Fields(line); len(f) >= 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::") {
			line = f[1]
		}
		line = strings.TrimPrefix(line, "||")
		line = strings.TrimSuffix(line, "^")
		line = strings.TrimPrefix(line, "*.")
		line = strings.ToLower(strings.TrimSuffix(line, "."))
		if line == "localhost" || !validName(line) || strings.HasPrefix(line, ".") {
			continue
		}
		set[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("the list has no domains")
	}
	return set, nil
}

// blocker decides which hosts to refuse.
type blocker struct {
	mu      sync.RWMutex
	list    map[string]struct{}
	extra   map[string]struct{} // "snisplit adblock block"
	allow   map[string]struct{} // "snisplit adblock allow" and the snisplit lists
	updated time.Time
	source  string

	blocked atomic.Int64
}

func newBlocker() *blocker {
	return &blocker{list: map[string]struct{}{}, extra: map[string]struct{}{}, allow: map[string]struct{}{}}
}

func toSet(names []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, n := range names {
		if n = strings.TrimPrefix(normalizeName(n), "."); n != "" {
			m[n] = struct{}{}
		}
	}
	return m
}

// setRules replaces the user's allow and block entries.
func (b *blocker) setRules(allow, block []string) {
	a, x := toSet(allow), toSet(block)
	b.mu.Lock()
	b.allow, b.extra = a, x
	b.mu.Unlock()
}

func (b *blocker) setList(list map[string]struct{}, source string, updated time.Time) {
	b.mu.Lock()
	b.list, b.source, b.updated = list, source, updated
	b.mu.Unlock()
}

// info returns the list size, where it came from and when.
func (b *blocker) info() (n int, source string, updated time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.list) + len(b.extra), b.source, b.updated
}

// blocks reports whether host or a parent domain is blocked and not allowed.
// An allow entry wins over a block entry at any level.
func (b *blocker) blocks(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || isLocalHost(host) || net.ParseIP(host) != nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	hit := false
	for h := host; ; {
		if _, ok := b.allow[h]; ok {
			return false
		}
		if !hit {
			_, inList := b.list[h]
			_, inExtra := b.extra[h]
			hit = inList || inExtra
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return hit
}

// loadBlocklistFile reads the cached list and the URL it was downloaded from.
func loadBlocklistFile(path string) (set map[string]struct{}, source string, mod time.Time, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	if first, _, _ := bytes.Cut(b, []byte("\n")); bytes.HasPrefix(first, []byte(sourceMark)) {
		source = strings.TrimSpace(string(first[len(sourceMark):]))
	}
	if set, err = parseBlocklist(bytes.NewReader(b)); err != nil {
		return nil, "", time.Time{}, err
	}
	if fi, err := os.Stat(path); err == nil {
		mod = fi.ModTime()
	}
	return set, source, mod, nil
}

// downloadBlocklist fetches the list, checks it, and only then replaces the
// cached copy, so a failed or empty download never removes a working list.
func downloadBlocklist(list string) (map[string]struct{}, string, error) {
	urls, err := adblockURLs(list)
	if err != nil {
		return nil, "", err
	}
	src := strings.Join(urls, " ")
	set := map[string]struct{}{}
	data := []byte(sourceMark + src + "\n")
	for _, u := range urls { // every list must download, or nothing changes
		body, err := fetchListBody(u)
		if err != nil {
			return nil, "", err
		}
		part, err := parseBlocklist(bytes.NewReader(body))
		if err != nil {
			return nil, "", fmt.Errorf("%s: %v", u, err)
		}
		for d := range part {
			set[d] = struct{}{}
		}
		data = append(append(data, body...), '\n')
	}
	path := adblockCachePath()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path+".tmp", data, 0o644); err != nil {
		return nil, "", err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return nil, "", err
	}
	return set, src, nil
}

func fetchListBody(u string) ([]byte, error) {
	resp, err := httpGet(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// applyAdblock brings the proxy's blocker in line with the saved settings:
// off, or on with the cached list (downloading it when missing or stale).
func (p *proxy) applyAdblock(s settings) {
	if !s.Adblock {
		p.ads.Store(nil)
		return
	}
	b := p.ads.Load()
	if b == nil {
		b = newBlocker()
	}
	b.setRules(append(append([]string(nil), s.Allow...), p.cfg.names...), s.Block)
	want, _ := adblockSource(s.AdblockList)
	if _, src, _ := b.info(); src != want {
		if set, fsrc, mod, err := loadBlocklistFile(adblockCachePath()); err == nil && fsrc == want {
			b.setList(set, fsrc, mod)
		}
	}
	p.ads.Store(b)
	if _, src, updated := b.info(); src != want || time.Since(updated) > 24*time.Hour {
		go p.refreshAdblock(s.AdblockList)
	}
}

var adblockRefreshing atomic.Bool

func (p *proxy) refreshAdblock(list string) {
	if !adblockRefreshing.CompareAndSwap(false, true) {
		return
	}
	defer adblockRefreshing.Store(false)
	set, src, err := downloadBlocklist(list)
	if err != nil {
		log.Printf("ad block list: %v", err)
		return
	}
	if b := p.ads.Load(); b != nil {
		b.setList(set, src, time.Now())
	}
	log.Printf("ad block list: %d domains from %s", len(set), src)
}

// refuse answers a blocked request without contacting the site.
func (p *proxy) refuse(c io.WriteCloser, host string) {
	if b := p.ads.Load(); b != nil {
		b.blocked.Add(1)
	}
	p.debugf("BLOCK %s", host)
	const body = "Blocked by snisplit adblock"
	fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	c.Close()
}

func (p *proxy) adBlocked(host string) bool {
	b := p.ads.Load()
	return b != nil && b.blocks(host)
}

// reloadProxy asks a running proxy to re-read settings.json.
func reloadProxy() {
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	if resp, err := c.Get("http://127.0.0.1:" + strconv.Itoa(defaultPort) + reloadPath); err == nil {
		resp.Body.Close()
	}
}

func cmdAdblock(args []string) error {
	s := loadSettings()
	if len(args) == 0 || args[0] == "status" {
		fmt.Printf("ad blocking: %s (list %s)\n", onOff(s.Adblock), orDefault(s.AdblockList, defaultAdblockLists))
		if st, err := getStatus(defaultPort); err == nil && st.Adblock != nil {
			fmt.Printf("  %d domains, %d requests blocked since the proxy started, list updated %s ago\n",
				st.Adblock.Domains, st.Adblock.Blocked, time.Since(st.Adblock.Updated).Round(time.Minute))
		}
		if len(s.Allow) > 0 {
			fmt.Printf("  allowed: %s\n", strings.Join(s.Allow, ", "))
		}
		if len(s.Block) > 0 {
			fmt.Printf("  also blocked: %s\n", strings.Join(s.Block, ", "))
		}
		if s.Adblock && !s.Browser {
			fmt.Println("  note: it only works in browser mode - snisplit browser on")
		}
		fmt.Println(`
  snisplit adblock on [lists]                  turn on; lists: light, normal, pro, vn or URLs,
                                               comma-separated (default normal,vn: ~240k domains)
  snisplit adblock off
  snisplit adblock allow <domain>...           never block these (and their subdomains)
  snisplit adblock block <domain>...           block these too
  snisplit adblock remove <domain>...          undo allow/block
  snisplit adblock test <domain>...            is it blocked?
  snisplit adblock update                      download the newest list now`)
		return nil
	}
	names := func() ([]string, error) {
		var out []string
		for _, a := range args[1:] {
			n := strings.TrimPrefix(normalizeName(a), ".")
			if !validName(n) {
				return nil, fmt.Errorf("invalid domain %q", a)
			}
			out = append(out, n)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("usage: snisplit adblock %s <domain>...", args[0])
		}
		return out, nil
	}
	switch args[0] {
	case "on", "update":
		list := s.AdblockList
		if args[0] == "on" && len(args) > 1 {
			list = args[1]
		}
		if _, err := adblockURLs(list); err != nil {
			return err
		}
		fmt.Printf("downloading the %s list ... ", orDefault(list, defaultAdblockLists))
		set, _, err := downloadBlocklist(list)
		if err != nil {
			fmt.Println("failed")
			return err
		}
		fmt.Printf("%d domains\n", len(set))
		s.Adblock, s.AdblockList = true, list
		if list == defaultAdblockLists {
			s.AdblockList = ""
		}
	case "off":
		s.Adblock = false
	case "allow", "block", "remove":
		ns, err := names()
		if err != nil {
			return err
		}
		for _, n := range ns {
			s.Allow, s.Block = without(s.Allow, n), without(s.Block, n)
			switch args[0] {
			case "allow":
				s.Allow = append(s.Allow, n)
			case "block":
				s.Block = append(s.Block, n)
			}
		}
	case "test":
		ns, err := names()
		if err != nil {
			return err
		}
		b := newBlocker()
		listed, _ := loadAll("steam", nil)
		b.setRules(append(append([]string(nil), s.Allow...), listed...), s.Block)
		if set, src, mod, err := loadBlocklistFile(adblockCachePath()); err == nil {
			b.setList(set, src, mod)
		} else {
			fmt.Println("(no list downloaded yet: snisplit adblock on)")
		}
		for _, n := range ns {
			verdict := "not blocked"
			if b.blocks(n) {
				verdict = "BLOCKED"
			}
			fmt.Printf("%-40s %s\n", n, verdict)
		}
		return nil
	default:
		return fmt.Errorf("usage: snisplit adblock [on|off|allow|block|remove|test|update]")
	}
	if err := saveSettings(s); err != nil {
		return err
	}
	reloadProxy()
	fmt.Printf("ad blocking %s\n", onOff(s.Adblock))
	if s.Adblock && !s.Browser {
		fmt.Println("it only works in browser mode: snisplit browser on")
	}
	return nil
}

func without(list []string, x string) []string {
	var out []string
	for _, v := range list {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
