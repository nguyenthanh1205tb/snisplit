package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseBlocklist(t *testing.T) {
	src := `# a comment
ads.example.com
0.0.0.0 tracker.example.net # hosts format
127.0.0.1 localhost
||metrics.example.org^
*.wild.example.io
Not A Domain!
bad..name
`
	set, err := parseBlocklist(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ads.example.com", "tracker.example.net", "metrics.example.org", "wild.example.io"} {
		if _, ok := set[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	if len(set) != 4 {
		t.Errorf("got %d entries: %v", len(set), set)
	}
	if _, err := parseBlocklist(strings.NewReader("# only comments\n")); err == nil {
		t.Error("an empty list must be rejected")
	}
}

func TestBlockerMatching(t *testing.T) {
	b := newBlocker()
	b.setList(map[string]struct{}{"ads.example.com": {}, "tracker.net": {}, "steamcommunity.com": {}}, "test", time.Now())
	b.setRules([]string{"ok.tracker.net", "steamcommunity.com"}, []string{"custom.example"})
	for host, want := range map[string]bool{
		"ads.example.com":    true,
		"x.ads.example.com":  true,  // subdomains of a blocked domain
		"example.com":        false, // but not its parent
		"cdn.tracker.net":    true,
		"ok.tracker.net":     false, // allowed, though its parent is blocked
		"a.ok.tracker.net":   false,
		"steamcommunity.com": false, // allow wins over the list
		"custom.example":     true,
		"www.custom.example": true,
		"localhost":          false,
		"192.168.1.1":        false,
		"ADS.EXAMPLE.COM.":   true,
		"notads.example.com": false,
	} {
		if got := b.blocks(host); got != want {
			t.Errorf("blocks(%s) = %v, want %v", host, got, want)
		}
	}
}

// A download that fails or is empty never replaces the cached list; a good
// one is cached with its source.
func TestBlocklistDownloadAndCache(t *testing.T) {
	body := "ads.example.com\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
	defer srv.Close()
	old := adblockCachePath
	cache := filepath.Join(t.TempDir(), "adblock.txt")
	adblockCachePath = func() string { return cache }
	defer func() { adblockCachePath = old }()
	adblockPresets["test"] = srv.URL // presets may be any URL; user URLs must be https
	defer delete(adblockPresets, "test")

	set, src, err := downloadBlocklist("test")
	if err != nil || len(set) != 1 || src != srv.URL {
		t.Fatalf("download: %v %v %s", set, err, src)
	}
	body = "# nothing\n"
	if _, _, err := downloadBlocklist("test"); err == nil {
		t.Fatal("empty list accepted")
	}
	got, gotSrc, _, err := loadBlocklistFile(cache)
	if err != nil || len(got) != 1 || gotSrc != srv.URL {
		t.Fatalf("cache after a bad download: %v %s %v", got, gotSrc, err)
	}
	if _, err := adblockURLs("normal,http://insecure.example/list"); err == nil {
		t.Error("plain http list URL accepted")
	}
}

// Through the proxy: a blocked host gets 403 without any connection to it,
// other hosts work, and turning blocking off takes effect without a restart.
func TestProxyRefusesBlockedHosts(t *testing.T) {
	p, _, port := testProxy(t)
	p.cfg.mode = "none"
	b := newBlocker()
	b.setList(map[string]struct{}{"ads.example.net": {}}, "test", time.Now())
	p.ads.Store(b)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go p.serve(ln, p.handleProxyConn)

	connect := func(target string) string {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		line, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(line)
	}
	if got := connect("ads.example.net:443"); !strings.Contains(got, "403") {
		t.Errorf("blocked host: %q", got)
	}
	if got := connect("example.com:" + port); !strings.Contains(got, "200") {
		t.Errorf("normal host: %q", got)
	}
	if b.blocked.Load() != 1 || p.status().Adblock.Blocked != 1 {
		t.Errorf("blocked counter = %d", b.blocked.Load())
	}
	c, err := net.Dial("tcp", ln.Addr().String()) // plain HTTP to a blocked subdomain
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET http://x.ads.example.net/pixel.gif HTTP/1.1\r\nHost: x.ads.example.net\r\n\r\n")
	if line, _ := bufio.NewReader(c).ReadString('\n'); !strings.Contains(line, "403") {
		t.Errorf("plain HTTP: %q", line)
	}
	c.Close()

	p.ads.Store(nil) // what "adblock off" + reload does
	// Now the proxy tries to reach it (502 here: the name does not exist in the test).
	if got := connect("ads.example.net:443"); strings.Contains(got, "403") {
		t.Errorf("after turning off: %q", got)
	}
}

// applyAdblock follows settings.json: on with the cached list (allowing the
// snisplit lists and the user's allow entries), then off.
func TestAdblockFollowsSettings(t *testing.T) {
	dir := t.TempDir()
	oldC := adblockCachePath
	adblockCachePath = func() string { return filepath.Join(dir, "adblock.txt") }
	defer func() { adblockCachePath = oldC }()

	u, _ := adblockSource("")
	os.WriteFile(adblockCachePath(), []byte(sourceMark+u+"\nads.example.com\nsteamcommunity.com\n"), 0o644)
	now := time.Now()
	os.Chtimes(adblockCachePath(), now, now) // fresh, so no download is started

	p := newProxy(config{names: []string{"steamcommunity.com"}}, newResolver(false), nil)
	p.applyAdblock(settings{Adblock: true, Block: []string{"more.example"}})
	if !p.adBlocked("ads.example.com") || !p.adBlocked("a.more.example") || p.adBlocked("steamcommunity.com") {
		t.Fatal("rules not applied")
	}
	p.applyAdblock(settings{Adblock: true, Allow: []string{"ads.example.com"}})
	if p.adBlocked("ads.example.com") {
		t.Fatal("allow entry ignored")
	}
	p.applyAdblock(settings{Adblock: false})
	if p.adBlocked("more.example") || p.status().Adblock != nil {
		t.Fatal("still blocking after off")
	}
}
