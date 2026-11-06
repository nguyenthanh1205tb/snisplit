package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// clientHello captures a real ClientHello produced by crypto/tls.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go tls.Client(a, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	rec, err := readRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestFindSNI(t *testing.T) {
	const name = "store.steampowered.com"
	rec := clientHello(t, name)
	off, n, ok := findSNI(rec)
	if !ok || string(rec[off:off+n]) != name {
		t.Fatalf("findSNI = %d,%d,%v", off, n, ok)
	}
	if _, _, ok := findSNI([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Fatal("found SNI in non-TLS data")
	}
	for i := 0; i < off+n; i++ { // truncated input must not panic or match
		if _, _, ok := findSNI(rec[:i]); ok {
			t.Fatalf("matched truncated record of %d bytes", i)
		}
	}
}

func TestFragmentModes(t *testing.T) {
	const name = "store.fastly.steamstatic.com"
	rec := clientHello(t, name)
	for _, mode := range fragModes {
		pieces := fragment(rec, mode)
		joined := bytes.Join(pieces, nil)
		for _, p := range pieces {
			if mode != "none" && bytes.Contains(p, []byte(name)) {
				t.Errorf("%s: a piece contains the whole SNI", mode)
			}
		}
		switch mode {
		case "none", "tcp":
			if !bytes.Equal(joined, rec) {
				t.Errorf("%s: bytes changed", mode)
			}
		case "record", "both":
			// two records whose payloads concatenate to the original payload
			r := bytes.NewReader(joined)
			r1, err1 := readRecord(r)
			r2, err2 := readRecord(r)
			if err1 != nil || err2 != nil || r.Len() != 0 {
				t.Fatalf("%s: not two records: %v %v", mode, err1, err2)
			}
			if got := append(append([]byte{}, r1[5:]...), r2[5:]...); !bytes.Equal(got, rec[5:]) {
				t.Errorf("%s: payload changed", mode)
			}
		}
		if mode == "both" && len(pieces) != 3 {
			t.Errorf("both: %d pieces, want 3", len(pieces))
		}
	}
}

func TestHostsBlock(t *testing.T) {
	orig := "# comment\r\n10.0.0.1 nas.local\r\n"
	names := mergeEntries([]string{"a.example", "b.example"}, nil)
	once := applyHostsBlock(orig, names)
	twice := applyHostsBlock(once, names)
	if once != twice {
		t.Fatalf("not idempotent:\n%q\n%q", once, twice)
	}
	if !strings.Contains(once, "\r\n127.0.0.1 a.example\r\n") || !strings.HasPrefix(once, orig) {
		t.Fatalf("unexpected content %q", once)
	}
	if got := installedNames(once); len(got) != 2 {
		t.Fatalf("installedNames = %v", got)
	}
	if removed := applyHostsBlock(once, nil); removed != orig {
		t.Fatalf("remove: got %q want %q", removed, orig)
	}
}

func TestParseNames(t *testing.T) {
	got := parseNames("# x\nA.example\n\n*.b.example # c\na.example\n")
	want := []string{"a.example", ".b.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v", got)
	}
	if len(exactNames(got)) != 1 {
		t.Fatal("exactNames kept a suffix")
	}
	steam, err := loadAll("steam", nil)
	if err != nil || len(exactNames(steam)) < 30 {
		t.Fatalf("steam preset: %v (%d)", err, len(steam))
	}
	if none, err := loadAll("none", nil); err != nil || len(none) != 0 {
		t.Fatalf("preset none: %v %v", none, err)
	}
	if _, err := loadAll("nope", nil); err == nil {
		t.Fatal("unknown preset accepted")
	}
	extra := filepath.Join(t.TempDir(), "extra.txt")
	os.WriteFile(extra, []byte("x.example\nstore.steampowered.com\n"), 0o644)
	merged, err := loadAll("steam", []string{extra})
	if err != nil || len(merged) != len(steam)+1 {
		t.Fatalf("merge: %v, %d names (steam %d)", err, len(merged), len(steam))
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Example.com":                     "example.com",
		"https://store.example.com/a?b=c": "store.example.com",
		"cdn.example.com:443":             "cdn.example.com",
		"example.com.":                    "example.com",
	} {
		if got := normalizeName(in); got != want {
			t.Errorf("normalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// User-added names survive a reinstall of the list (unless --reset), and
// "del" removes any name.
func TestHostsUserEntries(t *testing.T) {
	base := applyHostsBlock("10.0.0.1 nas\n", mergeEntries([]string{"a.example"}, nil))
	withUser := applyHostsBlock(base, append(parseBlock(base), hostEntry{"mine.example", true}))
	if !strings.Contains(withUser, "127.0.0.1 mine.example "+userMark) {
		t.Fatalf("user mark missing: %q", withUser)
	}
	got := userEntries(withUser)
	if len(got) != 1 || got[0].name != "mine.example" {
		t.Fatalf("userEntries = %v", got)
	}
	reinstalled := applyHostsBlock(withUser, mergeEntries([]string{"a.example", "b.example"}, userEntries(withUser)))
	if names := strings.Join(installedNames(reinstalled), ","); names != "a.example,b.example,mine.example" {
		t.Fatalf("after reinstall: %s", names)
	}
	if reset := applyHostsBlock(withUser, mergeEntries([]string{"a.example"}, nil)); strings.Contains(reset, "mine.example") {
		t.Fatal("reset kept the user name")
	}
}

func TestSplitHTTPRequest(t *testing.T) {
	const host = "store.steampowered.com"
	raw := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: x\r\n\r\n")
	pieces := splitHTTPRequest(append([]byte{}, raw...), host)
	joined := string(bytes.Join(pieces, nil))
	if len(pieces) != 2 || strings.Contains(joined, "Host:") || !strings.Contains(joined, "\r\nhoSt: "+host+"\r\n") {
		t.Fatalf("got %q", joined)
	}
	for _, p := range pieces {
		if bytes.Contains(p, []byte(host)) {
			t.Fatal("a piece contains the whole host")
		}
	}
	// the rewritten request must still parse with the right Host
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(joined)))
	if err != nil || req.Host != host {
		t.Fatalf("parse: %v host=%q", err, req.Host)
	}
}

func TestPAC(t *testing.T) {
	pac := makePAC([]string{"a.example", ".b.example"}, 8881)
	for _, s := range []string{`host == "a.example"`, `dnsDomainIs(host, ".b.example")`, "PROXY 127.0.0.1:8881"} {
		if !strings.Contains(pac, s) {
			t.Errorf("PAC missing %q", s)
		}
	}
}

// testProxy builds a proxy whose upstream is an httptest TLS server reachable
// as example.com (the name in httptest's certificate).
func testProxy(t *testing.T) (*proxy, *x509.CertPool, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello "+r.Host)
	}))
	t.Cleanup(ts.Close)
	_, portS, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portS)

	res := newResolver(false)
	res.override = func(h string) []net.IP {
		if h == "example.com" {
			return []net.IP{net.IPv4(127, 0, 0, 1)}
		}
		return nil
	}
	cfg := config{listen: "127.0.0.1", mode: "both", delay: time.Millisecond, timeout: 5 * time.Second, tlsPort: port}
	pool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return newProxy(cfg, res), pool, portS
}

func TestConnectProxyEndToEnd(t *testing.T) {
	p, pool, port := testProxy(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go p.serve(ln, p.handleProxyConn)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	resp, err := client.Get("https://example.com:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "hello example.com") {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}

	sresp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Get("http://" + ln.Addr().String() + statusPath)
	if err != nil || sresp.StatusCode != 200 {
		t.Fatalf("status endpoint: %v", err)
	}
	sresp.Body.Close()
}

func TestTransparentEndToEnd(t *testing.T) {
	p, pool, _ := testProxy(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go p.serve(ln, p.handleTransparentTLS)

	// What a browser does once the hosts file maps example.com to 127.0.0.1.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "hello example.com") {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
}

// In auto mode a reset before the server answers makes the proxy retry with
// the next split mode, and the mode that worked is remembered for the host.
func TestAutoModeFallback(t *testing.T) {
	p, pool, upPort := testProxy(t)

	// "DPI" in front of the TLS server: resets the first two connections.
	dpi, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dpi.Close()
	var seen int
	go func() {
		for {
			c, err := dpi.Accept()
			if err != nil {
				return
			}
			seen++
			if seen <= 2 {
				c.Read(make([]byte, 64))
				c.(*net.TCPConn).SetLinger(0) // RST, like an SNI filter
				c.Close()
				continue
			}
			up, err := net.Dial("tcp", "127.0.0.1:"+upPort)
			if err != nil {
				c.Close()
				continue
			}
			go relay(c, c, up)
		}
	}()
	_, dpiPort, _ := net.SplitHostPort(dpi.Addr().String())
	p.cfg.tlsPort, _ = strconv.Atoi(dpiPort)
	p.cfg.mode = "auto"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go p.serve(ln, p.handleTransparentTLS)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("request through fallback failed: %v", err)
	}
	if r := p.stats.retries.Load(); r != 2 {
		t.Errorf("retries = %d, want 2", r)
	}
	if m, _ := p.modes.Load("example.com"); m != autoModes[2] {
		t.Errorf("remembered mode = %v, want %s", m, autoModes[2])
	}
	if got := p.modesFor("example.com")[0]; got != autoModes[2] {
		t.Errorf("next attempt starts with %s, want %s", got, autoModes[2])
	}
	if st := p.status(); st.Connections != 1 || st.Failures != 0 {
		t.Errorf("status = %+v", st)
	}
}

func TestUpdateHelpers(t *testing.T) {
	if got := assetName("windows", "amd64"); got != "snisplit_windows_amd64.exe" {
		t.Errorf("assetName = %s", got)
	}
	if got := assetName("darwin", "arm64"); got != "snisplit_darwin_arm64" {
		t.Errorf("assetName = %s", got)
	}
	for path, want := range map[string]string{
		`/opt/homebrew/Cellar/snisplit/0.2.0/bin/snisplit`:        "Homebrew",
		`/home/linuxbrew/.linuxbrew/bin/snisplit`:                 "Homebrew",
		`C:\Users\a\scoop\apps\snisplit\current\snisplit.exe`:     "Scoop",
		`C:\Users\a\AppData\Local\Programs\snisplit\snisplit.exe`: "",
	} {
		if got := packageManager(path); got != want {
			t.Errorf("packageManager(%s) = %q, want %q", path, got, want)
		}
	}
	sums := "aaa  snisplit_linux_amd64\nBBB *snisplit_windows_amd64.exe\n"
	if h, ok := checksumFor(sums, "snisplit_windows_amd64.exe"); !ok || h != "bbb" {
		t.Errorf("checksumFor = %q %v", h, ok)
	}
	if _, ok := checksumFor(sums, "snisplit_darwin_arm64"); ok {
		t.Error("found a missing asset")
	}
}

// replaceBinary against a fake release server: a good download replaces the
// file and keeps the old one aside; a bad checksum changes nothing.
func TestReplaceBinary(t *testing.T) {
	asset := assetName(runtime.GOOS, runtime.GOARCH)
	newBin := []byte("new binary")
	sum := sha256.Sum256(newBin)
	good := hex.EncodeToString(sum[:])
	checksum := good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			io.WriteString(w, `{"tag_name":"v9.9.9"}`)
		case "/dl/v9.9.9/checksums.txt":
			io.WriteString(w, checksum+"  "+asset+"\n")
		case "/dl/v9.9.9/" + asset:
			w.Write(newBin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	src := updateSource{apiLatest: srv.URL + "/latest", downloadBase: srv.URL + "/dl"}

	if tag, err := latestTag(src); err != nil || tag != "v9.9.9" {
		t.Fatalf("latestTag = %q, %v", tag, err)
	}
	exe := filepath.Join(t.TempDir(), "snisplit.exe")
	os.WriteFile(exe, []byte("old binary"), 0o755)

	checksum = strings.Repeat("0", 64)
	if err := replaceBinary(src, "v9.9.9", exe); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("bad checksum: err = %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old binary" {
		t.Fatal("file changed despite a bad checksum")
	}
	if _, err := os.Stat(exe + ".new"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}

	checksum = good
	if err := replaceBinary(src, "v9.9.9", exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new binary" {
		t.Fatalf("not replaced: %q", b)
	}
}

func TestPluralAndAutostart(t *testing.T) {
	if plural(1, "connection") != "1 connection" || plural(0, "restart") != "0 restarts" || plural(12, "connection") != "12 connections" {
		t.Error("plural")
	}
	out := "\r\n" + `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` + "\r\n" +
		`    snisplit    REG_SZ    "C:\x\snisplit.exe" start` + "\r\n\r\n"
	if v := regValue(out); v != `"C:\x\snisplit.exe" start` {
		t.Errorf("regValue = %q", v)
	}
	for val, legacy := range map[string]bool{
		`"C:\x\snisplit.exe" start`:             true,  // written by v0.1-v0.3: upgrade
		`"C:\x\snisplit.exe" tray --start`:      false, // already has the icon
		`"C:\x\snisplit.exe" start --autostart`: false, // explicit --no-tray choice
		"":                                      false, // no entry
	} {
		if got := legacyAutostart(val); got != legacy {
			t.Errorf("legacyAutostart(%q) = %v", val, got)
		}
	}
	// the marker flag must not break "start"/"run" flag parsing
	if o := parseRunFlags("start", []string{"--autostart"}); o.validate() != nil {
		t.Error("--autostart rejected")
	}
}

func TestValidName(t *testing.T) {
	for n, want := range map[string]bool{
		"store.steampowered.com":          true,
		".steamstatic.com":                true,
		"steamcdn-a.akamaihd.net":         true,
		"localhost":                       false,
		"127.0.0.1":                       false,
		"evil.com 127.0.0.1":              false,
		"a.com\n10.0.0.1 b.com":           false,
		"-bad.example.com":                false,
		"bad..example.com":                false,
		strings.Repeat("a.", 130) + "com": false,
	} {
		if got := validName(n); got != want {
			t.Errorf("validName(%q) = %v, want %v", n, got, want)
		}
	}
}

func TestListDiffAndFetch(t *testing.T) {
	hosts := applyHostsBlock("", []hostEntry{{"a.example", false}, {"old.example", false}, {"mine.example", true}})
	added, removed := listDiff([]string{"a.example", "new.example", ".suffix.example"}, hosts)
	if strings.Join(added, ",") != "new.example" || strings.Join(removed, ",") != "old.example" {
		t.Fatalf("listDiff = +%v -%v (user names and suffixes must be ignored)", added, removed)
	}

	body := "# list\nstore.example.com\ncdn.example.com\n.example.com\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lists/good.txt":
			io.WriteString(w, body)
		case "/lists/evil.txt":
			io.WriteString(w, "store.example.com\nevil.com 10.0.0.1\n")
		case "/lists/empty.txt":
			io.WriteString(w, "# nothing\n.example.com\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := listBaseURL
	listBaseURL = srv.URL + "/lists/"
	defer func() { listBaseURL = old }()

	names, err := fetchList("good")
	if err != nil || len(exactNames(names)) != 2 {
		t.Fatalf("fetchList(good) = %v, %v", names, err)
	}
	for _, p := range []string{"evil", "empty", "missing", "../x"} {
		if _, err := fetchList(p); err == nil {
			t.Errorf("fetchList(%q) should fail", p)
		}
	}
}
