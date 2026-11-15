package main

// A fake ISP: a middlebox that reads what the client sends, looks for a
// blocked name the way different kinds of DPI do, and resets the connection
// when it finds it. It shows which split methods beat which kind of filter,
// including filters stricter than the one in use today.
//
// Loopback cannot imitate everything: TTL is never decremented and the
// middlebox's own socket drops TCP urgent data, so "disorder" and "oob"
// behave like "record" here. Both were checked against the real ISP instead.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type dpiLevel int

const (
	perPacket     dpiLevel = iota // looks at each packet on its own (the ISP today)
	tcpReassembly                 // puts the TCP stream together, reads the first TLS record
	tlsReassembly                 // also joins TLS records into the whole ClientHello
)

func (l dpiLevel) String() string {
	return [...]string{"per-packet", "tcp-reassembly", "tls-reassembly"}[l]
}

type fakeISP struct {
	ln     net.Listener
	level  dpiLevel
	giveUp time.Duration // stop inspecting when the next piece takes longer (0: never)
	block  string
	target string
	resets atomic.Int32
}

func startFakeISP(t *testing.T, bind string, level dpiLevel, giveUp time.Duration, target string) *fakeISP {
	t.Helper()
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeISP{ln: ln, level: level, giveUp: giveUp, block: "example.com", target: target}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	return f
}

func (f *fakeISP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeISP) handle(c net.Conn) {
	up, err := net.Dial("tcp", f.target)
	if err != nil {
		c.Close()
		return
	}
	var seen []byte
	buf := make([]byte, 4096)
	for done := false; !done; {
		wait := 5 * time.Second
		if f.giveUp > 0 && len(seen) > 0 {
			wait = f.giveUp
		}
		c.SetReadDeadline(time.Now().Add(wait))
		n, err := c.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			seen = append(seen, chunk...)
			blocked, finished := f.inspect(chunk, seen)
			if blocked {
				f.resets.Add(1)
				c.(*net.TCPConn).SetLinger(0) // RST
				c.Close()
				up.Close()
				return
			}
			up.Write(chunk)
			done = finished
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break // gave up waiting: let the rest through unseen
			}
			c.Close()
			up.Close()
			return
		}
	}
	c.SetReadDeadline(time.Time{})
	relay(c, c, up)
}

// inspect returns whether to block now and whether inspection is finished.
func (f *fakeISP) inspect(chunk, seen []byte) (blocked, finished bool) {
	name := []byte(f.block)
	switch f.level {
	case perPacket:
		if bytes.Contains(chunk, name) {
			return true, true
		}
		_, complete := joinHandshake(seen)
		return false, complete
	case tcpReassembly:
		if len(seen) < 5 {
			return false, false
		}
		l := 5 + int(binary.BigEndian.Uint16(seen[3:]))
		if len(seen) < l {
			return false, false
		}
		return bytes.Contains(seen[:l], name), true
	default:
		msg, complete := joinHandshake(seen)
		if !complete {
			return false, false
		}
		return bytes.Contains(msg, name), true
	}
}

// joinHandshake joins the payloads of the leading handshake records and
// reports whether they hold one complete handshake message.
func joinHandshake(b []byte) (msg []byte, complete bool) {
	for len(b) >= 5 && b[0] == 0x16 {
		l := int(binary.BigEndian.Uint16(b[3:]))
		if len(b) < 5+l {
			break
		}
		msg = append(msg, b[5:5+l]...)
		b = b[5+l:]
		if len(msg) >= 4 && len(msg) >= 4+(int(msg[1])<<16|int(msg[2])<<8|int(msg[3])) {
			return msg, true
		}
	}
	if len(b) > 0 && b[0] != 0x16 {
		return msg, true // not TLS: nothing to look at
	}
	return msg, false
}

// tlsServer is the "real" site, with a certificate for example.com.
func tlsServer(t *testing.T) (addr string, pool *x509.CertPool) {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello "+r.Host)
	}))
	ts.Config.ErrorLog = log.New(io.Discard, "", 0) // the fake ISP's resets are expected
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.Listener.Addr().String(), ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

func handshakeVia(addr, mode string, pool *x509.CertPool) error {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	tc := tls.Client(&splitConn{Conn: c, mode: mode, delay: 5 * time.Millisecond},
		&tls.Config{ServerName: "example.com", RootCAs: pool})
	tc.SetDeadline(time.Now().Add(4 * time.Second))
	defer tc.Close()
	return tc.Handshake()
}

// TestSplitModesAgainstDPI is the table of which method beats which filter.
func TestSplitModesAgainstDPI(t *testing.T) {
	server, pool := tlsServer(t)
	want := map[dpiLevel]map[string]bool{
		perPacket:     {"none": false, "both": true, "record": true, "tcp": true, "chunk": true, "disorder": true, "slow": true, "oob": true},
		tcpReassembly: {"none": false, "tcp": false, "both": true, "record": true, "chunk": true, "disorder": true, "slow": true, "oob": true},
		// Joins everything, but gives up after 150 ms: only "slow" outlasts it.
		tlsReassembly: {"none": false, "tcp": false, "both": false, "record": false, "chunk": false, "disorder": false, "slow": true, "oob": false},
	}
	for _, level := range []dpiLevel{perPacket, tcpReassembly, tlsReassembly} {
		giveUp := time.Duration(0)
		if level == tlsReassembly {
			giveUp = 150 * time.Millisecond
		}
		isp := startFakeISP(t, "127.0.0.1:0", level, giveUp, server)
		for _, mode := range fragModes {
			err := handshakeVia(isp.ln.Addr().String(), mode, pool)
			if got := err == nil; got != want[level][mode] {
				t.Errorf("%s DPI, mode %s: handshake ok=%v (%v), want ok=%v", level, mode, got, err, want[level][mode])
			}
		}
	}
}

func TestPlanKeepsHandshake(t *testing.T) {
	rec := clientHello(t, "store.fastly.steamstatic.com")
	for _, mode := range fragModes {
		ps := plan(rec, mode)
		var joined []byte
		for _, p := range ps {
			d := p.data
			if p.oob {
				d = d[:len(d)-1] // the urgent byte never reaches the server
			}
			joined = append(joined, d...)
			if mode != "none" && bytes.Contains(p.data, []byte("store.fastly.steamstatic.com")) {
				t.Errorf("%s: a piece holds the whole name", mode)
			}
		}
		msg, complete := joinHandshake(joined)
		if !complete || !bytes.Equal(msg, rec[5:]) {
			t.Errorf("%s: handshake changed (complete=%v)", mode, complete)
		}
	}
}

// proxyBehind returns a proxy whose only route to example.com is through isp.
func proxyBehind(t *testing.T, ispPort int, ips ...string) *proxy {
	t.Helper()
	res := newResolver(false)
	res.override = func(h string) []net.IP {
		if h != "example.com" && h != "unlisted.example.com" {
			return nil
		}
		var out []net.IP
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out
	}
	cfg := config{listen: "127.0.0.1", mode: "auto", delay: 5 * time.Millisecond, delaySet: true,
		timeout: 4 * time.Second, tlsPort: ispPort, names: []string{"example.com"}}
	return newProxy(cfg, res, nil)
}

// fetchThrough does what an app does once the hosts file points example.com
// at the proxy.
func fetchThrough(t *testing.T, p *proxy, host string, pool *x509.CertPool) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go p.serve(ln, p.handleTransparentTLS)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: host, RootCAs: pool})
	if err != nil {
		return err
	}
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "hello ") {
		return errors.New("unexpected body " + string(body))
	}
	return nil
}

// In auto mode the proxy finds the first method that beats each filter and
// remembers it.
func TestProxyFindsWayPastDPI(t *testing.T) {
	server, pool := tlsServer(t)
	for _, tc := range []struct {
		level  dpiLevel
		giveUp time.Duration
		mode   string
	}{
		{perPacket, 0, "both"},
		{tcpReassembly, 0, "both"},
		{tlsReassembly, 150 * time.Millisecond, "slow"},
	} {
		isp := startFakeISP(t, "127.0.0.1:0", tc.level, tc.giveUp, server)
		p := proxyBehind(t, isp.port(), "127.0.0.1")
		if err := fetchThrough(t, p, "example.com", pool); err != nil {
			t.Errorf("%s: %v", tc.level, err)
			continue
		}
		if r, _ := p.state.route("example.com"); r.Mode != tc.mode {
			t.Errorf("%s: remembered %q, want %q", tc.level, r.Mode, tc.mode)
		}
		before := p.stats.retries.Load()
		if err := fetchThrough(t, p, "example.com", pool); err != nil || p.stats.retries.Load() != before {
			t.Errorf("%s: second request: %v, %d extra retries", tc.level, err, p.stats.retries.Load()-before)
		}
	}
}

// One address of the site is blocked outright (every connection reset); the
// proxy moves on to another address and remembers the one that works.
func TestProxyAvoidsBlockedAddress(t *testing.T) {
	server, pool := tlsServer(t)
	good := startFakeISP(t, "127.0.0.1:0", perPacket, 0, server)
	bad, err := net.Listen("tcp", "127.0.0.2:"+strconv.Itoa(good.port()))
	if err != nil {
		t.Skip("cannot listen on 127.0.0.2:", err)
	}
	defer bad.Close()
	go func() {
		for {
			c, err := bad.Accept()
			if err != nil {
				return
			}
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}()
	p := proxyBehind(t, good.port(), "127.0.0.2", "127.0.0.1")
	for i := 0; i < 3; i++ { // the order of addresses is random: try a few times
		if err := fetchThrough(t, p, "example.com", pool); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if r, _ := p.state.route("example.com"); r.IP != "127.0.0.1" {
		t.Errorf("remembered address %q, want 127.0.0.1", r.IP)
	}
}

// When no split gets through, the proxy uses the upstream proxy (SOCKS5 or
// HTTP CONNECT) and goes straight there next time.
func TestUpstreamWhenEverythingIsBlocked(t *testing.T) {
	server, pool := tlsServer(t)
	isp := startFakeISP(t, "127.0.0.1:0", tlsReassembly, 0, server) // never gives up
	socks := startSOCKS5(t, server)

	// An HTTP CONNECT upstream: another snisplit that reaches the server directly.
	_, serverPort, _ := net.SplitHostPort(server)
	sp, _ := strconv.Atoi(serverPort)
	direct := newProxy(config{listen: "127.0.0.1", mode: "none", timeout: 4 * time.Second, tlsPort: sp}, newResolver(false), nil)
	direct.res.override = func(h string) []net.IP { return []net.IP{net.IPv4(127, 0, 0, 1)} }
	hln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hln.Close()
	go direct.serve(hln, direct.handleProxyConn)

	for _, up := range []string{"socks5://" + socks, "http://" + hln.Addr().String()} {
		p := proxyBehind(t, isp.port(), "127.0.0.1")
		p.cfg.upstream, _ = parseUpstream(up)
		if strings.HasPrefix(up, "http") {
			// The CONNECT names the server's real port, so the blocked direct
			// path must use that port too: a second fake ISP on 127.0.0.2.
			probe, err := net.Listen("tcp", "127.0.0.2:"+serverPort)
			if err != nil {
				t.Logf("skipping the HTTP upstream case: %v", err) // macOS has no 127.0.0.2
				continue
			}
			probe.Close()
			startFakeISP(t, "127.0.0.2:"+serverPort, tlsReassembly, 0, server)
			p.cfg.tlsPort = sp
			p.res.override = func(string) []net.IP { return []net.IP{net.ParseIP("127.0.0.2")} }
		}
		if err := fetchThrough(t, p, "example.com", pool); err != nil {
			t.Errorf("%s: %v", up, err)
			continue
		}
		if r, _ := p.state.route("example.com"); r.Mode != "upstream" || p.stats.viaUpstream.Load() != 1 {
			t.Errorf("%s: route %+v, via upstream %d", up, r, p.stats.viaUpstream.Load())
		}
		before := p.stats.retries.Load()
		if err := fetchThrough(t, p, "example.com", pool); err != nil || p.stats.retries.Load() != before {
			t.Errorf("%s: second request should go straight upstream: %v", up, err)
		}
	}
	if isp.resets.Load() == 0 {
		t.Error("the fake ISP never blocked anything")
	}
}

// startSOCKS5 runs a minimal SOCKS5 server that sends every CONNECT to target.
func startSOCKS5(t *testing.T, target string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				head := make([]byte, 2)
				io.ReadFull(c, head)
				io.ReadFull(c, make([]byte, head[1]))
				c.Write([]byte{5, 0})
				req := make([]byte, 4)
				io.ReadFull(c, req)
				switch req[3] {
				case 1:
					io.ReadFull(c, make([]byte, 4+2))
				case 3:
					l := make([]byte, 1)
					io.ReadFull(c, l)
					io.ReadFull(c, make([]byte, int(l[0])+2))
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					c.Close()
					return
				}
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				relay(c, c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// Browser mode: a site that is in no list is tried unsplit first; once it is
// found blocked it is remembered and split straight away next time.
func TestBrowserModeLearnsBlockedSites(t *testing.T) {
	server, pool := tlsServer(t)
	isp := startFakeISP(t, "127.0.0.1:0", perPacket, 0, server)
	p := proxyBehind(t, isp.port(), "127.0.0.1")
	p.cfg.names = nil
	p.exact = map[string]bool{}
	if got := p.modesFor("example.com", false)[0]; got != "none" {
		t.Fatalf("unknown site starts with %q, want none", got)
	}
	if err := fetchThrough(t, p, "example.com", pool); err != nil {
		t.Fatal(err)
	}
	if !p.state.isLearned("example.com") || isp.resets.Load() != 1 {
		t.Fatalf("learned=%v resets=%d", p.state.isLearned("example.com"), isp.resets.Load())
	}
	if err := fetchThrough(t, p, "example.com", pool); err != nil || isp.resets.Load() != 1 {
		t.Fatalf("second visit: %v, resets=%d (should split right away)", err, isp.resets.Load())
	}
	if st := p.status(); len(st.Learned) != 1 || st.Learned[0] != "example.com" {
		t.Errorf("status learned = %v", st.Learned)
	}
}

// ---------------------------------------------------------------- DNS

// dohServer answers A queries with two addresses (or fails with HTTP 500 when
// ip is ""). The answers use name compression, like real servers.
func dohServer(t *testing.T, ip string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if ip == "" {
			http.Error(w, "blocked", 500)
			return
		}
		q, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil || len(q) < 12 {
			http.Error(w, "bad", 400)
			return
		}
		resp := append([]byte(nil), q...)
		resp[2], resp[3] = 0x81, 0x80 // response, recursion available, no error
		resp[7] = 2                   // two answers
		for _, a := range []string{"10.9.9.9", ip} {
			resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4) // name pointer, A, IN, TTL 60
			resp = append(resp, net.ParseIP(a).To4()...)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// A blocked DoH server is skipped and moved to the back; when every server
// and the system DNS fail, the last good answer saved on disk is used.
func TestResolverFallbacks(t *testing.T) {
	var badHits, goodHits atomic.Int32
	bad := dohServer(t, "", &badHits)
	good := dohServer(t, "203.0.113.7", &goodHits)
	r := newResolver(true)
	r.client = good.Client()
	r.state = loadState(filepath.Join(t.TempDir(), "state.json"))
	r.setEndpoints([]string{bad.URL + "/a", bad.URL + "/b", good.URL + "/dns-query"})

	ips, err := r.lookup(context.Background(), "snisplit-test.invalid")
	if err != nil || len(ips) != 2 || ips[1].String() != "203.0.113.7" {
		t.Fatalf("lookup = %v, %v", ips, err)
	}
	if got := r.ordered()[0]; got != good.URL+"/dns-query" {
		t.Errorf("working server not tried first next time: %s", got)
	}

	r.cache = map[string]cacheEntry{}
	r.setEndpoints([]string{bad.URL + "/a"})
	ips, err = r.lookup(context.Background(), "snisplit-test.invalid")
	if err != nil || len(ips) != 2 {
		t.Fatalf("last-good fallback = %v, %v", ips, err)
	}
	if err := r.state.save(); err != nil {
		t.Fatal(err)
	}
	if again := loadState(r.state.path).lastDNS("snisplit-test.invalid"); len(again) != 2 {
		t.Errorf("saved answer not reloaded: %v", again)
	}
}

func TestParseDNSAnswer(t *testing.T) {
	if _, _, err := parseDNSAnswer([]byte{0, 0, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0}); !errors.Is(err, errNXDomain) {
		t.Errorf("NXDOMAIN: %v", err)
	}
	q := dnsQuery("example.com")
	for i := 0; i < len(q); i++ { // truncated input must not panic
		parseDNSAnswer(q[:i])
	}
}

// ---------------------------------------------------------------- strategy

func TestStrategy(t *testing.T) {
	s, err := parseStrategy(builtinStrategy)
	if err != nil || len(s.Modes) < 5 || len(s.DoH) < 4 || len(s.Canary) == 0 {
		t.Fatalf("built-in strategy: %v %+v", err, s)
	}
	for _, bad := range []string{
		`{"version":2,"modes":["both","bogus"]}`,
		`{"version":2,"modes":["none"]}`,
		`{"version":2,"modes":["both"],"doh":["https://dns.google/dns-query"]}`,
		`{"version":2,"modes":["both"],"doh":["http://8.8.8.8/dns-query"]}`,
		`{"version":2,"modes":["both"],"delay_ms":99999}`,
		`{"modes":["both"]}`,
	} {
		if _, err := parseStrategy([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}

	newer := `{"version":99,"modes":["slow","both"],"delay_ms":20,"slow_delay_ms":500,"doh":["https://1.1.1.1/dns-query"],"canary":["example.com"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, newer) }))
	defer srv.Close()
	oldURL, oldCache := strategyURL, strategyCachePath
	cache := filepath.Join(t.TempDir(), "strategy.json")
	strategyURL = func() string { return srv.URL }
	strategyCachePath = func() string { return cache }
	defer func() { strategyURL, strategyCachePath = oldURL, oldCache }()

	got, err := fetchStrategy(s)
	if err != nil || got == nil || got.Version != 99 {
		t.Fatalf("fetch: %v %+v", err, got)
	}
	if again, _ := fetchStrategy(got); again != nil {
		t.Error("same version fetched again")
	}
	if loaded := loadStrategy(); loaded.Version != 99 {
		t.Errorf("cached strategy not used: version %d", loaded.Version)
	}

	p := newProxy(config{mode: "auto"}, newResolver(false), nil)
	p.applyStrategy(got)
	if m := p.modesFor("example.com", true); m[0] != "slow" || p.delay() != 20*time.Millisecond {
		t.Errorf("strategy not applied: modes %v delay %s", m, p.delay())
	}
	if time.Duration(slowDelayNS.Load()) != 500*time.Millisecond {
		t.Error("slow delay not applied")
	}
	p.applyStrategy(s) // restore the global slow delay for other tests
}

// ---------------------------------------------------------------- misc

func TestUpstreamURLs(t *testing.T) {
	for _, ok := range []string{"socks5://127.0.0.1:40000", "http://u:p@proxy.example:3128", "socks5h://h:1080"} {
		if _, err := parseUpstream(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"127.0.0.1:1080", "ftp://x:1", "socks5://host", "http://h:1/path"} {
		if _, err := parseUpstream(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	u, _ := parseUpstream("http://me:secret@proxy.example:3128")
	if s := redactURL(u); strings.Contains(s, "secret") {
		t.Errorf("password shown: %s", s)
	}
	for h, local := range map[string]bool{"localhost": true, "nas": true, "printer.local": true,
		"192.168.1.1": true, "10.0.0.5": true, "example.com": false, "8.8.8.8": false} {
		if isLocalHost(h) != local {
			t.Errorf("isLocalHost(%s) = %v", h, !local)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := loadState(path)
	s.setRoute("a.example", "203.0.113.1", "chunk")
	s.learn("b.example")
	s.saveDNS("a.example", []net.IP{net.ParseIP("203.0.113.2")})
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	r := loadState(path)
	if rt, _ := r.route("a.example"); rt.Mode != "chunk" || !r.isLearned("b.example") {
		t.Fatalf("reloaded %+v", r)
	}
	// the address that worked comes before the plain DNS answer
	if ips := r.lastDNS("a.example"); len(ips) != 2 || ips[0].String() != "203.0.113.1" {
		t.Errorf("lastDNS = %v", ips)
	}
	os.WriteFile(path, []byte("{broken"), 0o644)
	if b := loadState(path); len(b.Routes) != 0 {
		t.Error("broken file not ignored")
	}
}
