package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	names := []string{"a.example", "b.example"}
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
	steam, err := loadNames("steam", "")
	if err != nil || len(exactNames(steam)) < 30 {
		t.Fatalf("steam preset: %v (%d)", err, len(steam))
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
