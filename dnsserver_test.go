package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// dnsTestProxy returns a proxy and DNS server whose DoH server answers every
// A query with 10.9.9.9 and 203.0.113.9 (and counts the queries it gets).
func dnsTestProxy(t *testing.T, names ...string) (*proxy, *dnsServer, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	doh := dohServer(t, "203.0.113.9", hits)
	res := newResolver(true)
	res.client = doh.Client()
	p := newProxy(config{listen: "127.0.0.1", mode: "auto", transparent: true, names: names}, res, loadState(filepath.Join(t.TempDir(), "s.json")))
	res.setEndpoints([]string{doh.URL + "/dns-query"}) // newProxy applied the real ones
	d := &dnsServer{p: p, probes: make(chan struct{}, 8), cache: map[string]dnsCached{}, checked: map[string]time.Time{}}
	d.setFallback(nil)
	return p, d, hits
}

func query(name string, qtype uint16) []byte {
	q := dnsQueryFor(dnsQ{host: name, qtype: qtype})
	rand.Read(q[:2])
	return q
}

func answers(t *testing.T, resp []byte) []string {
	t.Helper()
	ips, _, err := parseDNSAnswer(resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func mustParse(t *testing.T, q []byte) dnsQuestion {
	t.Helper()
	pq, ok := parseQuestion(q)
	if !ok {
		t.Fatal("parseQuestion failed")
	}
	return pq
}

func TestDNSServerAnswers(t *testing.T) {
	p, d, hits := dnsTestProxy(t, ".steampowered.com")
	b := newBlocker()
	b.setList(map[string]struct{}{"ads.example": {}}, "test", time.Now())
	p.ads.Store(b)
	p.state.learn("blocked.example")
	d.checked["plain.example"] = time.Now() // no SNI check in this test

	q := query("plain.example", typeA)
	resp := d.handle(q, true)
	if !bytes.Equal(resp[:2], q[:2]) || resp[2]&0x80 == 0 {
		t.Fatalf("not a response to the query: % x", resp[:4])
	}
	if got := answers(t, resp); len(got) != 2 || got[1] != "203.0.113.9" {
		t.Errorf("forwarded answer %v", got)
	}
	before := hits.Load()
	q2 := query("plain.example", typeA)
	if resp := d.handle(q2, true); !bytes.Equal(resp[:2], q2[:2]) || hits.Load() != before {
		t.Errorf("second lookup not from the cache (DoH hits %d -> %d)", before, hits.Load())
	}

	for _, tc := range []struct {
		name  string
		qtype uint16
		want  []string
	}{
		{"ads.example", typeA, []string{"0.0.0.0"}},
		{"sub.ads.example", typeAAAA, []string{"::"}},
		{"store.steampowered.com", typeA, []string{"127.0.0.1"}},
		{"store.steampowered.com", typeAAAA, nil}, // no IPv6: apps then use 127.0.0.1
		{"blocked.example", typeA, []string{"127.0.0.1"}},
		{"blocked.example", 65, nil}, // HTTPS record: none, so browsers take the A answer
	} {
		got := answers(t, d.handle(query(tc.name, tc.qtype), true))
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s type %d: %v, want %v", tc.name, tc.qtype, got, tc.want)
		}
	}
	if s := d.stats(); s.AdsBlocked != 2 || s.Redirected != 4 || s.Queries != 8 {
		t.Errorf("stats %+v", s)
	}
}

func TestDNSServerEdgeCases(t *testing.T) {
	_, d, _ := dnsTestProxy(t)
	if d.handle([]byte{1, 2, 3}, true) != nil {
		t.Error("answered a runt packet")
	}
	q := query("x.example", typeA)
	q[2] |= 0x80 // a response, not a query
	if d.handle(q, true) != nil {
		t.Error("answered a response")
	}
	bad := query("x.example", typeA)
	binary.BigEndian.PutUint16(bad[4:], 2) // two questions
	if r := d.handle(bad, true); r == nil || r[3]&0x0f != 1 {
		t.Errorf("two questions: % x", r)
	}

	// a UDP answer too big for the client is cut short with TC set
	bq := query("big.example", typeA)
	var rrs []dnsRR
	for i := 0; i < 40; i++ {
		rrs = append(rrs, dnsRR{typeA, 300, []byte{10, 0, 0, byte(i)}})
	}
	d.cache["big.example|1|1"] = dnsCached{reply(bq, mustParse(t, bq), 0, rrs...), time.Now().Add(time.Minute)}
	d.checked["big.example"] = time.Now()
	r := d.handle(query("big.example", typeA), true)
	if r[2]&0x02 == 0 || len(r) > 512 {
		t.Errorf("not truncated: %d bytes, flags % x", len(r), r[2:4])
	}
	if r := d.handle(query("big.example", typeA), false); r[2]&0x02 != 0 || len(answers(t, r)) != 40 {
		t.Error("TCP answer truncated")
	}
}

// A name nobody listed: a straight TLS handshake is cut off, a split one is
// answered, so it is blocked by its SNI.
func TestSNIBlockCheck(t *testing.T) {
	server, _ := tlsServer(t)
	isp := startFakeISP(t, "127.0.0.1:0", perPacket, 0, server) // resets "example.com"
	p, d, _ := dnsTestProxy(t)
	p.cfg.tlsPort = isp.port()
	lo := net.ParseIP("127.0.0.1")
	if p.tlsAnswers(lo, "example.com", isp.port(), "none") != errCutOff {
		t.Fatal("the fake ISP did not cut the straight handshake")
	}
	if !p.sniBlocked("example.com", lo) {
		t.Fatal("block not found")
	}
	if p.sniBlocked("other.test", lo) {
		t.Error("an unblocked name was reported blocked")
	}
	// an answer with only private or unreachable addresses is not checked
	q := query("lan.example", typeA)
	resp := reply(q, mustParse(t, q), 0, dnsRR{typeA, 300, []byte{192, 168, 1, 9}})
	if blocked, pending := d.check("lan.example", resp); blocked || pending {
		t.Error("checked a private address")
	}
	if !d.shouldCheck("new.example") || d.shouldCheck("new.example") || d.shouldCheck("printer.local") {
		t.Error("shouldCheck")
	}
}

func TestMinAndCapTTL(t *testing.T) {
	q := query("a.example", typeA)
	r := reply(q, mustParse(t, q), 0, dnsRR{typeA, 300, []byte{1, 2, 3, 4}}, dnsRR{typeA, 90, []byte{5, 6, 7, 8}})
	if got := minTTL(r); got != 90 {
		t.Errorf("minTTL = %d", got)
	}
	if got := minTTL(capTTL(r, 20)); got != 20 {
		t.Errorf("capTTL: minTTL = %d", got)
	}
	if got := minTTL(reply(q, mustParse(t, q), 3)); got != 60 {
		t.Errorf("no answers: %d", got)
	}
	for i := range r { // truncated input must not panic
		minTTL(r[:i])
		capTTL(r[:i], 1)
	}
}

func TestExchangeKeepsID(t *testing.T) {
	var hits atomic.Int32
	doh := dohServer(t, "203.0.113.9", &hits)
	r := newResolver(true)
	r.client = doh.Client()
	r.setEndpoints([]string{doh.URL + "/dns-query"})
	q := query("a.example", typeA)
	resp, err := r.exchange(t.Context(), q)
	if err != nil || !bytes.Equal(resp[:2], q[:2]) {
		t.Fatalf("exchange: %v", err)
	}
}

func TestDNSFallbacks(t *testing.T) {
	got := dnsFallbacks([]adapterDNS{{Used: []string{"127.0.0.1", "192.168.1.1", "8.8.8.8"}}, {Used: []string{"8.8.8.8", "::1", "fe80::1"}}})
	if strings.Join(got, ",") != "192.168.1.1:53,8.8.8.8:53,[fe80::1]:53" {
		t.Errorf("fallbacks %v", got)
	}
}

// ---------------------------------------------------------------- sharing

func TestLocalPeer(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "192.168.1.20": true, "10.0.0.5": true, "172.20.1.1": true,
		"fe80::1": true, "fd00::5": true, "8.8.8.8": false, "100.64.0.1": false, "2001:db8::1": false,
	} {
		if got := localPeer(&net.TCPAddr{IP: net.ParseIP(addr)}); got != want {
			t.Errorf("localPeer(%s) = %v", addr, got)
		}
	}
}

// fakeRemote makes a loopback connection look like it comes from remote.
type fakeRemote struct {
	net.Conn
	remote string
}

func (f fakeRemote) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", f.remote)
	return a
}

func TestPhonePageAndPAC(t *testing.T) {
	p := newProxy(config{listen: "127.0.0.1", port: 8881, share: true}, newResolver(false), nil)
	get := func(path, host, remote string) string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
				p.handleLocal(fakeRemote{c, remote}, req)
			}
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
		b, _ := io.ReadAll(c)
		return string(b)
	}
	if out := get("/proxy.pac?all=1", "192.168.1.5:8881", "192.168.1.30:5555"); !strings.Contains(out, "PROXY 192.168.1.5:8881; DIRECT") {
		t.Errorf("phone PAC:\n%s", out)
	}
	if out := get("/proxy.pac?all=1", "127.0.0.1:8881", "127.0.0.1:5555"); !strings.Contains(out, "PROXY 127.0.0.1:8881; DIRECT") {
		t.Errorf("local PAC:\n%s", out)
	}
	if out := get(statusPath, "192.168.1.5:8881", "192.168.1.30:5555"); !strings.HasPrefix(out, "HTTP/1.1 403") {
		t.Errorf("status open to the network:\n%.80s", out)
	}
	if lanIP() != nil {
		if out := get(phonePath, "192.168.1.5:8881", "192.168.1.30:5555"); !strings.Contains(out, "/proxy.pac?all=1") || strings.Contains(out, phoneQRPath) {
			t.Errorf("phone page on the phone:\n%.300s", out)
		}
		if out := get(phonePath, "127.0.0.1:8881", "127.0.0.1:5555"); !strings.Contains(out, phoneQRPath) {
			t.Errorf("phone page on this computer has no QR code:\n%.300s", out)
		}
		if out := get(phoneQRPath, "127.0.0.1:8881", "127.0.0.1:5555"); !strings.Contains(out, "image/png") || !strings.Contains(out, "\x89PNG") {
			t.Errorf("QR code:\n%.120q", out)
		}
	}
	var buf bytes.Buffer
	printQR(&buf, "http://192.168.1.5:8881/snisplit/phone")
	if lines := strings.Count(buf.String(), "\n"); lines < 12 {
		t.Errorf("terminal QR has %d lines", lines)
	}
}
