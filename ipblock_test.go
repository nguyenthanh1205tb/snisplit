package main

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func serverPort(t *testing.T, addr string) int {
	t.Helper()
	_, s, _ := net.SplitHostPort(addr)
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A site whose every DNS address is blocked: the proxy moves on to other
// addresses (here from fake "IPv6" and "other region" lookups), uses the
// first that works and goes straight there next time.
func TestBlockedAddressesUseOtherAddresses(t *testing.T) {
	server, pool := tlsServer(t)
	p := proxyBehind(t, serverPort(t, server), "::1") // nothing listens on [::1]:port
	var mu sync.Mutex
	var asked []string
	ask := func(s string) { mu.Lock(); asked = append(asked, s); mu.Unlock() }
	got := func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), asked...) }
	p.alts = []altTier{
		{name: "IPv6", ips: func(_ context.Context, host string, _ int, known []net.IP) []net.IP {
			ask("IPv6")
			return []net.IP{net.ParseIP("::1")} // blocked as well
		}},
		{name: "other region", ips: func(_ context.Context, host string, _ int, known []net.IP) []net.IP {
			ask("region")
			if len(known) != 2 {
				t.Errorf("addresses already tried: %v", known)
			}
			return []net.IP{net.ParseIP("127.0.0.1")}
		}},
		{name: "never", ips: func(context.Context, string, int, []net.IP) []net.IP {
			t.Error("tier after the working one was asked")
			return nil
		}},
	}
	if err := fetchThrough(t, p, "example.com", pool); err != nil {
		t.Fatal(err)
	}
	if a := got(); len(a) != 2 || p.stats.viaOtherIP.Load() != 1 {
		t.Errorf("tiers asked %v, via other address %d", a, p.stats.viaOtherIP.Load())
	}
	if r, _ := p.state.route("example.com"); r.IP != "127.0.0.1" {
		t.Errorf("remembered %+v", r)
	}
	before := len(got())
	if err := fetchThrough(t, p, "example.com", pool); err != nil || len(got()) != before {
		t.Errorf("second request: %v, tiers asked %v", err, got())
	}
}

// Other servers of a CDN are used only when a TLS handshake shows they hold
// a valid certificate for the site.
func TestCDNServerNeedsValidCertificate(t *testing.T) {
	server, pool := tlsServer(t)
	port := serverPort(t, server)
	p := proxyBehind(t, port, "::1")
	p.edgeRoots = pool
	p.edges = map[string][]net.IP{"somecdn": {net.ParseIP("127.0.0.1")}}
	p.edgesAt = time.Now()

	ctx := context.Background()
	if got := p.edgeIPs(ctx, "example.com", port, nil); len(got) != 1 || !got[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("example.com: %v", got)
	}
	if got := p.edgeIPs(ctx, "not-on-this-cdn.test", port, nil); len(got) != 0 {
		t.Errorf("a server without the site's certificate was accepted: %v", got)
	}

	p.alts = []altTier{{name: "CDN server", https: true, ips: p.edgeIPs}}
	if err := fetchThrough(t, p, "example.com", pool); err != nil {
		t.Fatal(err)
	}
	if r, _ := p.state.route("example.com"); r.IP != "127.0.0.1" {
		t.Errorf("remembered %+v", r)
	}
}

func TestClientSubnetQuery(t *testing.T) {
	_, sub, _ := net.ParseCIDR("116.14.0.0/24")
	q := dnsQueryFor(dnsQ{"example.com", typeA, sub})
	if q[11] != 1 {
		t.Errorf("no additional record: % x", q[:12])
	}
	opt := []byte{0, 41, 0x10, 0, 0, 0, 0, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 116, 14, 0}
	if !bytes.HasSuffix(q, opt) {
		t.Errorf("OPT record % x", q[len(q)-len(opt):])
	}
	if q := dnsQueryFor(dnsQ{"example.com", typeAAAA, nil}); q[11] != 0 || q[len(q)-3] != typeAAAA {
		t.Errorf("AAAA query % x", q)
	}

	// an answer with a CNAME, an A and an AAAA record
	resp := append([]byte(nil), dnsQuery("example.com")...)
	resp[2], resp[3], resp[7] = 0x81, 0x80, 3
	resp = append(resp, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12)
	resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 50, 0, 4, 1, 2, 3, 4)
	resp = append(resp, 0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 40, 0, 16)
	resp = append(resp, net.ParseIP("2001:db8::1")...)
	ips, ttl, err := parseDNSAnswer(resp)
	if err != nil || len(ips) != 2 || ips[0].String() != "1.2.3.4" || ips[1].String() != "2001:db8::1" || ttl != 40 {
		t.Errorf("parse = %v ttl %d, %v", ips, ttl, err)
	}
}

func TestAddressHelpers(t *testing.T) {
	ip := net.ParseIP
	got := interleave([][]net.IP{{ip("1.1.1.1"), ip("1.1.1.2")}, {ip("2.2.2.2")}, {ip("1.1.1.1"), ip("3.3.3.3")}},
		[]net.IP{ip("2.2.2.2")}, 3)
	if len(got) != 3 || got[0].String() != "1.1.1.1" || got[1].String() != "1.1.1.2" || got[2].String() != "3.3.3.3" {
		t.Errorf("interleave = %v", got)
	}
	_, cf, _ := net.ParseCIDR("104.16.0.0/13")
	for _, r := range randomIPs(cf, 20) {
		if !cf.Contains(r) || r[3] == 0 || r[3] == 255 {
			t.Errorf("random address %v", r)
		}
	}
	if !nearby([]net.IP{ip("104.18.1.1")}, nil, []*net.IPNet{cf}) ||
		!nearby([]net.IP{ip("23.205.9.9")}, []net.IP{ip("23.205.214.5")}, nil) ||
		nearby([]net.IP{ip("8.8.8.8")}, []net.IP{ip("23.205.214.5")}, []*net.IPNet{cf}) {
		t.Error("nearby")
	}
}

func TestCloseness(t *testing.T) {
	site := []net.IP{net.ParseIP("23.205.214.5")}
	for ip, want := range map[string]int{"23.205.214.5": 32, "23.205.214.4": 31, "23.205.1.1": 16, "151.101.1.1": 0} {
		if got := closeness(net.ParseIP(ip), site); got != want {
			t.Errorf("closeness(%s) = %d, want %d", ip, got, want)
		}
	}
}
