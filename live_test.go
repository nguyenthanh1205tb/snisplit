package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Tests against the real internet. Run with SNISPLIT_LIVE=1 go test -run Live -v
func TestLiveDoHServers(t *testing.T) {
	if os.Getenv("SNISPLIT_LIVE") == "" {
		t.Skip("set SNISPLIT_LIVE=1 to query the real DoH servers")
	}
	r := newResolver(true)
	ok := 0
	for _, ep := range defaultDoH {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		start := time.Now()
		ips, ttl, err := r.doh(ctx, ep, dnsQ{host: "store.steampowered.com", qtype: typeA})
		cancel()
		if err != nil || len(ips) == 0 {
			t.Logf("%-36s FAILED: %v", ep, err) // one provider down is what the list is for
			continue
		}
		ok++
		t.Logf("%-36s %v ttl %d (%d ms)", ep, ips, ttl, time.Since(start).Milliseconds())
	}
	if ok < len(defaultDoH)/2 {
		t.Errorf("only %d of %d DoH servers answer", ok, len(defaultDoH))
	}
}

// TestLiveBlockedAddresses pretends every address DNS gives for a site is
// blocked and shows which way of finding another one gets through.
func TestLiveBlockedAddresses(t *testing.T) {
	if os.Getenv("SNISPLIT_LIVE") == "" {
		t.Skip("set SNISPLIT_LIVE=1 to test against real sites")
	}
	hosts := []string{"store.steampowered.com", "steamcommunity.com", "steamcdn-a.akamaihd.net",
		"discord.com", "www.youtube.com", "aws.amazon.com", "www.microsoft.com", "github.com"}
	if h := os.Getenv("SNISPLIT_HOSTS"); h != "" {
		hosts = strings.Split(h, ",")
	}
	defer func() { testBlocked = nil }()
	works := 0
	for _, host := range hosts {
		res := newResolver(true)
		real, err := res.lookup(context.Background(), host)
		if err != nil {
			t.Logf("%-26s DNS: %v", host, err)
			continue
		}
		blocked := map[string]bool{}
		for _, ip := range real {
			blocked[ip.String()] = true
		}
		testBlocked = func(ip net.IP) bool { return blocked[ip.String()] }
		cfg := config{listen: "127.0.0.1", mode: "auto", timeout: 10 * time.Second, names: []string{host}, verbose: os.Getenv("SNISPLIT_VERBOSE") != ""}
		base := newProxy(cfg, res, nil)
		base.applyStrategy(loadStrategy())
		for _, tier := range base.altTiers() {
			p := newProxy(cfg, res, nil)
			p.applyStrategy(loadStrategy())
			p.alts = []altTier{tier}
			if tier.name == "CDN server" {
				p.alts[0].ips = p.edgeIPs
			}
			start := time.Now()
			via, err := liveFetch(p, host)
			if err != nil {
				t.Logf("%-26s %-13s no   (%v)", host, tier.name, err)
				continue
			}
			works++
			t.Logf("%-26s %-13s YES  %s, %d ms", host, tier.name, via, time.Since(start).Milliseconds())
		}
	}
	if works == 0 {
		t.Error("no blocked site got through")
	}
}

func liveFetch(p *proxy, host string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	go p.serve(ln, p.handleTransparentTLS)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: host})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	io.WriteString(conn, "HEAD / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	r, _ := p.state.route(host)
	return fmt.Sprintf("HTTP %d from %s (%s)", resp.StatusCode, r.IP, r.Mode), nil
}
