package main

// When an ISP blocks a site's addresses (not just its name), splitting the
// ClientHello cannot help: the packets never get there. snisplit then looks
// for other addresses of the same site, still connecting straight to it, so
// nothing is slower and no one else's server carries the traffic:
//
//  1. its IPv6 addresses, when this computer has IPv6;
//  2. the addresses it gives people in other countries (DNS client subnet,
//     RFC 7871): CDNs such as Akamai and CloudFront answer with servers near
//     the asker, and an ISP's block list rarely has them all;
//  3. other servers of the same CDN (Cloudflare, Google, CloudFront,
//     Akamai...). Most of a CDN's servers can serve any site on it. Such an
//     address did not come from the site's DNS, so it is used only after a
//     real TLS handshake has shown it holds a valid certificate for the site.
//
// Which regions and CDNs to use comes from the strategy file, so it can be
// changed without a release.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// An altTier is one way of finding other addresses for a blocked site.
type altTier struct {
	name  string
	https bool // its addresses are checked with a TLS handshake: HTTPS only
	ips   func(ctx context.Context, host string, port int, known []net.IP) []net.IP
}

func (p *proxy) altTiers() []altTier {
	if p.alts != nil {
		return p.alts
	}
	return []altTier{
		{name: "IPv6", ips: p.ipv6IPs},
		{name: "other region", ips: p.regionIPs},
		{name: "CDN server", https: true, ips: p.edgeIPs},
	}
}

// ---------------------------------------------------------------- IPv6

var v6 struct {
	sync.Mutex
	ok bool
	at time.Time
}

// hasIPv6 reports whether this computer has a route to the IPv6 internet.
// Connecting a UDP socket sends nothing; it only picks a route.
func hasIPv6() bool {
	v6.Lock()
	defer v6.Unlock()
	if time.Since(v6.at) < time.Minute {
		return v6.ok
	}
	v6.ok, v6.at = false, time.Now()
	if c, err := net.Dial("udp", "[2001:4860:4860::8888]:53"); err == nil {
		ip := c.LocalAddr().(*net.UDPAddr).IP
		v6.ok = ip.IsGlobalUnicast() && !ip.IsPrivate()
		c.Close()
	}
	return v6.ok
}

func (p *proxy) ipv6IPs(ctx context.Context, host string, _ int, _ []net.IP) []net.IP {
	if !p.res.useDoH || !hasIPv6() {
		return nil
	}
	ips, _ := p.res.lookupAlt(ctx, host, typeAAAA, nil)
	ips = usable(ips)
	rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
	return ips[:min(2, len(ips))]
}

// ---------------------------------------------------------------- other regions

func (p *proxy) regions() []*net.IPNet {
	var out []*net.IPNet
	for _, r := range p.strat.Load().Regions {
		if _, n, err := net.ParseCIDR(r); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// regionIPs asks for host's addresses as if from each region at once and
// returns up to four that are new, taking one from each region in turn.
func (p *proxy) regionIPs(ctx context.Context, host string, _ int, known []net.IP) []net.IP {
	if !p.res.useDoH {
		return nil
	}
	regions := p.regions()
	answers := make([][]net.IP, len(regions))
	var wg sync.WaitGroup
	for i, sub := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ips, _ := p.res.lookupAlt(ctx, host, typeA, sub)
			answers[i] = usable(ips)
		}()
	}
	wg.Wait()
	return interleave(answers, known, 4)
}

// interleave takes one new address from each list in turn, up to n.
func interleave(lists [][]net.IP, known []net.IP, n int) []net.IP {
	seen := map[string]bool{}
	for _, ip := range known {
		seen[ip.String()] = true
	}
	var out []net.IP
	for round := 0; len(out) < n; round++ {
		more := false
		for _, l := range lists {
			if round >= len(l) {
				continue
			}
			more = true
			if s := l[round].String(); !seen[s] && len(out) < n {
				seen[s] = true
				out = append(out, l[round])
			}
		}
		if !more {
			break
		}
	}
	return out
}

// ---------------------------------------------------------------- CDN servers

// edgePools returns live server addresses of each CDN in the strategy file:
// the addresses of its sample host names (asked from here and from two other
// regions) plus a few random addresses from its ranges. Refreshed every 6 h.
func (p *proxy) edgePools(ctx context.Context) map[string][]net.IP {
	p.edgeMu.Lock()
	defer p.edgeMu.Unlock()
	if p.edges != nil && time.Since(p.edgesAt) < 6*time.Hour || !p.res.useDoH {
		return p.edges
	}
	subnets := []*net.IPNet{nil}
	if r := p.regions(); len(r) > 0 {
		subnets = append(subnets, r[:min(2, len(r))]...)
	}
	pools := map[string][]net.IP{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for cdn, entries := range p.strat.Load().Edges {
		for _, e := range entries {
			if _, n, err := net.ParseCIDR(e); err == nil {
				mu.Lock()
				pools[cdn] = append(pools[cdn], randomIPs(n, 4)...)
				mu.Unlock()
				continue
			}
			for _, sub := range subnets {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ips, _ := p.res.lookupAlt(ctx, e, typeA, sub)
					mu.Lock()
					pools[cdn] = append(pools[cdn], usable(ips)...)
					mu.Unlock()
				}()
			}
		}
	}
	wg.Wait()
	found := false
	for cdn, ips := range pools {
		pools[cdn] = uniqueIPs(ips)
		found = found || len(pools[cdn]) > 0
	}
	if found {
		p.edges, p.edgesAt = pools, time.Now()
	}
	return p.edges
}

// edgeIPs returns up to two servers of the site's CDN that proved, with a TLS
// handshake, to hold a valid certificate for host. CDNs whose addresses look
// like the site's own are tried first, but the handshake decides.
func (p *proxy) edgeIPs(ctx context.Context, host string, port int, known []net.IP) []net.IP {
	pools := p.edgePools(ctx)
	if len(pools) == 0 {
		return nil
	}
	ranges := map[string][]*net.IPNet{}
	for cdn, entries := range p.strat.Load().Edges {
		for _, e := range entries {
			if _, n, err := net.ParseCIDR(e); err == nil {
				ranges[cdn] = append(ranges[cdn], n)
			}
		}
	}
	type cdnPool struct {
		name string
		near bool
		ips  []net.IP
	}
	var cdns []cdnPool
	for name, ips := range pools {
		cdns = append(cdns, cdnPool{name, nearby(known, ips, ranges[name]), ips})
	}
	sort.Slice(cdns, func(i, j int) bool {
		if cdns[i].near != cdns[j].near {
			return cdns[i].near
		}
		return cdns[i].name < cdns[j].name
	})
	skip := map[string]bool{}
	for _, ip := range known {
		skip[ip.String()] = true
	}
	var cands []net.IP
	for _, c := range cdns {
		ips := append([]net.IP(nil), c.ips...)
		rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
		// Servers with addresses close to the site's own are the likeliest
		// to carry it (a CDN such as Akamai is split into separate networks).
		sort.SliceStable(ips, func(i, j int) bool { return closeness(ips[i], known) > closeness(ips[j], known) })
		n := 3
		if c.near {
			n = 5
		}
		for _, ip := range ips {
			if n == 0 || len(cands) == 14 {
				break
			}
			if !skip[ip.String()] {
				cands = append(cands, ip)
				n--
			}
		}
	}

	mode := p.probeMode(host)
	vctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	ok := make(chan net.IP, len(cands))
	var wg sync.WaitGroup
	for _, ip := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p.verifyEdge(vctx, ip, host, port, mode) {
				ok <- ip
			}
		}()
	}
	go func() { wg.Wait(); close(ok) }()
	var out []net.IP
	for ip := range ok {
		if out = append(out, ip); len(out) == 2 {
			break
		}
	}
	return out
}

// verifyEdge does a TLS handshake for host with ip, split the same way as
// the real connection will be, and checks the certificate.
func (p *proxy) verifyEdge(ctx context.Context, ip net.IP, host string, port int, mode string) bool {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil || testBlocked != nil && testBlocked(ip) {
		return false
	}
	defer c.Close()
	tc := tls.Client(&splitConn{Conn: c, mode: mode, delay: p.delay()},
		&tls.Config{ServerName: host, RootCAs: p.edgeRoots, NextProtos: []string{"h2", "http/1.1"}})
	return tc.HandshakeContext(ctx) == nil
}

// probeMode is the split method to use for host's test handshakes.
func (p *proxy) probeMode(host string) string {
	if r, ok := p.state.route(host); ok && r.Mode != "" && r.Mode != "none" && r.Mode != "upstream" {
		return r.Mode
	}
	if p.cfg.mode != "auto" {
		return p.cfg.mode
	}
	if b, _ := p.best.Load().(string); b != "" && b != "none" {
		return b
	}
	return p.strat.Load().Modes[0]
}

// nearby reports whether any of the site's addresses is in one of the CDN's
// ranges or in the same /16 as one of its known servers.
func nearby(site, pool []net.IP, ranges []*net.IPNet) bool {
	prefixes := map[[2]byte]bool{}
	for _, ip := range pool {
		if v4 := ip.To4(); v4 != nil {
			prefixes[[2]byte{v4[0], v4[1]}] = true
		}
	}
	for _, ip := range site {
		for _, n := range ranges {
			if n.Contains(ip) {
				return true
			}
		}
		if v4 := ip.To4(); v4 != nil && prefixes[[2]byte{v4[0], v4[1]}] {
			return true
		}
	}
	return false
}

// closeness is how many leading bits ip shares with the closest of site's
// IPv4 addresses (0 to 32).
func closeness(ip net.IP, site []net.IP) int {
	a := ip.To4()
	if a == nil {
		return 0
	}
	best := 0
	for _, s := range site {
		b := s.To4()
		if b == nil {
			continue
		}
		x := binary.BigEndian.Uint32(a) ^ binary.BigEndian.Uint32(b)
		n := 32
		for ; x != 0; x >>= 1 {
			n--
		}
		best = max(best, n)
	}
	return best
}

// randomIPs picks k addresses in n, avoiding .0 and .255.
func randomIPs(n *net.IPNet, k int) []net.IP {
	base := n.IP.To4()
	if base == nil {
		return nil
	}
	ones, _ := n.Mask.Size()
	size := int64(1) << (32 - ones)
	var out []net.IP
	for i := 0; i < k*4 && len(out) < k; i++ {
		v := binary.BigEndian.Uint32(base) + uint32(rand.Int63n(size))
		if b := byte(v); b == 0 || b == 255 {
			continue
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, v)
		out = append(out, ip)
	}
	return out
}

func uniqueIPs(ips []net.IP) []net.IP {
	seen := map[string]bool{}
	var out []net.IP
	for _, ip := range ips {
		if s := ip.String(); !seen[s] {
			seen[s] = true
			out = append(out, ip)
		}
	}
	return out
}

// ---------------------------------------------------------------- dialling

// testBlocked makes addresses unreachable in live tests; nil otherwise.
var testBlocked func(net.IP) bool

type dialResult struct {
	ip  net.IP
	c   net.Conn
	err error
}

// dialStaggered connects to ips in order, starting the next one when the
// previous has failed or not answered within 400 ms, so a dead address costs
// little and a working one is not raced needlessly. Results arrive in the
// order connections complete. The caller must call stop, which also closes
// connections it did not take.
func dialStaggered(ctx context.Context, ips []net.IP, port int, timeout time.Duration) (results <-chan dialResult, stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	out := make(chan dialResult, len(ips))
	failed := make(chan struct{}, len(ips))
	go func() {
		var wg sync.WaitGroup
		for _, ip := range ips {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				d := net.Dialer{Timeout: timeout}
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
				if err == nil && testBlocked != nil && testBlocked(ip) {
					c.Close()
					c, err = nil, errors.New("blocked (test)")
				}
				if err != nil {
					failed <- struct{}{}
				}
				out <- dialResult{ip, c, err}
			}()
			select {
			case <-ctx.Done():
			case <-failed:
			case <-time.After(400 * time.Millisecond):
			}
		}
		wg.Wait()
		close(out)
	}()
	stop = func() {
		cancel()
		go func() {
			for r := range out {
				if r.c != nil {
					r.c.Close()
				}
			}
		}()
	}
	return out, stop
}
