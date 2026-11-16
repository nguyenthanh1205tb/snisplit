package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// defaultDoH are DNS-over-HTTPS (RFC 8484) servers addressed by IP, so using
// them needs no DNS and sends no server name for an ISP to filter. They belong
// to different companies, so blocking one or two changes nothing.
var defaultDoH = []string{
	"https://8.8.8.8/dns-query",         // Google
	"https://1.1.1.1/dns-query",         // Cloudflare
	"https://8.8.4.4/dns-query",         // Google
	"https://1.0.0.1/dns-query",         // Cloudflare
	"https://94.140.14.14/dns-query",    // AdGuard
	"https://208.67.222.222/dns-query",  // OpenDNS
	"https://185.222.222.222/dns-query", // DNS.SB
	"https://9.9.9.9/dns-query",         // Quad9
}

// resolver looks hosts up over DoH (with a cache), then the system resolver,
// then the last answer that ever worked. Loopback answers are discarded: ISP
// DNS answers 127.0.0.1 for blocked sites, and our hosts file does the same.
type resolver struct {
	useDoH   bool
	client   *http.Client
	state    *state                     // last good answers; may be nil
	override func(host string) []net.IP // tests only

	mu        sync.Mutex
	endpoints []string
	fails     map[string]int // consecutive failures per endpoint
	cache     map[string]cacheEntry
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func newResolver(useDoH bool) *resolver {
	tr := &http.Transport{
		Proxy:               nil, // never send DNS queries through a proxy
		TLSHandshakeTimeout: 5 * time.Second,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}
	return &resolver{
		useDoH:    useDoH,
		client:    &http.Client{Timeout: 6 * time.Second, Transport: tr},
		endpoints: defaultDoH,
		fails:     map[string]int{},
		cache:     map[string]cacheEntry{},
	}
}

// setEndpoints replaces the DoH servers (from the strategy file).
func (r *resolver) setEndpoints(eps []string) {
	if len(eps) == 0 {
		return
	}
	r.mu.Lock()
	r.endpoints = eps
	r.mu.Unlock()
}

// ordered returns the endpoints, the ones failing least first.
func (r *resolver) ordered() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	eps := append([]string(nil), r.endpoints...)
	sort.SliceStable(eps, func(i, j int) bool { return r.fails[eps[i]] < r.fails[eps[j]] })
	return eps
}

func (r *resolver) mark(ep string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		delete(r.fails, ep)
	} else {
		r.fails[ep]++
	}
}

func (r *resolver) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if r.override != nil {
		if ips := r.override(host); ips != nil {
			return ips, nil
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")

	r.mu.Lock()
	e, ok := r.cache[host]
	r.mu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.ips, nil
	}

	var dohErr error
	if r.useDoH {
		ips, ttl, err := r.dohAny(ctx, dnsQ{host: host, qtype: typeA}, r.ordered())
		if err == nil {
			r.remember(host, ips, ttl)
			return ips, nil
		}
		if errors.Is(err, errNXDomain) {
			return nil, fmt.Errorf("%s: no such host", host)
		}
		dohErr = err
	}

	var ips []net.IP
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	if ips = usable(ips); len(ips) > 0 {
		if !r.useDoH { // with DoH failing, system DNS may be the ISP's: do not remember it
			r.remember(host, ips, 300)
		}
		return ips, nil
	}
	if r.state != nil {
		if ips := r.state.lastDNS(host); len(ips) > 0 {
			return ips, nil
		}
	}
	switch {
	case err != nil && dohErr != nil:
		return nil, fmt.Errorf("DoH: %v; system DNS: %v", dohErr, err)
	case err != nil:
		return nil, err
	}
	return nil, fmt.Errorf("DNS for %s returned only loopback addresses (ISP DNS block or hosts file) and DoH failed: %v", host, dohErr)
}

func (r *resolver) remember(host string, ips []net.IP, ttl int) {
	ttl = min(max(ttl, 30), 3600)
	r.mu.Lock()
	r.cache[host] = cacheEntry{ips, time.Now().Add(time.Duration(ttl) * time.Second)}
	r.mu.Unlock()
	if r.state != nil {
		r.state.saveDNS(host, ips)
	}
}

var errNXDomain = errors.New("no such host")

// dnsQ is one question: host's A or AAAA records, optionally as seen from
// another network (EDNS client subnet).
type dnsQ struct {
	host   string
	qtype  uint16
	subnet *net.IPNet
}

const (
	typeA    = 1
	typeAAAA = 28
)

// googleDoH honour a client subnet sent with the query, so they can answer
// as if the question came from another country.
var googleDoH = []string{"https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"}

// lookupAlt asks DoH only (no system DNS, no saved answers) for host's AAAA
// records, or for its A records as seen from subnet. Answers are cached.
func (r *resolver) lookupAlt(ctx context.Context, host string, qtype uint16, subnet *net.IPNet) ([]net.IP, error) {
	if !r.useDoH {
		return nil, errors.New("DoH is off")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	key := fmt.Sprintf("%s|%d|%v", host, qtype, subnet)
	r.mu.Lock()
	e, ok := r.cache[key]
	r.mu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.ips, nil
	}
	eps := r.ordered()
	if subnet != nil {
		eps = googleDoH
	}
	ips, ttl, err := r.dohAny(ctx, dnsQ{host, qtype, subnet}, eps)
	if errors.Is(err, errNXDomain) {
		ips, ttl, err = nil, 300, nil
	}
	if err != nil {
		return nil, err
	}
	ttl = min(max(ttl, 60), 3600)
	r.mu.Lock()
	r.cache[key] = cacheEntry{ips, time.Now().Add(time.Duration(ttl) * time.Second)}
	r.mu.Unlock()
	return ips, nil
}

// dohAny asks the endpoints two at a time, healthiest first, and returns the
// first usable answer.
func (r *resolver) dohAny(ctx context.Context, q dnsQ, eps []string) ([]net.IP, int, error) {
	type result struct {
		ep  string
		ips []net.IP
		ttl int
		err error
	}
	var lastErr error
	for i := 0; i < len(eps); i += 2 {
		batch := eps[i:min(i+2, len(eps))]
		bctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ch := make(chan result, len(batch))
		for _, ep := range batch {
			go func(ep string) {
				ips, ttl, err := r.doh(bctx, ep, q)
				ch <- result{ep, ips, ttl, err}
			}(ep)
		}
		var found *result
		for range batch {
			res := <-ch
			if found != nil { // the slower one was cancelled: not its fault
				continue
			}
			r.mark(res.ep, res.err == nil || errors.Is(res.err, errNXDomain))
			if res.err != nil {
				lastErr = res.err
				continue
			}
			if res.ips = usable(res.ips); len(res.ips) > 0 || q.qtype != typeA {
				found = &res
				cancel()
			}
		}
		cancel()
		if found != nil {
			return found.ips, found.ttl, nil
		}
		if errors.Is(lastErr, errNXDomain) {
			return nil, 0, errNXDomain
		}
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no usable address")
	}
	return nil, 0, lastErr
}

// doh sends one RFC 8484 GET query.
func (r *resolver) doh(ctx context.Context, endpoint string, q dnsQ) ([]net.IP, int, error) {
	msg, err := r.dohRaw(ctx, endpoint, dnsQueryFor(q))
	if err != nil {
		return nil, 0, err
	}
	return parseDNSAnswer(msg)
}

// dohRaw sends a DNS message (ID 0) to endpoint and returns the response.
func (r *resolver) dohRaw(ctx context.Context, endpoint string, query []byte) ([]byte, error) {
	u := endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s: HTTP %d", endpoint, resp.StatusCode)
	}
	msg, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if len(msg) < 12 {
		return nil, errors.New("short DNS response")
	}
	return msg, nil
}

// exchange forwards any DNS query over DoH, two servers at a time,
// healthiest first, and returns the first response with the query's ID.
func (r *resolver) exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("short DNS query")
	}
	q := append([]byte(nil), query...)
	q[0], q[1] = 0, 0 // RFC 8484: ID 0 keeps responses cacheable
	type result struct {
		ep  string
		msg []byte
		err error
	}
	var lastErr error
	eps := r.ordered()
	for i := 0; i < len(eps); i += 2 {
		batch := eps[i:min(i+2, len(eps))]
		bctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ch := make(chan result, len(batch))
		for _, ep := range batch {
			go func() {
				msg, err := r.dohRaw(bctx, ep, q)
				ch <- result{ep, msg, err}
			}()
		}
		var found []byte
		for range batch {
			res := <-ch
			if found != nil {
				continue
			}
			r.mark(res.ep, res.err == nil)
			if res.err != nil {
				lastErr = res.err
				continue
			}
			found = res.msg
			cancel()
		}
		cancel()
		if found != nil {
			found[0], found[1] = query[0], query[1]
			return found, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no DoH server answered")
	}
	return nil, lastErr
}

// dnsQuery builds a DNS query (ID 0, recursion desired) for host's A records.
func dnsQuery(host string) []byte { return dnsQueryFor(dnsQ{host: host, qtype: typeA}) }

// dnsQueryFor builds the query for q, with an EDNS client subnet option
// (RFC 7871) when q.subnet is set.
func dnsQueryFor(q dnsQ) []byte {
	b := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(q.host, "."), ".") {
		if len(label) > 63 {
			label = label[:63]
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, byte(q.qtype>>8), byte(q.qtype), 0, 1) // root, QTYPE, QCLASS IN
	if q.subnet == nil || q.subnet.IP.To4() == nil {
		return b
	}
	bits, _ := q.subnet.Mask.Size()
	opt := append([]byte{0, 1, byte(bits), 0}, q.subnet.IP.To4()[:(bits+7)/8]...) // family IPv4, source prefix, scope 0
	opt = append([]byte{0, 8, 0, byte(len(opt))}, opt...)                         // option 8: client subnet
	b[11] = 1                                                                     // one additional record: OPT
	b = append(b, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, byte(len(opt)))               // root, OPT, 4096-byte UDP, no flags
	return append(b, opt...)
}

// parseDNSAnswer returns the A and AAAA records of a DNS response and their
// lowest TTL.
func parseDNSAnswer(msg []byte) (ips []net.IP, ttl int, err error) {
	defer func() {
		if recover() != nil {
			ips, ttl, err = nil, 0, errors.New("malformed DNS response")
		}
	}()
	if len(msg) < 12 {
		return nil, 0, errors.New("short DNS response")
	}
	switch msg[3] & 0x0f {
	case 0:
	case 3:
		return nil, 0, errNXDomain
	default:
		return nil, 0, fmt.Errorf("DNS error code %d", msg[3]&0x0f)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	p := 12
	for i := 0; i < qd; i++ {
		p = skipDNSName(msg, p) + 4
	}
	ttl = 3600
	for i := 0; i < an; i++ {
		p = skipDNSName(msg, p)
		typ := binary.BigEndian.Uint16(msg[p:])
		t := int(binary.BigEndian.Uint32(msg[p+4:]))
		l := int(binary.BigEndian.Uint16(msg[p+8:]))
		p += 10
		switch {
		case typ == typeA && l == 4:
			ips = append(ips, net.IPv4(msg[p], msg[p+1], msg[p+2], msg[p+3]))
			ttl = min(ttl, t)
		case typ == typeAAAA && l == 16:
			ips = append(ips, net.IP(append([]byte(nil), msg[p:p+16]...)))
			ttl = min(ttl, t)
		}
		p += l
	}
	return ips, ttl, nil
}

func skipDNSName(msg []byte, p int) int {
	for {
		l := int(msg[p])
		switch {
		case l == 0:
			return p + 1
		case l&0xc0 == 0xc0: // compression pointer ends the name
			return p + 2
		}
		p += 1 + l
	}
}

// usable drops loopback/unspecified addresses and puts IPv4 first.
func usable(ips []net.IP) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return append(v4, v6...)
}
