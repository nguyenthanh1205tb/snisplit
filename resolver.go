package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// dohEndpoints are DNS-over-HTTPS JSON APIs addressed by IP, so resolving them
// needs no DNS and they cannot be poisoned by the ISP or by our own hosts file.
var dohEndpoints = []string{
	"https://8.8.8.8/resolve?type=A&name=",
	"https://1.1.1.1/dns-query?type=A&name=",
}

// resolver looks hosts up over DoH (with a cache), falling back to the system
// resolver. Loopback answers are discarded: ISP DNS answers 127.0.0.1 for
// blocked sites, and our hosts file does the same on purpose.
type resolver struct {
	useDoH   bool
	client   *http.Client
	mu       sync.Mutex
	cache    map[string]cacheEntry
	override func(host string) []net.IP // tests only
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
		MaxIdleConnsPerHost: 4,
	}
	return &resolver{
		useDoH: useDoH,
		client: &http.Client{Timeout: 6 * time.Second, Transport: tr},
		cache:  map[string]cacheEntry{},
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
		for _, ep := range dohEndpoints {
			ips, ttl, err := r.doh(ctx, ep+url.QueryEscape(host))
			if err != nil {
				dohErr = err
				continue
			}
			if ips = usable(ips); len(ips) > 0 {
				ttl = min(max(ttl, 30), 3600)
				r.mu.Lock()
				r.cache[host] = cacheEntry{ips, time.Now().Add(time.Duration(ttl) * time.Second)}
				r.mu.Unlock()
				return ips, nil
			}
		}
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		if dohErr != nil {
			return nil, fmt.Errorf("DoH: %v; system DNS: %v", dohErr, err)
		}
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	if ips = usable(ips); len(ips) == 0 {
		return nil, fmt.Errorf("DNS for %s returned only loopback addresses (ISP DNS block or hosts file) and DoH failed: %v", host, dohErr)
	}
	return ips, nil
}

func (r *resolver) doh(ctx context.Context, u string) ([]net.IP, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	var body struct {
		Answer []struct {
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, 0, err
	}
	ttl := 300
	var ips []net.IP
	for _, a := range body.Answer {
		if a.Type != 1 {
			continue
		}
		if ip := net.ParseIP(a.Data); ip != nil {
			ips = append(ips, ip)
			ttl = min(ttl, a.TTL)
		}
	}
	return ips, ttl, nil
}

// usable drops loopback/unspecified addresses and puts IPv4 first.
func usable(ips []net.IP) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsUnspecified() {
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
