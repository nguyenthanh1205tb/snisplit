package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	statusPath = "/snisplit/status"
	reloadPath = "/snisplit/reload"
)

type config struct {
	listen      string
	port        int
	transparent bool
	mode        string // a fragModes value, or "auto"
	delay       time.Duration
	delaySet    bool // --delay given: the strategy file must not change it
	timeout     time.Duration
	verbose     bool
	names       []string // hostnames / .suffixes routed through the proxy (PAC)
	upstream    *url.URL // last-resort tunnel, nil for none

	tlsPort int // upstream HTTPS port; 0 means 443 (tests override it)
}

func (c config) httpsPort() int {
	if c.tlsPort != 0 {
		return c.tlsPort
	}
	return 443
}

type proxyStats struct {
	conns, fails, retries, viaUpstream, viaOtherIP atomic.Int64
	mu                                             sync.Mutex
	hostFails                                      map[string]int
}

func (s *proxyStats) fail(host string) {
	s.fails.Add(1)
	s.mu.Lock()
	s.hostFails[host]++
	s.mu.Unlock()
}

// top returns the n hosts with the most failures, as "host (count)".
func (s *proxyStats) top(n int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	type kv struct {
		host string
		n    int
	}
	var all []kv
	for h, c := range s.hostFails {
		all = append(all, kv{h, c})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n > all[j].n || all[i].n == all[j].n && all[i].host < all[j].host })
	var out []string
	for i := 0; i < len(all) && i < n; i++ {
		out = append(out, fmt.Sprintf("%s (%d)", all[i].host, all[i].n))
	}
	return out
}

// health is the result of the periodic self-test against the canary hosts.
type health struct {
	State   string    `json:"state"` // unknown, open (not blocked), ok, upstream, blocked
	Mode    string    `json:"mode,omitempty"`
	Host    string    `json:"host,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Checked time.Time `json:"checked,omitempty"`
}

type proxy struct {
	cfg     config
	res     *resolver
	state   *state
	started time.Time
	stats   proxyStats

	exact    map[string]bool // listed names
	suffixes []string        // listed ".domain" entries

	strat  atomic.Pointer[strategy]
	best   atomic.Value // string: the mode the last health check found working
	health atomic.Pointer[health]
	ads    atomic.Pointer[blocker] // nil when ad blocking is off

	// other addresses for sites blocked by address (ipblock.go)
	alts      []altTier      // nil: the real ones (tests replace them)
	edgeRoots *x509.CertPool // nil: the system's
	edgeMu    sync.Mutex
	edges     map[string][]net.IP
	edgesAt   time.Time

	supervisorPID int // set when started by "snisplit start"
	restarts      int

	mu        sync.Mutex
	listeners []net.Listener
	closers   []io.Closer // DNS sockets

	dns atomic.Pointer[dnsServer] // nil unless "snisplit dns on"
}

func newProxy(cfg config, res *resolver, st *state) *proxy {
	if st == nil {
		st = loadState("")
	}
	p := &proxy{cfg: cfg, res: res, state: st, started: time.Now(), exact: map[string]bool{}}
	res.state = st
	p.stats.hostFails = map[string]int{}
	for _, n := range cfg.names {
		if strings.HasPrefix(n, ".") {
			p.suffixes = append(p.suffixes, n)
		} else {
			p.exact[n] = true
		}
	}
	p.best.Store("")
	p.health.Store(&health{State: "unknown"})
	builtin, _ := parseStrategy(builtinStrategy)
	p.applyStrategy(builtin)
	return p
}

// applyStrategy switches to s: split-mode order, pauses and DoH servers.
func (p *proxy) applyStrategy(s *strategy) {
	p.edgeMu.Lock()
	p.edgesAt = time.Time{} // the CDN list may have changed
	p.edgeMu.Unlock()
	p.strat.Store(s)
	slowDelayNS.Store(int64(s.SlowDelayMS) * int64(time.Millisecond))
	p.res.setEndpoints(s.DoH)
}

func (p *proxy) delay() time.Duration {
	if p.cfg.delaySet {
		return p.cfg.delay
	}
	return time.Duration(p.strat.Load().DelayMS) * time.Millisecond
}

// listed reports whether host is in the configured lists.
func (p *proxy) listed(host string) bool {
	if p.exact[host] {
		return true
	}
	for _, s := range p.suffixes {
		if host == s[1:] || strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

func (p *proxy) debugf(format string, a ...any) {
	if p.cfg.verbose {
		log.Printf(format, a...)
	}
}

// listenAll opens the HTTP proxy listener and, in transparent mode, the
// listeners on :443 and :80. Failure to open the transparent ports is a warning.
func (p *proxy) listenAll() error {
	ln, err := net.Listen("tcp", net.JoinHostPort(p.cfg.listen, strconv.Itoa(p.cfg.port)))
	if err != nil {
		return err
	}
	p.track(ln)
	go p.serve(ln, p.handleProxyConn)
	log.Printf("HTTP proxy on %s  (PAC: http://%s/proxy.pac)", ln.Addr(), ln.Addr())

	if p.cfg.transparent {
		for _, t := range []struct {
			port int
			h    func(net.Conn)
		}{{443, p.handleTransparentTLS}, {80, p.handleTransparentHTTP}} {
			l, err := net.Listen("tcp", net.JoinHostPort(p.cfg.listen, strconv.Itoa(t.port)))
			if err != nil {
				log.Printf("WARNING: transparent mode cannot listen on port %d: %v", t.port, err)
				if t.port < 1024 && os.Getenv("OS") != "Windows_NT" {
					log.Printf("         ports below 1024 need root on Linux: run with sudo, or")
					log.Printf("         sudo setcap cap_net_bind_service=+ep \"$(command -v snisplit)\"")
				}
				continue
			}
			p.track(l)
			go p.serve(l, t.h)
			log.Printf("transparent listener on %s", l.Addr())
		}
	}
	return nil
}

func (p *proxy) track(l net.Listener) {
	p.mu.Lock()
	p.listeners = append(p.listeners, l)
	p.mu.Unlock()
}

func (p *proxy) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, l := range p.listeners {
		l.Close()
	}
	for _, c := range p.closers {
		c.Close()
	}
	p.state.save()
}

func (p *proxy) serve(ln net.Listener, h func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go func(c net.Conn) {
			defer func() { // one bad connection must never take the proxy down
				if r := recover(); r != nil {
					log.Printf("PANIC handling %s: %v", c.RemoteAddr(), r)
					c.Close()
				}
			}()
			h(c)
		}(c)
	}
}

// ---------------------------------------------------------------- background

// background runs the periodic jobs of a long-running proxy: saving what it
// learned, fetching a newer strategy and the health self-test.
func (p *proxy) background(fetchRemote bool) {
	go func() {
		for range time.Tick(time.Minute) {
			if err := p.state.save(); err != nil {
				log.Printf("saving %s: %v", p.state.path, err)
			}
		}
	}()
	go func() { // keep the ad block list fresh
		for range time.Tick(6 * time.Hour) {
			if b := p.ads.Load(); b != nil {
				if _, _, updated := b.info(); time.Since(updated) > 24*time.Hour {
					p.refreshAdblock(loadSettings().AdblockList)
				}
			}
		}
	}()
	if fetchRemote {
		go func() {
			time.Sleep(time.Minute)
			for {
				if s, err := fetchStrategy(p.strat.Load()); err != nil {
					p.debugf("strategy update: %v", err)
				} else if s != nil {
					log.Printf("strategy updated to version %d (modes %s)", s.Version, strings.Join(s.Modes, ", "))
					p.applyStrategy(s)
				}
				time.Sleep(24 * time.Hour)
			}
		}()
	}
	go func() { // CDN servers to try for sites blocked by address, ready before they are needed
		time.Sleep(30 * time.Second)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			p.edgePools(ctx)
			cancel()
			time.Sleep(6*time.Hour + time.Minute)
		}
	}()
	go func() {
		time.Sleep(20 * time.Second)
		for {
			h := p.checkHealth()
			p.health.Store(h)
			log.Printf("health: %s %s %s", h.State, h.Mode, h.Detail)
			wait := 3 * time.Hour
			if h.State == "blocked" || h.State == "unknown" {
				wait = 15 * time.Minute
			}
			time.Sleep(wait)
		}
	}()
}

// checkHealth runs real TLS handshakes to a canary host: direct, then with
// each split mode in strategy order, then through the upstream proxy. The
// first mode that works becomes the first one tried for new hosts.
func (p *proxy) checkHealth() *health {
	h := &health{State: "unknown", Checked: time.Now()}
	for _, host := range p.strat.Load().Canary {
		ctx, cancel := context.WithTimeout(context.Background(), p.cfg.timeout)
		ips, err := p.res.lookup(ctx, host)
		cancel()
		if err != nil {
			h.Detail = "DNS: " + err.Error()
			continue
		}
		ip := ips[0].String()
		h.Host = host
		const t = 8 * time.Second
		if probe(host, ip, "none", 0, t) == "OK" {
			h.State, h.Detail = "open", "not blocked right now"
			return h
		}
		for _, m := range p.modesFor(host, true) {
			if probe(host, ip, m, p.delay(), t) == "OK" {
				h.State, h.Mode = "ok", m
				p.best.Store(m)
				return h
			}
		}
		if p.cfg.upstream != nil {
			r := probeUpstream(p.cfg.upstream, host, t)
			if r == "OK" {
				h.State, h.Mode = "upstream", "upstream"
				return h
			}
			h.Detail = "upstream: " + r
		}
		h.State = "blocked"
		if h.Detail == "" {
			h.Detail = "every split method failed for " + host
		}
		return h
	}
	return h
}

func probeUpstream(up *url.URL, host string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := dialUpstream(ctx, up, host, 443, timeout)
	if err != nil {
		return "NO CONNECT"
	}
	tc := tls.Client(c, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	tc.SetDeadline(time.Now().Add(timeout))
	err = tc.Handshake()
	tc.Close()
	return classify(err)
}

// ---------------------------------------------------------------- routing

// modesFor returns the split modes to try for host, best guess first. Hosts
// not in the lists (browser mode) are tried unsplit first.
func (p *proxy) modesFor(host string, listed bool) []string {
	if p.cfg.mode != "auto" {
		return []string{p.cfg.mode}
	}
	var order []string
	add := func(m string) {
		if m == "" || m == "upstream" {
			return
		}
		for _, x := range order {
			if x == m {
				return
			}
		}
		order = append(order, m)
	}
	if r, ok := p.state.route(host); ok {
		add(r.Mode)
	}
	if !listed && !p.state.isLearned(host) {
		add("none")
	}
	add(p.best.Load().(string))
	for _, m := range p.strat.Load().Modes {
		add(m)
	}
	return order
}

// candidateIPs returns up to three addresses for host, the one that last
// worked first.
func (p *proxy) candidateIPs(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := p.res.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	ips = append([]net.IP(nil), ips...) // do not reorder the resolver's cached slice
	rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
	if r, ok := p.state.route(host); ok && r.IP != "" {
		if good := net.ParseIP(r.IP); good != nil {
			rest := []net.IP{good}
			found := false
			for _, ip := range ips {
				if ip.Equal(good) {
					found = true
				} else {
					rest = append(rest, ip)
				}
			}
			if found || time.Since(r.At) < 6*time.Hour {
				ips = rest
			}
		}
	}
	return ips[:min(3, len(ips))], nil
}

// dial connects to host:port (no TLS tricks), trying up to three addresses
// and then the upstream proxy.
func (p *proxy) dial(host string, port int) (net.Conn, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.timeout)
	defer cancel()
	ips, err := p.candidateIPs(ctx, host)
	if err == nil {
		lists := []func() []net.IP{func() []net.IP { return ips }}
		for _, t := range p.altTiers() {
			if !t.https { // the others need a TLS handshake to check
				lists = append(lists, func() []net.IP { return t.ips(ctx, host, port, ips) })
			}
		}
		for i, list := range lists {
			results, stop := dialStaggered(ctx, list(), port, min(p.cfg.timeout, 5*time.Second))
			for r := range results {
				if r.err != nil {
					err = r.err
					continue
				}
				stop()
				if i > 0 {
					p.stats.viaOtherIP.Add(1)
				}
				return r.c, r.ip.String(), nil
			}
			stop()
		}
	}
	if p.cfg.upstream != nil {
		uctx, ucancel := context.WithTimeout(context.Background(), p.cfg.timeout)
		defer ucancel()
		if c, uerr := dialUpstream(uctx, p.cfg.upstream, host, port, p.cfg.timeout); uerr == nil {
			p.stats.viaUpstream.Add(1)
			return c, "upstream", nil
		}
	}
	if err == nil {
		err = fmt.Errorf("%s: no address answers", host)
	}
	return nil, "", err
}

// openTLS connects to host:port and sends the ClientHello, trying every split
// mode on up to three addresses until the server answers. A connection that
// dies before the server's first byte is what an SNI filter's reset looks
// like; one that cannot even connect means the address is blocked, so the
// next address is tried. When nothing works it goes through the upstream
// proxy. It returns the connection and the server's first bytes, which the
// caller must forward to the client.
func (p *proxy) openTLS(host string, port int, hello []byte) (up net.Conn, first []byte, via string, err error) {
	_, _, hasSNI := findSNI(hello)
	listed := p.listed(host)
	modes := p.modesFor(host, listed)
	if !hasSNI {
		modes = modes[:1]
	}
	if r, ok := p.state.route(host); ok && r.Mode == "upstream" && p.cfg.upstream != nil && time.Since(r.At) < 6*time.Hour {
		if up, first, err = p.openUpstream(host, port, hello); err == nil {
			return up, first, "upstream", nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.timeout)
	ips, lastErr := p.candidateIPs(ctx, host)
	cancel()
	a := &attempt{p: p, host: host, port: port, hello: hello, hasSNI: hasSNI, listed: listed,
		total: len(ips) * len(modes), deadline: time.Now().Add(2 * p.cfg.timeout), err: lastErr}
	if up, first, via, ok := a.try(ips, modes, ""); ok {
		return up, first, via, nil
	}
	if len(ips) > 0 {
		// Every usual address failed: the site may be blocked by address.
		// Look for others, with the first few methods only.
		altModes := modes[:min(3, len(modes))]
		a.deadline = time.Now().Add(p.cfg.timeout + 10*time.Second)
		tried := append([]net.IP(nil), ips...)
		for _, t := range p.altTiers() {
			if time.Now().After(a.deadline) {
				break
			}
			tctx, cancel := context.WithDeadline(context.Background(), a.deadline)
			alt := t.ips(tctx, host, port, tried)
			cancel()
			if len(alt) == 0 {
				continue
			}
			p.debugf("ALT %s: trying %s addresses %v", host, t.name, alt)
			tried = append(tried, alt...)
			a.total += len(alt) * len(altModes)
			if up, first, via, ok := a.try(alt, altModes, t.name); ok {
				p.stats.viaOtherIP.Add(1)
				return up, first, via, nil
			}
		}
	}
	lastErr = a.err
	if p.cfg.upstream != nil {
		if up, first, err = p.openUpstream(host, port, hello); err == nil {
			return up, first, "upstream", nil
		}
		lastErr = fmt.Errorf("%v; %v", lastErr, err)
	}
	return nil, nil, "", fmt.Errorf("blocked with every split mode and address (last error: %v)", lastErr)
}

// attempt is one openTLS call's search for an address and split method that
// get the ClientHello answered.
type attempt struct {
	p        *proxy
	host     string
	port     int
	hello    []byte
	hasSNI   bool
	listed   bool
	deadline time.Time
	attempts int
	total    int
	err      error
}

// try connects to ips (staggered) and, on each address that answers, tries
// modes in order. tier names where the addresses came from ("" for DNS).
func (a *attempt) try(ips []net.IP, modes []string, tier string) (net.Conn, []byte, string, bool) {
	if len(ips) == 0 {
		return nil, nil, "", false
	}
	ctx, cancel := context.WithDeadline(context.Background(), a.deadline)
	defer cancel()
	results, stop := dialStaggered(ctx, ips, a.port, min(a.p.cfg.timeout, 5*time.Second))
	defer stop()
	for r := range results {
		if r.err != nil {
			a.err = r.err
			continue
		}
		if c, first, via, ok := a.modesOn(r.ip, r.c, modes, tier); ok {
			return c, first, via, true
		}
	}
	return nil, nil, "", false
}

// modesOn tries each mode on ip; c is an already open connection to it.
func (a *attempt) modesOn(ip net.IP, c net.Conn, modes []string, tier string) (net.Conn, []byte, string, bool) {
	p := a.p
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(a.port))
	d := net.Dialer{Timeout: min(p.cfg.timeout, 5*time.Second)}
	for _, m := range modes {
		if time.Now().After(a.deadline) {
			break
		}
		if a.attempts++; a.attempts > 1 {
			p.stats.retries.Add(1)
			p.debugf("RETRY %s via %s with %s (%v)", a.host, ip, m, a.err)
		}
		if c == nil {
			var err error
			if c, err = d.Dial("tcp", addr); err != nil {
				a.err = err
				break // this address stopped answering: no point trying other modes on it
			}
		}
		if err := sendPieces(c, plan(a.hello, m), p.delay()); err != nil {
			c.Close()
			c, a.err = nil, err
			continue
		}
		via := ip.String() + " (" + m + ")"
		if tier != "" {
			via += " [" + tier + "]"
		}
		if !a.hasSNI {
			return c, nil, via, true
		}
		wait := p.cfg.timeout
		if a.attempts < a.total {
			wait = min(wait, 7*time.Second)
		}
		c.SetReadDeadline(time.Now().Add(wait))
		buf := make([]byte, 16<<10)
		n, rerr := c.Read(buf)
		c.SetReadDeadline(time.Time{})
		if n > 0 {
			a.success(ip, m, tier)
			return c, buf[:n], via, true
		}
		if rerr == nil {
			rerr = io.ErrUnexpectedEOF
		}
		a.err = rerr
		c.Close()
		c = nil
	}
	if c != nil {
		c.Close()
	}
	return nil, nil, "", false
}

// success remembers what worked for the host.
func (a *attempt) success(ip net.IP, m, tier string) {
	p := a.p
	if tier != "" {
		if r, _ := p.state.route(a.host); r.IP != ip.String() {
			log.Printf("ADDR %s: its usual addresses are blocked; using %s (%s)", a.host, ip, tier)
		}
	}
	if a.listed || m != "none" || tier != "" {
		p.state.setRoute(a.host, ip.String(), m)
	}
	if !a.listed && m != "none" {
		if !p.state.isLearned(a.host) {
			log.Printf("LEARN %s is blocked; it will be split from now on", a.host)
		}
		p.state.learn(a.host)
	}
}

func (p *proxy) openUpstream(host string, port int, hello []byte) (net.Conn, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.timeout)
	defer cancel()
	c, err := dialUpstream(ctx, p.cfg.upstream, host, port, p.cfg.timeout)
	if err != nil {
		return nil, nil, err
	}
	if _, err := c.Write(hello); err != nil {
		c.Close()
		return nil, nil, err
	}
	c.SetReadDeadline(time.Now().Add(p.cfg.timeout))
	buf := make([]byte, 16<<10)
	n, err := c.Read(buf)
	c.SetReadDeadline(time.Time{})
	if n == 0 {
		c.Close()
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, nil, fmt.Errorf("upstream: %v", err)
	}
	p.stats.viaUpstream.Add(1)
	p.state.setRoute(host, "", "upstream")
	return c, buf[:n], nil
}

// relay copies both ways until either side finishes, then closes both.
func relay(client net.Conn, clientR io.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, clientR); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
	client.Close()
	upstream.Close()
	<-done
}

func (p *proxy) readHello(c net.Conn, r io.Reader) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(p.cfg.timeout))
	defer c.SetReadDeadline(time.Time{})
	return readRecord(r)
}

// forwardTLS opens the split upstream connection for an already-read
// ClientHello and relays the rest of the session.
func (p *proxy) forwardTLS(c net.Conn, clientR io.Reader, host string, port int, hello []byte) {
	p.stats.conns.Add(1)
	up, first, via, err := p.openTLS(host, port, hello)
	if err != nil {
		p.stats.fail(host)
		log.Printf("FAIL  %s:%d  %v", host, port, err)
		c.Close()
		return
	}
	if len(first) > 0 {
		if _, err := c.Write(first); err != nil {
			c.Close()
			up.Close()
			return
		}
	}
	p.debugf("TLS   %s via %s", host, via)
	relay(c, clientR, up)
}

// ---------------------------------------------------------------- HTTP proxy

func (p *proxy) handleProxyConn(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(p.cfg.timeout))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	switch {
	case req.Method == http.MethodConnect:
		p.handleConnect(c, br, req.Host)
	case req.URL.Host == "":
		p.handleLocal(c, req)
	default:
		p.handlePlainHTTP(c, br, req)
	}
}

func (p *proxy) handleConnect(c net.Conn, br *bufio.Reader, target string) {
	host, portS, err := net.SplitHostPort(target)
	if err != nil {
		host, portS = target, "443"
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	port, _ := strconv.Atoi(portS)
	if p.adBlocked(host) {
		p.refuse(c, host)
		return
	}

	if port != p.cfg.httpsPort() { // not HTTPS: plain tunnel
		up, ip, err := p.dial(host, port)
		if err != nil {
			log.Printf("FAIL  %s  %v", target, err)
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			c.Close()
			return
		}
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		p.debugf("TUNNEL %s via %s", target, ip)
		relay(c, br, up)
		return
	}

	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	hello, err := p.readHello(c, br)
	if err != nil {
		p.debugf("FAIL  %s  reading ClientHello: %v", target, err)
		c.Close()
		return
	}
	p.forwardTLS(c, br, host, port, hello)
}

func (p *proxy) handlePlainHTTP(c net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.URL.Hostname()
	if p.adBlocked(host) {
		p.refuse(c, host)
		return
	}
	port, _ := strconv.Atoi(req.URL.Port())
	if port == 0 {
		port = 80
	}
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Close = true // one request per upstream connection
	req.RequestURI = ""
	p.forwardHTTP(c, br, req, host, port)
}

func (p *proxy) forwardHTTP(c net.Conn, br *bufio.Reader, req *http.Request, host string, port int) {
	p.stats.conns.Add(1)
	up, ip, err := p.dial(host, port)
	if err != nil {
		p.stats.fail(host)
		log.Printf("FAIL  http://%s  %v", host, err)
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		c.Close()
		return
	}
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		c.Close()
		up.Close()
		return
	}
	if err := writePieces(up, splitHTTPRequest(buf.Bytes(), host), p.delay()); err != nil {
		c.Close()
		up.Close()
		return
	}
	p.debugf("HTTP  %s via %s", host, ip)
	relay(c, br, up)
}

// splitHTTPRequest hides the Host header from plain-HTTP DPI. Filters match the
// literal "Host:" (header names are case-insensitive, so servers accept
// "hoSt:"), and the request is also cut in the middle of the host name.
func splitHTTPRequest(raw []byte, host string) [][]byte {
	i := bytes.Index(raw, []byte("\r\nHost: "))
	if i < 0 {
		return [][]byte{raw[:len(raw)/2], raw[len(raw)/2:]}
	}
	copy(raw[i+2:], "hoSt")
	cut := i + len("\r\nHost: ") + max(1, len(host)/2)
	if cut >= len(raw) {
		cut = len(raw) / 2
	}
	return [][]byte{raw[:cut], raw[cut:]}
}

func (p *proxy) handleLocal(c net.Conn, req *http.Request) {
	defer c.Close()
	switch req.URL.Path {
	case "/proxy.pac":
		all := req.URL.Query().Get("all") == "1"
		writeResponse(c, "application/x-ns-proxy-autoconfig", []byte(makePAC(p.cfg.names, p.cfg.port, all)))
	case statusPath:
		b, _ := json.Marshal(p.status())
		writeResponse(c, "application/json", b)
	case reloadPath: // re-read settings.json (ad blocking, DNS fallbacks) without dropping connections
		p.applyAdblock(loadSettings())
		if d := p.dns.Load(); d != nil {
			d.setFallback(dnsFallbacks(loadDNSBackup(dnsBackupPath())))
		}
		writeResponse(c, "text/plain", []byte("ok\n"))
	default:
		io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}
}

func writeResponse(w io.Writer, ctype string, body []byte) {
	fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nCache-Control: no-cache\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", ctype, len(body))
	w.Write(body)
}

type statusInfo struct {
	PID           int       `json:"pid"`
	SupervisorPID int       `json:"supervisor_pid,omitempty"`
	Restarts      int       `json:"restarts"`
	Version       string    `json:"version"`
	Uptime        string    `json:"uptime"`
	Mode          string    `json:"mode"`
	Transparent   bool      `json:"transparent"`
	Port          int       `json:"port"`
	Connections   int64     `json:"connections"`
	Failures      int64     `json:"failures"`
	Retries       int64     `json:"retries"`
	ViaUpstream   int64     `json:"via_upstream"`
	ViaOtherIP    int64     `json:"via_other_address"`
	TopFailures   []string  `json:"top_failures,omitempty"`
	Health        health    `json:"health"`
	Strategy      int       `json:"strategy"`
	Upstream      string    `json:"upstream,omitempty"`
	Learned       []string  `json:"learned,omitempty"`
	Adblock       *adStats  `json:"adblock,omitempty"`
	DNS           *dnsStats `json:"dns,omitempty"` // "snisplit dns on"
}

type adStats struct {
	Domains int       `json:"domains"`
	Blocked int64     `json:"blocked"`
	Source  string    `json:"source,omitempty"`
	Updated time.Time `json:"updated,omitempty"`
}

func (p *proxy) status() statusInfo {
	learned := p.state.learnedNames()
	var ads *adStats
	if b := p.ads.Load(); b != nil {
		n, src, updated := b.info()
		ads = &adStats{Domains: n, Blocked: b.blocked.Load(), Source: src, Updated: updated}
	}
	return statusInfo{
		Adblock:       ads,
		DNS:           dnsStatsOf(p.dns.Load()),
		PID:           os.Getpid(),
		SupervisorPID: p.supervisorPID,
		Restarts:      p.restarts,
		Version:       version,
		Uptime:        time.Since(p.started).Round(time.Second).String(),
		Mode:          p.cfg.mode,
		Transparent:   p.cfg.transparent,
		Port:          p.cfg.port,
		Connections:   p.stats.conns.Load(),
		Failures:      p.stats.fails.Load(),
		Retries:       p.stats.retries.Load(),
		ViaUpstream:   p.stats.viaUpstream.Load(),
		ViaOtherIP:    p.stats.viaOtherIP.Load(),
		TopFailures:   p.stats.top(5),
		Health:        *p.health.Load(),
		Strategy:      p.strat.Load().Version,
		Upstream:      redactURL(p.cfg.upstream),
		Learned:       learned[:min(50, len(learned))],
	}
}

// ---------------------------------------------------------------- transparent

// handleTransparentTLS serves connections that reach 127.0.0.1:443 because the
// hosts file points a blocked name here. The real destination is the SNI.
func (p *proxy) handleTransparentTLS(c net.Conn) {
	hello, err := p.readHello(c, c)
	if err != nil {
		c.Close()
		return
	}
	off, n, ok := findSNI(hello)
	if !ok {
		p.debugf("FAIL  transparent :443 connection without SNI")
		c.Close()
		return
	}
	host := strings.ToLower(string(hello[off : off+n]))
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		c.Close()
		return
	}
	p.forwardTLS(c, c, host, p.cfg.httpsPort(), hello)
}

func (p *proxy) handleTransparentHTTP(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(p.cfg.timeout))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsLoopback() {
		c.Close()
		return
	}
	req.RequestURI = ""
	p.forwardHTTP(c, br, req, host, 80)
}

// ---------------------------------------------------------------- PAC

// makePAC routes the given names through the proxy. Entries starting with "."
// match the domain and all its subdomains. With all set (browser mode) every
// public host goes through the proxy, which only splits where it has to; the
// "; DIRECT" fallback keeps browsing working if snisplit is not running.
func makePAC(names []string, port int, all bool) string {
	if all {
		return fmt.Sprintf(`function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (isPlainHostName(host) || host == "localhost" || dnsDomainIs(host, ".local") ||
      dnsDomainIs(host, ".localhost") || /^[0-9.]+$/.test(host) || host.indexOf(":") >= 0)
    return "DIRECT";
  return "PROXY 127.0.0.1:%d; DIRECT";
}
`, port)
	}
	var conds []string
	for _, n := range names {
		if strings.HasPrefix(n, ".") {
			d := strings.TrimPrefix(n, ".")
			conds = append(conds, fmt.Sprintf(`host == "%s" || dnsDomainIs(host, ".%s")`, d, d))
		} else {
			conds = append(conds, fmt.Sprintf(`host == "%s"`, n))
		}
	}
	cond := "false"
	if len(conds) > 0 {
		cond = strings.Join(conds, " ||\n      ")
	}
	return fmt.Sprintf("function FindProxyForURL(url, host) {\n  host = host.toLowerCase();\n  if (%s)\n    return \"PROXY 127.0.0.1:%d\";\n  return \"DIRECT\";\n}\n", cond, port)
}
