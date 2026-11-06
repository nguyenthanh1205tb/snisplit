package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const statusPath = "/snisplit/status"

// autoModes is the order "--mode auto" tries; the mode that last worked for a
// host is tried first.
var autoModes = []string{"both", "record", "tcp"}

type config struct {
	listen      string
	port        int
	transparent bool
	mode        string // a fragModes value, or "auto"
	delay       time.Duration
	timeout     time.Duration
	verbose     bool
	names       []string // hostnames / .suffixes routed through the proxy (PAC)

	tlsPort int // upstream HTTPS port; 0 means 443 (tests override it)
}

func (c config) httpsPort() int {
	if c.tlsPort != 0 {
		return c.tlsPort
	}
	return 443
}

type proxyStats struct {
	conns, fails, retries atomic.Int64
	mu                    sync.Mutex
	hostFails             map[string]int
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

type proxy struct {
	cfg     config
	res     *resolver
	started time.Time
	stats   proxyStats
	modes   sync.Map // host -> split mode that last worked

	supervisorPID int // set when started by "snisplit start"
	restarts      int

	mu        sync.Mutex
	listeners []net.Listener
}

func newProxy(cfg config, res *resolver) *proxy {
	p := &proxy{cfg: cfg, res: res, started: time.Now()}
	p.stats.hostFails = map[string]int{}
	return p
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

// dial connects to host:port using our resolver, trying up to three addresses.
func (p *proxy) dial(host string, port int) (net.Conn, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.timeout)
	defer cancel()
	ips, err := p.res.lookup(ctx, host)
	if err != nil {
		return nil, "", err
	}
	ips = append([]net.IP(nil), ips...) // do not reorder the resolver's cached slice
	rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
	var lastErr error
	d := net.Dialer{Timeout: p.cfg.timeout}
	for _, ip := range ips[:min(3, len(ips))] {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			return c, ip.String(), nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

// modesFor returns the split modes to try for host, best guess first.
func (p *proxy) modesFor(host string) []string {
	if p.cfg.mode != "auto" {
		return []string{p.cfg.mode}
	}
	var order []string
	if m, ok := p.modes.Load(host); ok {
		order = append(order, m.(string))
	}
	for _, m := range autoModes {
		if len(order) == 0 || order[0] != m {
			order = append(order, m)
		}
	}
	return order
}

// openTLS connects to host:port and sends the ClientHello split, trying the
// next mode whenever the connection dies before the server answers (what an
// SNI filter's reset looks like). It returns the upstream connection and the
// server's first bytes, which the caller must forward to the client.
func (p *proxy) openTLS(host string, port int, hello []byte) (up net.Conn, first []byte, ip, mode string, err error) {
	_, _, hasSNI := findSNI(hello)
	modes := p.modesFor(host)
	if !hasSNI {
		modes = modes[:1]
	}
	for i, m := range modes {
		if i > 0 {
			p.stats.retries.Add(1)
			p.debugf("RETRY %s with mode %s (%v)", host, m, err)
		}
		up, ip, err = p.dial(host, port)
		if err != nil {
			return nil, nil, "", "", err
		}
		if err = writePieces(up, fragment(hello, m), p.cfg.delay); err == nil {
			if !hasSNI {
				return up, nil, ip, m, nil
			}
			up.SetReadDeadline(time.Now().Add(p.cfg.timeout))
			buf := make([]byte, 16<<10)
			var n int
			n, err = up.Read(buf)
			up.SetReadDeadline(time.Time{})
			if n > 0 {
				p.modes.Store(host, m)
				return up, buf[:n], ip, m, nil
			}
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
		}
		up.Close()
	}
	return nil, nil, ip, "", fmt.Errorf("blocked with every split mode (last error: %v)", err)
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
	up, first, ip, mode, err := p.openTLS(host, port, hello)
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
	log.Printf("TLS   %s via %s (%s)", host, ip, mode)
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
	port, _ := strconv.Atoi(portS)

	if port != p.cfg.httpsPort() { // not HTTPS: plain tunnel
		up, ip, err := p.dial(host, port)
		if err != nil {
			log.Printf("FAIL  %s  %v", target, err)
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			c.Close()
			return
		}
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		log.Printf("TUNNEL %s via %s", target, ip)
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
	if err := writePieces(up, splitHTTPRequest(buf.Bytes(), host), p.cfg.delay); err != nil {
		c.Close()
		up.Close()
		return
	}
	log.Printf("HTTP  %s via %s", host, ip)
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
		writeResponse(c, "application/x-ns-proxy-autoconfig", []byte(makePAC(p.cfg.names, p.cfg.port)))
	case statusPath:
		b, _ := json.Marshal(p.status())
		writeResponse(c, "application/json", b)
	default:
		io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}
}

func writeResponse(w io.Writer, ctype string, body []byte) {
	fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nCache-Control: no-cache\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", ctype, len(body))
	w.Write(body)
}

type statusInfo struct {
	PID           int      `json:"pid"`
	SupervisorPID int      `json:"supervisor_pid,omitempty"`
	Restarts      int      `json:"restarts"`
	Version       string   `json:"version"`
	Uptime        string   `json:"uptime"`
	Mode          string   `json:"mode"`
	Transparent   bool     `json:"transparent"`
	Port          int      `json:"port"`
	Connections   int64    `json:"connections"`
	Failures      int64    `json:"failures"`
	Retries       int64    `json:"retries"`
	TopFailures   []string `json:"top_failures,omitempty"`
}

func (p *proxy) status() statusInfo {
	return statusInfo{
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
		TopFailures:   p.stats.top(5),
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
	p.forwardTLS(c, c, string(hello[off:off+n]), p.cfg.httpsPort(), hello)
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
// match the domain and all its subdomains.
func makePAC(names []string, port int) string {
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
