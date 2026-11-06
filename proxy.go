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
	"strconv"
	"strings"
	"sync"
	"time"
)

const statusPath = "/snisplit/status"

type config struct {
	listen      string
	port        int
	transparent bool
	mode        string
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

type proxy struct {
	cfg     config
	res     *resolver
	started time.Time

	mu        sync.Mutex
	listeners []net.Listener
}

func newProxy(cfg config, res *resolver) *proxy {
	return &proxy{cfg: cfg, res: res, started: time.Now()}
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
		go h(c)
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

// sendHello reads the ClientHello from the client and forwards it fragmented.
func (p *proxy) sendHello(client net.Conn, clientR io.Reader, up net.Conn) (int, error) {
	client.SetReadDeadline(time.Now().Add(p.cfg.timeout))
	rec, err := readRecord(clientR)
	client.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, err
	}
	pieces := fragment(rec, p.cfg.mode)
	return len(pieces), writePieces(up, pieces, p.cfg.delay)
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
	up, ip, err := p.dial(host, port)
	if err != nil {
		log.Printf("FAIL  %s  %v", target, err)
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		c.Close()
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if port == p.cfg.httpsPort() {
		n, err := p.sendHello(c, br, up)
		if err != nil {
			p.debugf("FAIL  %s  reading ClientHello: %v", target, err)
			c.Close()
			up.Close()
			return
		}
		log.Printf("TLS   %s via %s (%d pieces)", target, ip, n)
	} else {
		log.Printf("TUNNEL %s via %s", target, ip)
	}
	relay(c, br, up)
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
	up, ip, err := p.dial(host, port)
	if err != nil {
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
		b, _ := json.Marshal(statusInfo{
			PID:         os.Getpid(),
			Version:     version,
			Uptime:      time.Since(p.started).Round(time.Second).String(),
			Mode:        p.cfg.mode,
			Transparent: p.cfg.transparent,
			Port:        p.cfg.port,
		})
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
	PID         int    `json:"pid"`
	Version     string `json:"version"`
	Uptime      string `json:"uptime"`
	Mode        string `json:"mode"`
	Transparent bool   `json:"transparent"`
	Port        int    `json:"port"`
}

// ---------------------------------------------------------------- transparent

// handleTransparentTLS serves connections that reach 127.0.0.1:443 because the
// hosts file points a blocked name here. The real destination is the SNI.
func (p *proxy) handleTransparentTLS(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(p.cfg.timeout))
	rec, err := readRecord(c)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	off, n, ok := findSNI(rec)
	if !ok {
		p.debugf("FAIL  transparent :443 connection without SNI")
		c.Close()
		return
	}
	host := string(rec[off : off+n])
	up, ip, err := p.dial(host, p.cfg.httpsPort())
	if err != nil {
		log.Printf("FAIL  %s:443  %v", host, err)
		c.Close()
		return
	}
	pieces := fragment(rec, p.cfg.mode)
	if err := writePieces(up, pieces, p.cfg.delay); err != nil {
		c.Close()
		up.Close()
		return
	}
	log.Printf("TLS   %s via %s (%d pieces)", host, ip, len(pieces))
	relay(c, c, up)
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
	if host == "" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() {
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
