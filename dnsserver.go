package main

// The DNS server behind "snisplit dns on": the computer's DNS points at
// 127.0.0.1, so every app, not just browsers, gets:
//
//   - answers over DNS-over-HTTPS (the ISP's DNS blocks and poisoning are gone);
//   - ad, tracker and malware names answered with 0.0.0.0 (when ad blocking is on);
//   - names blocked by their SNI answered with 127.0.0.1, where snisplit's
//     listeners on ports 443 and 80 split the connection. Steam's names and
//     sites found blocked in browser mode are known; any other name is
//     checked the first time an app asks for it, with one TLS handshake
//     straight to the site and, if that is cut off, one split the usual way.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type dnsServer struct {
	p        *proxy
	fallback atomic.Pointer[[]string] // "ip:53" servers the computer used before, for when DoH fails
	probes   chan struct{}            // at most this many SNI checks at once

	mu      sync.Mutex
	cache   map[string]dnsCached
	checked map[string]time.Time // names already checked for an SNI block

	queries, adsBlocked, redirected, learned atomic.Int64
}

type dnsCached struct {
	msg     []byte
	expires time.Time
}

type dnsStats struct {
	Queries    int64 `json:"queries"`
	AdsBlocked int64 `json:"ads_blocked"`
	Redirected int64 `json:"redirected"`
	Learned    int64 `json:"learned"`
}

// startDNS serves DNS on 127.0.0.1:53 (required) and [::1]:53 (if possible),
// over UDP and TCP.
func (p *proxy) startDNS(fallback []string) error {
	d := &dnsServer{p: p, probes: make(chan struct{}, 8), cache: map[string]dnsCached{}, checked: map[string]time.Time{}}
	d.setFallback(fallback)
	for i, host := range []string{"127.0.0.1", "::1"} {
		addr := net.JoinHostPort(host, "53")
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			if i == 0 {
				return fmt.Errorf("DNS: cannot listen on %s (another DNS program running?): %v", addr, err)
			}
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close()
			if i == 0 {
				return fmt.Errorf("DNS: cannot listen on %s/tcp: %v", addr, err)
			}
			continue
		}
		p.mu.Lock()
		p.closers = append(p.closers, pc, ln)
		p.mu.Unlock()
		go d.serveUDP(pc)
		go d.serveTCP(ln)
		log.Printf("DNS server on %s (udp, tcp)", addr)
	}
	p.dns.Store(d)
	return nil
}

func (d *dnsServer) setFallback(servers []string) {
	s := append([]string(nil), servers...)
	d.fallback.Store(&s)
}

func (d *dnsServer) stats() dnsStats {
	return dnsStats{d.queries.Load(), d.adsBlocked.Load(), d.redirected.Load(), d.learned.Load()}
}

func (d *dnsServer) serveUDP(pc net.PacketConn) {
	for {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			if resp := d.handle(buf[:n], true); resp != nil {
				pc.WriteTo(resp, addr)
			}
		}()
	}
}

func (d *dnsServer) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				resp := d.handle(msg, false)
				if resp == nil {
					return
				}
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
				if _, err := c.Write(append(out, resp...)); err != nil {
					return
				}
			}
		}()
	}
}

// dnsQuestion is the one question of a query.
type dnsQuestion struct {
	name   string // lower case, no trailing dot ("" for the root)
	qtype  uint16
	qclass uint16
	end    int // offset just past the question
	udp    int // largest UDP response the client takes
}

func parseQuestion(msg []byte) (q dnsQuestion, ok bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:]) != 1 {
		return q, false
	}
	var labels []string
	p := 12
	for {
		if p >= len(msg) {
			return q, false
		}
		l := int(msg[p])
		if l == 0 {
			p++
			break
		}
		if l > 63 || p+1+l > len(msg) {
			return q, false // no compression in questions
		}
		labels = append(labels, strings.ToLower(string(msg[p+1:p+1+l])))
		p += 1 + l
	}
	if p+4 > len(msg) {
		return q, false
	}
	q.name = strings.Join(labels, ".")
	q.qtype = binary.BigEndian.Uint16(msg[p:])
	q.qclass = binary.BigEndian.Uint16(msg[p+2:])
	q.end = p + 4
	q.udp = 512
	// an EDNS OPT record (root name, type 41) gives the client's UDP size
	if binary.BigEndian.Uint16(msg[10:]) > 0 && q.end+11 <= len(msg) && msg[q.end] == 0 &&
		binary.BigEndian.Uint16(msg[q.end+1:]) == 41 {
		q.udp = max(512, int(binary.BigEndian.Uint16(msg[q.end+3:])))
	}
	return q, true
}

type dnsRR struct {
	typ  uint16
	ttl  uint32
	data []byte
}

// reply builds a response to query with rcode and answers for the
// question's name.
func reply(query []byte, q dnsQuestion, rcode byte, answers ...dnsRR) []byte {
	b := make([]byte, 12, 12+len(query)+len(answers)*28)
	copy(b, query[:2])
	b[2] = 0x80 | query[2]&0x79 // response, same opcode and RD
	b[3] = 0x80 | rcode&0x0f    // recursion available
	if q.end > 12 {
		b[5] = 1
	}
	binary.BigEndian.PutUint16(b[6:], uint16(len(answers)))
	b = append(b, query[12:q.end]...)
	for _, a := range answers {
		b = append(b, 0xc0, 12) // the question's name
		b = binary.BigEndian.AppendUint16(b, a.typ)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, a.ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.data)))
		b = append(b, a.data...)
	}
	return b
}

// pointAt answers A with v4 and AAAA with v6 (nil: no record), and any other
// type with no records.
func pointAt(query []byte, q dnsQuestion, v4, v6 net.IP, ttl uint32) []byte {
	switch {
	case q.qtype == typeA && v4 != nil:
		return reply(query, q, 0, dnsRR{typeA, ttl, v4.To4()})
	case q.qtype == typeAAAA && v6 != nil:
		return reply(query, q, 0, dnsRR{typeAAAA, ttl, v6.To16()})
	}
	return reply(query, q, 0)
}

var localhost4 = net.IPv4(127, 0, 0, 1)

func (d *dnsServer) handle(msg []byte, udp bool) []byte {
	if len(msg) < 12 || msg[2]&0x80 != 0 { // too short, or a response
		return nil
	}
	q, ok := parseQuestion(msg)
	switch {
	case !ok:
		return reply(msg, dnsQuestion{end: 12}, 1) // FORMERR
	case msg[2]&0x78 != 0:
		return reply(msg, q, 4) // NOTIMP: only standard queries
	}
	d.queries.Add(1)
	if q.qclass == 1 && strings.Contains(q.name, ".") {
		if d.p.adBlocked(q.name) {
			d.adsBlocked.Add(1)
			return pointAt(msg, q, net.IPv4zero, net.IPv6unspecified, 300)
		}
		if d.redirect(q.name) {
			d.redirected.Add(1)
			return pointAt(msg, q, localhost4, nil, 60)
		}
	}
	resp := d.forward(msg, q)
	if resp == nil {
		return reply(msg, q, 2) // SERVFAIL
	}
	if q.qtype == typeA && q.qclass == 1 && d.shouldCheck(q.name) {
		blocked, pending := d.check(q.name, resp)
		if blocked {
			d.redirected.Add(1)
			return pointAt(msg, q, localhost4, nil, 60)
		}
		if pending { // the check goes on: let the app ask again soon
			resp = capTTL(resp, 20)
		}
	}
	if udp && len(resp) > q.udp {
		t := reply(msg, q, resp[3]&0x0f)
		t[2] |= 0x02 // truncated: the client asks again over TCP
		return t
	}
	return resp
}

// redirect reports whether name is answered with 127.0.0.1.
func (d *dnsServer) redirect(name string) bool {
	p := d.p
	return p.cfg.transparent && (p.listed(name) || p.state.isLearned(name))
}

// forward answers from the cache, over DoH, or (DoH failing) from the DNS
// servers the computer used before.
func (d *dnsServer) forward(msg []byte, q dnsQuestion) []byte {
	key := fmt.Sprintf("%s|%d|%d", q.name, q.qtype, q.qclass)
	d.mu.Lock()
	c, ok := d.cache[key]
	d.mu.Unlock()
	if ok && time.Now().Before(c.expires) {
		resp := append([]byte(nil), c.msg...)
		copy(resp, msg[:2])
		return resp
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	resp, err := d.p.res.exchange(ctx, msg)
	if err != nil {
		if resp = d.askFallback(msg); resp == nil {
			d.p.debugf("DNS %s: %v", q.name, err)
			return nil
		}
	}
	if rc := resp[3] & 0x0f; rc == 0 || rc == 3 {
		ttl := min(max(minTTL(resp), 10), 3600)
		d.mu.Lock()
		if len(d.cache) > 20000 {
			d.cache = map[string]dnsCached{}
		}
		d.cache[key] = dnsCached{append([]byte(nil), resp...), time.Now().Add(time.Duration(ttl) * time.Second)}
		d.mu.Unlock()
	}
	return resp
}

func (d *dnsServer) askFallback(msg []byte) []byte {
	for _, s := range *d.fallback.Load() {
		c, err := net.DialTimeout("udp", s, 2*time.Second)
		if err != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n := 0
		if _, err = c.Write(msg); err == nil {
			n, err = c.Read(buf)
		}
		c.Close()
		if err == nil && n >= 12 && buf[0] == msg[0] && buf[1] == msg[1] {
			return buf[:n]
		}
	}
	return nil
}

// shouldCheck reports whether name still needs checking for an SNI block
// (once a day per name).
func (d *dnsServer) shouldCheck(name string) bool {
	if !d.p.cfg.transparent || !strings.Contains(name, ".") {
		return false
	}
	for _, s := range []string{".local", ".lan", ".home", ".arpa", ".internal", ".localhost"} {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if at, ok := d.checked[name]; ok && time.Since(at) < 24*time.Hour {
		return false
	}
	if len(d.checked) > 50000 {
		d.checked = map[string]time.Time{}
	}
	d.checked[name] = time.Now()
	return true
}

// check tests whether the site in resp is blocked by its SNI. It waits up to
// 250 ms; a slower check finishes in the background (pending).
func (d *dnsServer) check(name string, resp []byte) (blocked, pending bool) {
	ips, _, err := parseDNSAnswer(resp)
	var ip net.IP
	for _, x := range ips {
		if x.To4() != nil && x.IsGlobalUnicast() && !x.IsPrivate() {
			ip = x
			break
		}
	}
	if err != nil || ip == nil {
		return false, false
	}
	done := make(chan bool, 1)
	go func() {
		d.probes <- struct{}{}
		defer func() { <-d.probes }()
		b := d.p.sniBlocked(name, ip)
		if b {
			d.p.state.learn(name)
			d.learned.Add(1)
			log.Printf("LEARN %s is blocked by its name; apps reach it through snisplit now", name)
		}
		done <- b
	}()
	select {
	case b := <-done:
		return b, false
	case <-time.After(250 * time.Millisecond):
		return false, true
	}
}

// sniBlocked reports whether a TLS handshake for host straight to ip is cut
// off while a split one gets an answer.
func (p *proxy) sniBlocked(host string, ip net.IP) bool {
	port := p.cfg.httpsPort()
	if p.tlsAnswers(ip, host, port, "none") != errCutOff {
		return false
	}
	return p.tlsAnswers(ip, host, port, p.probeMode(host)) == nil
}

var errCutOff = errors.New("connection cut off")

// tlsAnswers does a TLS handshake for host with ip, split with mode. It
// returns nil when the server answered (even with an error alert),
// errCutOff when the connection was reset or went silent, or the dial error.
func (p *proxy) tlsAnswers(ip net.IP, host string, port int, mode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprint(port)))
	if err != nil {
		return err
	}
	defer c.Close()
	tc := tls.Client(&splitConn{Conn: c, mode: mode, delay: p.delay()},
		&tls.Config{ServerName: host, InsecureSkipVerify: true}) // only whether it answers matters
	err = tc.HandshakeContext(ctx)
	var alert tls.AlertError
	if err == nil || errors.As(err, &alert) {
		return nil
	}
	return errCutOff
}

// minTTL is the lowest TTL among the answer records (60 when there are none).
func minTTL(msg []byte) (ttl int) {
	defer func() {
		if recover() != nil {
			ttl = 60
		}
	}()
	p := 12
	for i := 0; i < int(binary.BigEndian.Uint16(msg[4:])); i++ {
		p = skipDNSName(msg, p) + 4
	}
	ttl = -1
	for i := 0; i < int(binary.BigEndian.Uint16(msg[6:])); i++ {
		p = skipDNSName(msg, p)
		if t := int(binary.BigEndian.Uint32(msg[p+4:])); ttl < 0 || t < ttl {
			ttl = t
		}
		p += 10 + int(binary.BigEndian.Uint16(msg[p+8:]))
	}
	if ttl < 0 {
		return 60
	}
	return ttl
}

// capTTL returns a copy of msg with every answer's TTL at most maxTTL.
func capTTL(msg []byte, maxTTL uint32) (out []byte) {
	out = append([]byte(nil), msg...)
	defer func() {
		if recover() != nil {
			out = msg
		}
	}()
	p := 12
	for i := 0; i < int(binary.BigEndian.Uint16(out[4:])); i++ {
		p = skipDNSName(out, p) + 4
	}
	for i := 0; i < int(binary.BigEndian.Uint16(out[6:])); i++ {
		p = skipDNSName(out, p)
		if binary.BigEndian.Uint32(out[p+4:]) > maxTTL {
			binary.BigEndian.PutUint32(out[p+4:], maxTTL)
		}
		p += 10 + int(binary.BigEndian.Uint16(out[p+8:]))
	}
	return out
}
