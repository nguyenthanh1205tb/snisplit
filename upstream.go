package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// parseUpstream checks an upstream proxy URL: socks5://[user:pass@]host:port
// or http://[user:pass@]host:port. An empty string means none.
func parseUpstream(s string) (*url.URL, error) {
	if s == "" {
		return nil, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "socks5", "socks5h", "http":
	default:
		return nil, fmt.Errorf("upstream %q: use socks5://host:port or http://host:port", s)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, fmt.Errorf("upstream %q: needs a host and a port", s)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("upstream %q: must not have a path", s)
	}
	return u, nil
}

// dialUpstream opens a tunnel to host:port through the upstream proxy. The
// proxy resolves host itself, so neither DNS nor the ISP's view of the
// destination matters any more.
func dialUpstream(ctx context.Context, up *url.URL, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", up.Host)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %v", up.Host, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(timeout))
	}
	if up.Scheme == "http" {
		err = httpConnect(c, up, host, port)
	} else {
		err = socks5Connect(c, up, host, port)
	}
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("upstream %s: %v", up.Host, err)
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

func httpConnect(c net.Conn, up *url.URL, host string, port int) error {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if up.User != nil {
		pass, _ := up.User.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(up.User.Username()+":"+pass)) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		return err
	}
	// Read byte by byte up to the blank line so no tunnel data is buffered away.
	br := bufio.NewReaderSize(&oneByteReader{c}, 16)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}
	return nil
}

type oneByteReader struct{ r io.Reader }

func (o *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}

func socks5Connect(c net.Conn, up *url.URL, host string, port int) error {
	methods := []byte{0x00}
	if up.User != nil {
		methods = []byte{0x02, 0x00}
	}
	if _, err := c.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return err
	}
	if rep[0] != 5 {
		return errors.New("not a SOCKS5 proxy")
	}
	switch rep[1] {
	case 0x00:
	case 0x02:
		user := up.User.Username()
		pass, _ := up.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("SOCKS5 user name or password too long")
		}
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(append(msg, byte(len(pass))), pass...)
		if _, err := c.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, rep[:]); err != nil {
			return err
		}
		if rep[1] != 0 {
			return errors.New("SOCKS5 login rejected")
		}
	default:
		return errors.New("SOCKS5 proxy wants a login method snisplit does not support")
	}

	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(append(req, 1), ip.To4()...)
	} else if ip != nil {
		req = append(append(req, 4), ip.To16()...)
	} else {
		if len(host) > 255 {
			return errors.New("host name too long")
		}
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	if head[1] != 0 {
		return fmt.Errorf("SOCKS5 connect to %s failed (code %d)", host, head[1])
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return errors.New("bad SOCKS5 reply")
	}
	_, err := io.ReadFull(c, make([]byte, skip+2))
	return err
}

// redactURL hides the password of an upstream URL for logs and status.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	if _, ok := u.User.Password(); ok {
		v := *u
		v.User = url.UserPassword(u.User.Username(), "xxxxx")
		return v.String()
	}
	return u.String()
}

// isLocalHost reports names and literal addresses that must never go through
// a proxy (browser mode).
func isLocalHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "localhost" || !strings.Contains(h, ".") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}
