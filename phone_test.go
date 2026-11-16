package main

import (
	"bufio"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// serveLocal sends one raw request to p.handleLocal as if from remote.
func serveLocal(t *testing.T, p *proxy, raw, remote string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
			p.handleLocal(fakeRemote{c, remote}, req)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, raw)
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestPhoneKind(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1": "ios",
		"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)":                                            "ios",
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 Chrome/130 Mobile Safari":    "android",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)":                                                "",
	} {
		if got := phoneKind(ua); got != want {
			t.Errorf("%q: %q, want %q", ua, got, want)
		}
	}
}

func TestMobileconfig(t *testing.T) {
	ssid := `Nhà <Minh> & "5G"`
	cfg := mobileconfig(ssid, "http://192.168.1.5:8881/proxy.pac?all=1")
	// well-formed XML, with the name and PAC address intact once decoded
	d := xml.NewDecoder(strings.NewReader(cfg))
	d.Strict = true
	var texts []string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("not valid XML: %v\n%s", err, cfg)
		}
		if cd, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(cd)) != "" {
			texts = append(texts, string(cd))
		}
	}
	joined := strings.Join(texts, "\n")
	for _, want := range []string{ssid, "http://192.168.1.5:8881/proxy.pac?all=1", "com.apple.wifi.managed", "Auto", "Configuration"} {
		if !strings.Contains(joined, want) {
			t.Errorf("profile lacks %q", want)
		}
	}
	if strings.Contains(cfg, "<key>Password</key>") {
		t.Error("the profile must not carry a password")
	}
	if a, b := mobileconfig("x", "y"), mobileconfig("x", "y"); a == b {
		t.Error("payload UUIDs are not fresh")
	}
}

func TestPhonePagePerDevice(t *testing.T) {
	if lanIP() == nil {
		t.Skip("no local network address")
	}
	p := newProxy(config{listen: "127.0.0.1", port: 8881, share: true}, newResolver(false), nil)
	page := func(ua string) string {
		return serveLocal(t, p, "GET "+phonePath+" HTTP/1.1\r\nHost: 192.168.1.5:8881\r\nUser-Agent: "+ua+"\r\n\r\n", "192.168.1.30:5555")
	}
	ios := page("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X)")
	if !strings.Contains(ios, `action="`+phoneProfilePath+`"`) || strings.Contains(ios, "<h2>Android</h2>") {
		t.Errorf("iPhone page:\n%.400s", ios)
	}
	android := page("Mozilla/5.0 (Linux; Android 14)")
	if strings.Contains(android, phoneProfilePath) || !strings.Contains(android, "<h2>Android</h2>") || !strings.Contains(android, "proxy.pac?all=1") {
		t.Errorf("Android page:\n%.400s", android)
	}

	prof := serveLocal(t, p, "GET "+phoneProfilePath+"?ssid=Nha+Minh HTTP/1.1\r\nHost: 192.168.1.5:8881\r\n\r\n", "192.168.1.30:5555")
	if !strings.Contains(prof, "application/x-apple-aspen-config") || !strings.Contains(prof, "<string>Nha Minh</string>") {
		t.Errorf("profile response:\n%.300s", prof)
	}
	if bad := serveLocal(t, p, "GET "+phoneProfilePath+"?ssid= HTTP/1.1\r\nHost: x\r\n\r\n", "192.168.1.30:5555"); !strings.HasPrefix(bad, "HTTP/1.1 400") {
		t.Errorf("empty Wi-Fi name accepted:\n%.100s", bad)
	}
}
