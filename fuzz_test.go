package main

import (
	"bytes"
	"strings"
	"testing"
)

// Fuzz tests for everything that parses data from outside: ClientHellos from
// local apps, DNS answers from DoH servers, and downloaded block lists. They
// must never panic or loop, whatever the input. Seeds run with "go test";
// "go test -fuzz FuzzFindSNI" explores further.

func FuzzFindSNI(f *testing.F) {
	f.Add(clientHello(&testing.T{}, "store.steampowered.com"))
	f.Add([]byte{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0})
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Fuzz(func(t *testing.T, rec []byte) {
		off, n, ok := findSNI(rec)
		if ok && (off < 0 || n <= 0 || off+n > len(rec)) {
			t.Fatalf("findSNI returned %d,%d for %d bytes", off, n, len(rec))
		}
		for _, mode := range fragModes {
			var joined []byte
			for _, p := range plan(rec, mode) {
				d := p.data
				if p.oob && len(d) > 0 {
					d = d[:len(d)-1]
				}
				joined = append(joined, d...)
			}
			if !ok && !bytes.Equal(joined, rec) {
				t.Fatalf("%s changed data that has no SNI", mode)
			}
		}
	})
}

func FuzzParseDNSAnswer(f *testing.F) {
	f.Add(dnsQuery("example.com"))
	f.Add([]byte{0, 0, 0x81, 0x80, 0, 1, 0, 1, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
		0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4})
	f.Add([]byte{0, 0, 0x81, 0x80, 0, 0, 0, 1, 0xc0, 0})
	f.Fuzz(func(t *testing.T, msg []byte) {
		ips, _, err := parseDNSAnswer(msg)
		if err == nil {
			for _, ip := range ips {
				if ip.To4() == nil {
					t.Fatalf("non-IPv4 answer %v", ip)
				}
			}
		}
	})
}

func FuzzParseBlocklist(f *testing.F) {
	f.Add("ads.example.com\n0.0.0.0 t.example.net\n||m.example.org^\n# c\n")
	f.Add("*.wild.example\n\n!comment\n127.0.0.1 localhost\n")
	f.Fuzz(func(t *testing.T, list string) {
		set, err := parseBlocklist(strings.NewReader(list))
		if err != nil {
			return
		}
		for d := range set {
			if !validName(d) || strings.HasPrefix(d, ".") || d != strings.ToLower(d) {
				t.Fatalf("accepted bad domain %q", d)
			}
		}
	})
}

func FuzzParseStrategy(f *testing.F) {
	f.Add(string(builtinStrategy))
	f.Add(`{"version":2,"modes":["both"],"doh":["https://1.1.1.1/dns-query"]}`)
	f.Fuzz(func(t *testing.T, s string) {
		st, err := parseStrategy([]byte(s))
		if err != nil {
			return
		}
		for _, m := range st.Modes {
			if !validMode(m) || m == "none" {
				t.Fatalf("accepted mode %q", m)
			}
		}
	})
}
