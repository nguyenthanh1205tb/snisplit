package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

// cmdCheck runs real TLS handshakes to each host - once normally and once with
// the ClientHello split - and reports which ones the ISP blocks.
func cmdCheck(args []string) error {
	fset := flag.NewFlagSet("check", flag.ExitOnError)
	mode := fset.String("mode", "auto", "split mode to test: auto (try each), "+strings.Join(fragModes, ", "))
	delay := fset.Duration("delay", 10*time.Millisecond, "pause between pieces")
	timeout := fset.Duration("timeout", 8*time.Second, "per-handshake timeout")
	preset := fset.String("preset", "steam", "built-in lists to test when no hosts are given")
	var lists listFlag
	fset.Var(&lists, "list", "list file to test when no hosts are given (repeatable)")
	all := fset.Bool("all", false, "test every name in the list (default: a sample of 8)")
	fset.Parse(args)
	if *mode != "auto" && !validMode(*mode) {
		return fmt.Errorf("invalid --mode %q", *mode)
	}
	modes := []string{*mode}
	if *mode == "auto" {
		modes = autoModes
	}

	var hosts []string
	for _, h := range fset.Args() {
		hosts = append(hosts, normalizeName(h))
	}
	if len(hosts) == 0 {
		names, err := loadAll(*preset, lists)
		if err != nil {
			return err
		}
		hosts = exactNames(names)
		if !*all && len(hosts) > 8 {
			hosts = hosts[:8]
		}
	}

	res := newResolver(true)
	type row struct{ host, ip, direct, split string }
	rows := make([]row, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), *timeout)
			ips, err := res.lookup(ctx, h)
			cancel()
			if err != nil {
				rows[i] = row{h, "-", "DNS ERROR", "-"}
				return
			}
			ip := ips[0].String()
			r := row{h, ip, probe(h, ip, "none", 0, *timeout), ""}
			for _, m := range modes {
				r.split = probe(h, ip, m, *delay, *timeout)
				if r.split == "OK" {
					if *mode == "auto" {
						r.split = "OK (" + m + ")"
					}
					break
				}
			}
			rows[i] = r
		}(i, h)
	}
	wg.Wait()

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tIP\tDIRECT\tSPLIT")
	blocked, fixed := 0, 0
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.host, r.ip, r.direct, r.split)
		if r.direct != "OK" {
			blocked++
			if strings.HasPrefix(r.split, "OK") {
				fixed++
			}
		}
	}
	tw.Flush()
	fmt.Println()
	switch {
	case blocked == 0:
		fmt.Println("Nothing is blocked from here (or another bypass tool is already active).")
	case fixed == blocked:
		fmt.Printf("%d blocked, all reachable with splitting -> snisplit will work.\n", blocked)
	default:
		fmt.Printf("%d blocked, %d reachable with splitting. Try a longer --delay; the rest may be blocked by IP.\n", blocked, fixed)
	}
	return nil
}

func probe(host, ip, mode string, delay, timeout time.Duration) string {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return "NO CONNECT"
	}
	var conn net.Conn = c
	if mode != "none" {
		conn = &splitConn{Conn: c, mode: mode, delay: delay}
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	tc.SetDeadline(time.Now().Add(timeout))
	err = tc.Handshake()
	tc.Close()
	return classify(err)
}

func classify(err error) string {
	if err == nil {
		return "OK"
	}
	var ne net.Error
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.As(err, &certErr):
		return "CERT ERROR"
	case errors.As(err, &ne) && ne.Timeout():
		return "TIMEOUT"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed"):
		return "RESET"
	case strings.Contains(s, "eof"):
		return "CLOSED"
	}
	return "ERROR"
}
