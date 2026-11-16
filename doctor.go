package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// cmdDoctor checks the whole setup - proxy, hosts file, DNS, the ISP block
// and real connections through snisplit - and says how to fix what is wrong.
// Its output is meant to be pasted into a bug report.
func cmdDoctor(args []string) error {
	fset := flag.NewFlagSet("doctor", flag.ExitOnError)
	port := fset.Int("port", defaultPort, "port of the running proxy")
	preset := fset.String("preset", "steam", "list the hosts file should contain")
	fset.Parse(args)

	d := &doctor{}
	exe, _ := os.Executable()
	d.info("snisplit %s (%s/%s) at %s", version, runtime.GOOS, runtime.GOARCH, exe)

	// 1. proxy
	status, err := getStatus(*port)
	switch {
	case err != nil:
		d.fail("the proxy is not running", "start it: snisplit start")
	default:
		d.ok("proxy running: pid %d, %s, up %s, mode %s", status.PID, status.Version, status.Uptime, status.Mode)
		if status.Version != version {
			d.warn(fmt.Sprintf("the running proxy is %s but this command is %s", status.Version, version), "restart it: snisplit stop, then snisplit start")
		}
		if !status.Transparent {
			d.warn("transparent mode is off", "Steam needs it: snisplit stop, then snisplit start")
		}
		if status.Failures > 0 {
			d.warn(fmt.Sprintf("%d of %s failed", status.Failures, plural(status.Connections, "connection")),
				"failing: "+strings.Join(status.TopFailures, ", "))
		}
		switch h := status.Health; h.State {
		case "ok", "open":
			d.ok("self-test: %s", describeHealth(h))
		case "upstream":
			d.warn("self-test: "+describeHealth(h), "it works, but only through your upstream proxy")
		case "blocked":
			d.fail("self-test: "+describeHealth(h),
				"run 'snisplit update' (a newer version may have a way around it), or set an upstream proxy: snisplit upstream socks5://host:port")
		default:
			d.info("self-test: %s", describeHealth(h))
		}
		d.info("strategy version %d, %d sites learned in browser mode, upstream %s", status.Strategy, len(status.Learned), orNone(status.Upstream))
	}

	// 2. hosts file
	content, err := os.ReadFile(hostsPath())
	installed := installedNames(string(content))
	want, _ := loadAll(*preset, nil)
	have := map[string]bool{}
	for _, n := range installed {
		have[n] = true
	}
	var missing []string
	for _, n := range exactNames(want) {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	switch {
	case err != nil:
		d.fail("cannot read "+hostsPath()+": "+err.Error(), "")
	case len(installed) == 0:
		d.fail("no snisplit entries in "+hostsPath(), "as Administrator / with sudo: snisplit hosts install")
	case len(missing) > 0:
		d.warn(fmt.Sprintf("%d names installed, %d from the %s list missing (e.g. %s)", len(installed), len(missing), *preset, missing[0]),
			"as Administrator / with sudo: snisplit hosts update")
	default:
		d.ok("hosts file: %d names point to 127.0.0.1", len(installed))
	}

	// 3. what apps actually resolve
	const sample = "store.steampowered.com"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	addrs, err := net.DefaultResolver.LookupHost(ctx, sample)
	cancel()
	switch {
	case err != nil:
		d.warn(sample+" does not resolve: "+err.Error(), "")
	case len(addrs) > 0 && net.ParseIP(addrs[0]) != nil && net.ParseIP(addrs[0]).IsLoopback():
		d.ok("%s resolves to %s, so apps go through snisplit", sample, addrs[0])
	default:
		d.warn(fmt.Sprintf("%s resolves to %s, not 127.0.0.1 - apps bypass snisplit", sample, strings.Join(addrs, ", ")),
			"install the hosts entries, then flush the DNS cache (Windows: ipconfig /flushdns)")
	}

	// 4. DNS-over-HTTPS, used by snisplit to find the real servers
	strat := loadStrategy()
	res := newResolver(true)
	res.setEndpoints(strat.DoH)
	var dohOK, dohBad []string
	for _, ep := range strat.DoH {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _, err := res.doh(ctx, ep, dnsQ{host: sample, qtype: typeA})
		cancel()
		host := strings.TrimSuffix(strings.TrimPrefix(ep, "https://"), "/dns-query")
		if err != nil {
			dohBad = append(dohBad, host)
		} else {
			dohOK = append(dohOK, host)
		}
	}
	switch {
	case len(dohOK) == 0:
		d.fail("no DNS-over-HTTPS server answers", "snisplit falls back to system DNS and the last good answers; check your connection")
	case len(dohBad) > 0:
		d.info("DNS-over-HTTPS: %d of %d servers answer (not reachable: %s)", len(dohOK), len(strat.DoH), strings.Join(dohBad, ", "))
	default:
		d.ok("DNS-over-HTTPS: all %d servers answer", len(dohOK))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
	ips, err := res.lookup(ctx, sample)
	cancel()
	if err != nil || len(ips) == 0 {
		d.fail("cannot resolve "+sample+" over DNS-over-HTTPS or system DNS", "check your internet connection")
	} else {
		d.ok("upstream DNS works: %s is %s", sample, ips[0])
		// 5. is the ISP actually blocking? (informational)
		if r := probe(sample, ips[0].String(), "none", 0, 6*time.Second); r == "OK" {
			d.info("a direct connection to %s works - it is not blocked from this network", sample)
		} else {
			d.info("a direct connection to %s is blocked (%s) - this is what snisplit gets around", sample, r)
		}
	}

	// 6. real connections through the transparent listener
	if status != nil && status.Transparent {
		for _, h := range []string{"store.steampowered.com", "steamcommunity.com", "store.fastly.steamstatic.com"} {
			start := time.Now()
			if r := probe(h, "127.0.0.1", "none", 0, 12*time.Second); r == "OK" {
				d.ok("%s through snisplit: OK (%d ms)", h, time.Since(start).Milliseconds())
			} else {
				d.fail(fmt.Sprintf("%s through snisplit: %s", h, r), "see the log: "+logPath())
			}
		}
	}

	// 7. upstream proxy and browser mode
	set := loadSettings()
	if u, err := parseUpstream(set.Upstream); err != nil {
		d.fail("saved upstream proxy is invalid: "+err.Error(), "snisplit upstream off")
	} else if u != nil {
		if r := probeUpstream(u, "www.cloudflare.com", 10*time.Second); r == "OK" {
			d.ok("upstream proxy %s works", redactURL(u))
		} else {
			d.warn(fmt.Sprintf("upstream proxy %s does not work (%s)", redactURL(u), r), "start it, or remove it: snisplit upstream off")
		}
	}
	if set.Adblock {
		switch a := status; {
		case a == nil:
		case a.Adblock == nil:
			d.warn("ad blocking is on but the running proxy has not loaded it", "restart it: snisplit stop, then snisplit start")
		case a.Adblock.Domains == 0:
			d.warn("ad blocking is on but no list is loaded yet", "snisplit adblock update")
		case time.Since(a.Adblock.Updated) > 72*time.Hour:
			d.warn(fmt.Sprintf("the ad block list is %s old", time.Since(a.Adblock.Updated).Round(time.Hour)), "snisplit adblock update")
		default:
			d.ok("ad blocking: %d domains, %d requests blocked", a.Adblock.Domains, a.Adblock.Blocked)
		}
		if !set.Browser && !set.DNS {
			d.warn("ad blocking works in browser mode or dns mode, and both are off", "snisplit browser on   (or for all apps: snisplit dns on)")
		}
	}
	if set.Browser {
		if cur, _ := systemPAC(); cur != browserPAC() {
			d.warn("browser mode is on, but the system proxy setting was changed to "+orNone(cur), "snisplit browser on")
		} else {
			d.ok("browser mode on: browsers use %s", browserPAC())
		}
	}
	if set.DNS {
		here, other := systemDNSStatus()
		switch {
		case status != nil && status.DNS == nil:
			d.fail("dns mode is on but snisplit's DNS server is not running (port 53 taken?)", "see the log; snisplit dns off puts the DNS setting back")
		case askLocalDNS(3*time.Second) != nil:
			d.fail("snisplit's DNS server on 127.0.0.1:53 does not answer", "snisplit stop, then snisplit start")
		case len(other) > 0:
			d.warn("these network adapters do not use snisplit for DNS: "+strings.Join(other, ", "), "snisplit dns on")
		case status != nil:
			s := status.DNS
			d.ok("dns mode on (%s): %d lookups, %d ads blocked, %d sent through snisplit", strings.Join(here, ", "), s.Queries, s.AdsBlocked, s.Redirected)
		}
	}
	if set.Share && status != nil {
		if status.Share == "" {
			d.warn("sharing with phones is on but this computer has no local network address", "connect to Wi-Fi or a cable, then restart snisplit")
		} else {
			d.ok("shared with phones on this network: %s", status.Share)
		}
	}

	// 8. Windows: login entry and other bypass tools
	if runtime.GOOS == "windows" {
		switch v := autostartValue(); {
		case v == "":
			d.warn("snisplit does not start at login", "snisplit autostart on")
		case autostartDisabled():
			d.warn("snisplit is turned off in Task Manager's Startup apps, so it does not start at login",
				"snisplit autostart on (or tick 'Start at login' in the tray icon menu)")
		case legacyAutostart(v):
			d.warn("the login entry starts the proxy without the tray icon", "snisplit autostart on")
		default:
			d.ok("starts at login")
		}
		if out, err := exec.Command("sc", "query", "GoodbyeDPI").Output(); err == nil && strings.Contains(string(out), "RUNNING") {
			d.warn("GoodbyeDPI is also running", "only one bypass tool is needed: stop GoodbyeDPI or snisplit")
		}
	}

	fmt.Println()
	switch {
	case d.fails > 0:
		return fmt.Errorf("%d problem(s), %d warning(s)", d.fails, d.warns)
	case d.warns > 0:
		fmt.Printf("No problems, %d warning(s).\n", d.warns)
	default:
		fmt.Println("Everything looks fine.")
	}
	return nil
}

type doctor struct{ fails, warns int }

func (d *doctor) ok(format string, a ...any)   { fmt.Printf("  [ OK ] "+format+"\n", a...) }
func (d *doctor) info(format string, a ...any) { fmt.Printf("  [INFO] "+format+"\n", a...) }

func (d *doctor) warn(msg, fix string) {
	d.warns++
	d.print("WARN", msg, fix)
}

func (d *doctor) fail(msg, fix string) {
	d.fails++
	d.print("FAIL", msg, fix)
}

func (d *doctor) print(tag, msg, fix string) {
	fmt.Printf("  [%s] %s\n", tag, msg)
	if fix != "" {
		fmt.Printf("         -> %s\n", fix)
	}
}
