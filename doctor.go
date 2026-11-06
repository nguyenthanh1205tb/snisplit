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
	ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
	ips, err := newResolver(true).lookup(ctx, sample)
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

	// 7. Windows: login entry and other bypass tools
	if runtime.GOOS == "windows" {
		switch v := autostartValue(); {
		case v == "":
			d.warn("snisplit does not start at login", "snisplit autostart on")
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
