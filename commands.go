package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultPort = 8881

type runOpts struct {
	cfg    config
	dns    string
	preset string
	list   string
}

func parseRunFlags(name string, args []string) *runOpts {
	o := &runOpts{}
	fset := flag.NewFlagSet(name, flag.ExitOnError)
	fset.StringVar(&o.cfg.listen, "listen", "127.0.0.1", "address to listen on")
	fset.IntVar(&o.cfg.port, "port", defaultPort, "HTTP proxy / PAC / status port")
	fset.BoolVar(&o.cfg.transparent, "transparent", true, "also listen on ports 443 and 80 for names the hosts file points at 127.0.0.1")
	fset.StringVar(&o.cfg.mode, "mode", "both", "how to split the ClientHello: "+strings.Join(fragModes, ", "))
	fset.DurationVar(&o.cfg.delay, "delay", 10*time.Millisecond, "pause between pieces")
	fset.DurationVar(&o.cfg.timeout, "timeout", 15*time.Second, "connect / handshake timeout")
	fset.BoolVar(&o.cfg.verbose, "v", false, "verbose logging")
	fset.StringVar(&o.dns, "dns", "doh", "resolver for upstream hosts: doh or system")
	fset.StringVar(&o.preset, "preset", "steam", "built-in list for the PAC file ("+strings.Join(presets(), ", ")+")")
	fset.StringVar(&o.list, "list", "", "use this list file instead of a preset")
	fset.Parse(args)
	return o
}

func cmdRun(args []string) error {
	o := parseRunFlags("run", args)
	if !validMode(o.cfg.mode) {
		return fmt.Errorf("invalid --mode %q (use %s)", o.cfg.mode, strings.Join(fragModes, ", "))
	}
	if o.dns != "doh" && o.dns != "system" {
		return fmt.Errorf("invalid --dns %q (use doh or system)", o.dns)
	}
	names, err := loadNames(o.preset, o.list)
	if err != nil {
		return err
	}
	o.cfg.names = names
	if ip := net.ParseIP(o.cfg.listen); ip == nil || !ip.IsLoopback() {
		log.Printf("WARNING: listening on %s exposes an open proxy to your network", o.cfg.listen)
	}

	log.SetFlags(log.Ltime)
	log.Printf("snisplit %s  mode=%s delay=%s dns=%s list=%d names", version, o.cfg.mode, o.cfg.delay, o.dns, len(names))
	p := newProxy(o.cfg, newResolver(o.dns == "doh"))
	if err := p.listenAll(); err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("stopping")
	p.close()
	return nil
}

// ---------------------------------------------------------------- background

func logPath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "snisplit")
	os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "snisplit.log")
}

func getStatus(port int) (*statusInfo, error) {
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Get("http://127.0.0.1:" + strconv.Itoa(port) + statusPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var s statusInfo
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("something else is listening on port %d", port)
	}
	return &s, nil
}

func cmdStart(args []string) error {
	o := parseRunFlags("start", args)
	if !validMode(o.cfg.mode) {
		return fmt.Errorf("invalid --mode %q", o.cfg.mode)
	}
	if s, err := getStatus(o.cfg.port); err == nil {
		fmt.Printf("already running (pid %d, up %s)\n", s.PID, s.Uptime)
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	lp := logPath()
	if fi, err := os.Stat(lp); err == nil && fi.Size() > 5<<20 {
		os.Rename(lp, lp+".old")
	}
	f, err := os.OpenFile(lp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.Command(exe, append([]string{"run"}, args...)...)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()
	for i := 0; i < 30; i++ {
		time.Sleep(200 * time.Millisecond)
		if s, err := getStatus(o.cfg.port); err == nil {
			fmt.Printf("snisplit started (pid %d), log: %s\n", s.PID, lp)
			return nil
		}
	}
	return fmt.Errorf("proxy (pid %d) did not come up; see %s", pid, lp)
}

func cmdStop(args []string) error {
	fset := flag.NewFlagSet("stop", flag.ExitOnError)
	port := fset.Int("port", defaultPort, "port of the running proxy")
	fset.Parse(args)
	s, err := getStatus(*port)
	if err != nil {
		fmt.Println("not running")
		return nil
	}
	proc, err := os.FindProcess(s.PID)
	if err != nil {
		return err
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("cannot stop pid %d: %v", s.PID, err)
	}
	for i := 0; i < 20; i++ {
		time.Sleep(150 * time.Millisecond)
		if _, err := getStatus(*port); err != nil {
			fmt.Printf("stopped (pid %d)\n", s.PID)
			return nil
		}
	}
	return errors.New("proxy still answering after kill")
}

func cmdStatus(args []string) error {
	fset := flag.NewFlagSet("status", flag.ExitOnError)
	port := fset.Int("port", defaultPort, "port of the running proxy")
	fset.Parse(args)
	hosts, _ := os.ReadFile(hostsPath())
	n := len(installedNames(string(hosts)))
	if s, err := getStatus(*port); err == nil {
		fmt.Printf("running   pid %d, version %s, up %s, mode %s, transparent %v, port %d\n",
			s.PID, s.Version, s.Uptime, s.Mode, s.Transparent, s.Port)
	} else {
		fmt.Println("stopped")
	}
	fmt.Printf("hosts     %d names installed in %s\n", n, hostsPath())
	fmt.Printf("log       %s\n", logPath())
	return nil
}

// ---------------------------------------------------------------- autostart

const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

func cmdAutostart(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: snisplit autostart on|off")
	}
	if runtime.GOOS != "windows" {
		fmt.Println("On macOS/Linux use Homebrew services:")
		fmt.Println("  brew services start snisplit     # start now and at login")
		fmt.Println("  brew services stop snisplit")
		return nil
	}
	switch args[0] {
	case "on":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		val := fmt.Sprintf(`"%s" start`, exe)
		if out, err := exec.Command("reg", "add", runKey, "/v", "snisplit", "/t", "REG_SZ", "/d", val, "/f").CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		fmt.Println("autostart on: snisplit starts when you log in")
	case "off":
		exec.Command("reg", "delete", runKey, "/v", "snisplit", "/f").Run()
		fmt.Println("autostart off")
	default:
		return fmt.Errorf("usage: snisplit autostart on|off")
	}
	return nil
}
