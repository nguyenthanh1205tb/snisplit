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
	cfg      config
	dns      string
	preset   string
	lists    listFlag
	upstream string
}

func parseRunFlags(name string, args []string) *runOpts {
	o := &runOpts{}
	fset := flag.NewFlagSet(name, flag.ExitOnError)
	fset.StringVar(&o.upstream, "upstream", loadSettings().Upstream, "last-resort proxy for sites no split gets through: socks5://host:port or http://host:port (saved with 'snisplit upstream')")
	fset.StringVar(&o.cfg.listen, "listen", "127.0.0.1", "address to listen on")
	fset.IntVar(&o.cfg.port, "port", defaultPort, "HTTP proxy / PAC / status port")
	fset.BoolVar(&o.cfg.transparent, "transparent", true, "also listen on ports 443 and 80 for names the hosts file points at 127.0.0.1")
	fset.StringVar(&o.cfg.mode, "mode", "auto", "how to split the ClientHello: auto, "+strings.Join(fragModes, ", "))
	fset.DurationVar(&o.cfg.delay, "delay", 10*time.Millisecond, "pause between pieces")
	fset.DurationVar(&o.cfg.timeout, "timeout", 15*time.Second, "connect / handshake timeout")
	fset.BoolVar(&o.cfg.verbose, "v", false, "verbose logging")
	fset.StringVar(&o.dns, "dns", "doh", "resolver for upstream hosts: doh or system")
	fset.StringVar(&o.preset, "preset", "steam", "built-in lists for the PAC file, comma-separated ("+strings.Join(presets(), ", ")+", none)")
	fset.Var(&o.lists, "list", "extra list file for the PAC file (repeatable)")
	fset.Bool("autostart", false, "marks a login entry made with 'autostart on --no-tray' (no effect)")
	fset.Parse(args)
	fset.Visit(func(f *flag.Flag) {
		if f.Name == "delay" {
			o.cfg.delaySet = true
		}
	})
	return o
}

// validate checks the options and loads the name lists.
func (o *runOpts) validate() error {
	if o.cfg.mode != "auto" && !validMode(o.cfg.mode) {
		return fmt.Errorf("invalid --mode %q (use auto, %s)", o.cfg.mode, strings.Join(fragModes, ", "))
	}
	if o.dns != "doh" && o.dns != "system" {
		return fmt.Errorf("invalid --dns %q (use doh or system)", o.dns)
	}
	names, err := loadAll(o.preset, o.lists)
	if err != nil {
		return err
	}
	o.cfg.names = names
	up, err := parseUpstream(o.upstream)
	if err != nil {
		return err
	}
	o.cfg.upstream = up
	return nil
}

func cmdRun(args []string) error {
	o := parseRunFlags("run", args)
	if err := o.validate(); err != nil {
		return err
	}
	log.SetFlags(log.Ltime)
	if ip := net.ParseIP(o.cfg.listen); ip == nil || !ip.IsLoopback() {
		log.Printf("WARNING: listening on %s exposes an open proxy to your network", o.cfg.listen)
	}
	p := newProxy(o.cfg, newResolver(o.dns == "doh"), loadState(statePath()))
	p.applyStrategy(loadStrategy())
	st := p.strat.Load()
	log.Printf("snisplit %s  mode=%s delay=%s dns=%s list=%d names strategy=%d upstream=%s",
		version, o.cfg.mode, p.delay(), o.dns, len(o.cfg.names), st.Version, orNone(redactURL(o.cfg.upstream)))
	p.supervisorPID, _ = strconv.Atoi(os.Getenv("SNISPLIT_SUPERVISOR_PID"))
	p.restarts, _ = strconv.Atoi(os.Getenv("SNISPLIT_RESTARTS"))
	if err := p.listenAll(); err != nil {
		return err
	}
	p.applyAdblock(loadSettings())
	p.background(true)
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

// cmdStart launches "snisplit supervise" in the background; the supervisor
// runs the proxy and restarts it if it ever exits.
func cmdStart(args []string) error {
	o := parseRunFlags("start", args)
	if err := o.validate(); err != nil {
		return err
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
	cmd := exec.Command(exe, append([]string{"supervise"}, args...)...)
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
	return fmt.Errorf("proxy (supervisor pid %d) did not come up; see %s", pid, lp)
}

// cmdSupervise runs the proxy as a child process and restarts it whenever it
// exits, with exponential backoff (1s .. 30s). Not meant to be run by hand.
func cmdSupervise(args []string) error {
	log.SetFlags(log.Ltime)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	backoff := time.Second
	for restarts := 0; ; restarts++ {
		cmd := exec.Command(exe, append([]string{"run"}, args...)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Env = append(os.Environ(),
			"SNISPLIT_SUPERVISOR_PID="+strconv.Itoa(os.Getpid()),
			"SNISPLIT_RESTARTS="+strconv.Itoa(restarts))
		cmd.SysProcAttr = detachAttr()
		began := time.Now()
		err := cmd.Run()
		if time.Since(began) > time.Minute {
			backoff = time.Second // it ran fine for a while: restart quickly
		}
		log.Printf("supervisor: proxy exited (%v), restarting in %s", err, backoff)
		time.Sleep(backoff)
		backoff = min(backoff*2, 30*time.Second)
	}
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
	if s.SupervisorPID > 0 { // stop the supervisor first so it does not restart the proxy
		if sp, err := os.FindProcess(s.SupervisorPID); err == nil {
			sp.Kill()
		}
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
		if s.SupervisorPID > 0 {
			fmt.Printf("restarts  %d (supervisor pid %d)\n", s.Restarts, s.SupervisorPID)
		}
		fmt.Printf("traffic   %s, %d failed, %d needed another split mode, %d another address, %d via upstream\n",
			plural(s.Connections, "connection"), s.Failures, s.Retries, s.ViaOtherIP, s.ViaUpstream)
		if len(s.TopFailures) > 0 {
			fmt.Printf("failing   %s\n", strings.Join(s.TopFailures, ", "))
		}
		fmt.Printf("health    %s\n", describeHealth(s.Health))
		fmt.Printf("strategy  version %d\n", s.Strategy)
		fmt.Printf("upstream  %s\n", orNone(s.Upstream))
		if len(s.Learned) > 0 {
			fmt.Printf("learned   %d blocked sites found in browser mode: %s\n", len(s.Learned), strings.Join(s.Learned[:min(5, len(s.Learned))], ", "))
		}
		if a := s.Adblock; a != nil {
			fmt.Printf("adblock   on: %d domains, %d requests blocked\n", a.Domains, a.Blocked)
		} else {
			fmt.Println("adblock   off")
		}
	} else {
		fmt.Println("stopped")
	}
	fmt.Printf("hosts     %d names installed in %s\n", n, hostsPath())
	fmt.Printf("browser   %s\n", onOff(loadSettings().Browser))
	fmt.Printf("log       %s\n", logPath())
	return nil
}

func describeHealth(h health) string {
	when := ""
	if !h.Checked.IsZero() {
		when = fmt.Sprintf(" (checked %s ago)", time.Since(h.Checked).Round(time.Minute))
	}
	switch h.State {
	case "open":
		return h.Host + " is not blocked right now" + when
	case "ok":
		return fmt.Sprintf("OK: %s gets through with %q%s", h.Host, h.Mode, when)
	case "upstream":
		return "every split method is blocked; going through the upstream proxy" + when
	case "blocked":
		return "BLOCKED: " + h.Detail + when + " - see 'snisplit doctor'"
	}
	return "not checked yet"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// restartIfRunning restarts the background proxy so it picks up new settings.
func restartIfRunning() error {
	if _, err := getStatus(defaultPort); err != nil {
		return nil
	}
	if err := cmdStop(nil); err != nil {
		return err
	}
	return cmdStart(nil)
}

func cmdUpstream(args []string) error {
	s := loadSettings()
	if len(args) == 0 {
		u, _ := parseUpstream(s.Upstream)
		fmt.Printf("upstream: %s\n", orNone(redactURL(u)))
		fmt.Println("set with:  snisplit upstream socks5://host:port   (or http://host:port, user:pass@ allowed)")
		fmt.Println("remove:    snisplit upstream off")
		fmt.Println("It is used only for sites that no split method gets through.")
		return nil
	}
	if args[0] == "off" {
		s.Upstream = ""
	} else {
		u, err := parseUpstream(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("testing %s ... ", redactURL(u))
		if r := probeUpstream(u, "www.cloudflare.com", 10*time.Second); r != "OK" {
			fmt.Println(r)
			return fmt.Errorf("could not reach https://www.cloudflare.com through %s (%s); not saved", redactURL(u), r)
		}
		fmt.Println("OK")
		s.Upstream = args[0]
	}
	if err := saveSettings(s); err != nil {
		return err
	}
	fmt.Printf("upstream: %s\n", orNone(s.Upstream))
	return restartIfRunning()
}

// ---------------------------------------------------------------- autostart

const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

// approvedKey is where Task Manager's Startup apps page records an entry the
// user turned off: the Run value stays, and a binary value of the same name
// here starts with an odd byte (03 disabled, 02 enabled).
const approvedKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`

// startupDisabled reports whether approval data (raw bytes) marks an entry
// as turned off in Task Manager. No data means enabled.
func startupDisabled(data []byte) bool {
	return len(data) > 0 && data[0]&1 == 1
}

// regValue extracts the data of a REG_SZ value from "reg query" output.
func regValue(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "REG_SZ"); i >= 0 {
			return strings.TrimSpace(line[i+len("REG_SZ"):])
		}
	}
	return ""
}

// legacyAutostart reports a login entry written before v0.4.0, which starts
// the proxy without the tray icon (and was not an explicit --no-tray choice).
func legacyAutostart(val string) bool {
	return val != "" && !strings.Contains(val, " tray") && !strings.Contains(val, "--autostart")
}

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func cmdAutostart(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: snisplit autostart on [--no-tray] | off")
	}
	fset := flag.NewFlagSet("autostart", flag.ExitOnError)
	noTray := fset.Bool("no-tray", false, "start only the proxy at login, without the tray icon")
	fset.Parse(args[1:])
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
		val, what := fmt.Sprintf(`"%s" tray --start`, exe), "the proxy and its tray icon start"
		if *noTray { // "--autostart" tells the tray this was chosen, so it is not upgraded
			val, what = fmt.Sprintf(`"%s" start --autostart`, exe), "the proxy starts"
		}
		if out, err := exec.Command("reg", "add", runKey, "/v", "snisplit", "/t", "REG_SZ", "/d", val, "/f").CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		// Undo "Disable" from Task Manager, so the entry really runs again.
		exec.Command("reg", "delete", approvedKey, "/v", "snisplit", "/f").Run()
		fmt.Printf("autostart on: %s when you log in\n", what)
	case "off":
		exec.Command("reg", "delete", runKey, "/v", "snisplit", "/f").Run()
		exec.Command("reg", "delete", approvedKey, "/v", "snisplit", "/f").Run()
		fmt.Println("autostart off")
	default:
		return fmt.Errorf("usage: snisplit autostart on|off")
	}
	return nil
}
