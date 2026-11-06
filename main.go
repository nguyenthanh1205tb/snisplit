// Command snisplit bypasses SNI-based DPI blocking by splitting the TLS
// ClientHello so that no single packet carries the full server name.
package main

import (
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `snisplit - bypass SNI-based DPI blocking by splitting the TLS ClientHello

Usage:
  snisplit run [flags]          run the proxy in the foreground (Ctrl+C to stop)
  snisplit start [flags]        run the proxy in the background (restarted if it ever exits)
  snisplit stop                 stop the background proxy
  snisplit status               show state and traffic counters
  snisplit check [host ...]     test which hosts are blocked and whether splitting helps
  snisplit hosts install        point the list's hostnames at 127.0.0.1 (admin/sudo)
  snisplit hosts add <name>...  add hostnames (admin/sudo)
  snisplit hosts del <name>...  remove hostnames (admin/sudo)
  snisplit hosts remove         remove all snisplit entries from the hosts file (admin/sudo)
  snisplit hosts show           print the hostnames that would be installed
  snisplit autostart on|off     start the proxy when you log in (Windows)
  snisplit version              print the version

Typical setup (Steam):
  snisplit check                # confirm the block and that splitting works
  snisplit hosts install        # once, as Administrator / with sudo
  snisplit start                # then restart Steam

Run "snisplit <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = cmdRun(args)
	case "start":
		err = cmdStart(args)
	case "supervise": // internal: started by "snisplit start"
		err = cmdSupervise(args)
	case "stop":
		err = cmdStop(args)
	case "status":
		err = cmdStatus(args)
	case "check":
		err = cmdCheck(args)
	case "hosts":
		err = cmdHosts(args)
	case "autostart":
		err = cmdAutostart(args)
	case "version", "--version", "-version":
		fmt.Println("snisplit", version)
	case "help", "-h", "--help", "-help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
