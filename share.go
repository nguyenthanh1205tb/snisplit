package main

// Sharing with phones ("snisplit share on"): the proxy also listens on the
// local network, so a phone on the same Wi-Fi can use it through an automatic
// proxy (PAC) address, with the same unblocking and ad blocking as this
// computer. Only this computer and devices on the local network get in.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"rsc.io/qr"
)

const (
	phonePath   = "/snisplit/phone"
	phoneQRPath = "/snisplit/phone.png"
)

func isLoopback(a net.Addr) bool {
	t, ok := a.(*net.TCPAddr)
	return ok && t.IP.IsLoopback()
}

// localPeer reports whether a is this computer or a device on the local
// network (private and link-local addresses).
func localPeer(a net.Addr) bool {
	t, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip := t.IP
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// lanOnly drops connections from outside the local network.
func lanOnly(h func(net.Conn)) func(net.Conn) {
	return func(c net.Conn) {
		if !localPeer(c.RemoteAddr()) {
			c.Close()
			return
		}
		h(c)
	}
}

// lanIP is this computer's address on the local network.
func lanIP() net.IP {
	if c, err := net.Dial("udp", "8.8.8.8:53"); err == nil { // sends nothing, picks the route
		ip := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		if ip.To4() != nil && ip.IsPrivate() {
			return ip.To4()
		}
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
			return n.IP.To4()
		}
	}
	return nil
}

func sharedURL(ip net.IP, port int, path string) string {
	return "http://" + net.JoinHostPort(ip.String(), strconv.Itoa(port)) + path
}

// sharedPAC is the address phones put in their proxy settings ("" when
// sharing is off).
func (p *proxy) sharedPAC() string {
	if !p.cfg.share {
		return ""
	}
	if ip := lanIP(); ip != nil {
		return sharedURL(ip, p.cfg.port, "/proxy.pac?all=1")
	}
	return ""
}

func (p *proxy) servePhoneQR(c net.Conn) {
	ip := lanIP()
	if !p.cfg.share || ip == nil {
		io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	code, err := qr.Encode(sharedURL(ip, p.cfg.port, phonePath), qr.M)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	code.Scale = 8
	writeResponse(c, "image/png", code.PNG())
}

// printQR draws text as a QR code in the terminal, two rows per line.
func printQR(w io.Writer, text string) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return
	}
	const quiet = 2
	var b strings.Builder
	for y := -quiet; y < code.Size+quiet; y += 2 {
		b.WriteString("  ")
		for x := -quiet; x < code.Size+quiet; x++ {
			top, bottom := code.Black(x, y), code.Black(x, y+1)
			switch { // light modules are drawn, so it reads on dark terminals
			case !top && !bottom:
				b.WriteString("█")
			case !top:
				b.WriteString("▀")
			case !bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	io.WriteString(w, b.String())
}

// cmdShare turns sharing with phones on the local network on or off.
func cmdShare(args []string) error {
	s := loadSettings()
	errPath := settingsPath() + ".share.err"
	if len(args) == 0 || args[0] == "status" {
		fmt.Printf("share with phones: %s\n", onOff(s.Share))
		if st, err := getStatus(defaultPort); err == nil && st.Share != "" {
			showShare(st.Share)
		}
		fmt.Println("turn on with:  snisplit share on    (phones on the same Wi-Fi use snisplit)")
		fmt.Println("turn off with: snisplit share off")
		return nil
	}
	switch args[0] {
	case "on":
		if lanIP() == nil {
			return errors.New("this computer is not on a local network (Wi-Fi or cable)")
		}
		if hasFirewall() {
			fmt.Println("Windows will ask for administrator rights to let phones reach snisplit through the firewall...")
			if err := asAdmin(errPath, firewallAllow, "share", "firewall", "add"); err != nil {
				return fmt.Errorf("could not open the firewall: %v", err)
			}
		}
		s.Share = true
		if err := saveSettings(s); err != nil {
			return err
		}
		if err := startOrRestart(); err != nil {
			return err
		}
		st, err := getStatus(defaultPort)
		if err != nil || st.Share == "" {
			return errors.New("snisplit did not start sharing; see " + logPath())
		}
		fmt.Println("share on: phones on the same Wi-Fi can use snisplit.")
		showShare(st.Share)
	case "off":
		s.Share = false
		if err := saveSettings(s); err != nil {
			return err
		}
		restartIfRunning()
		if hasFirewall() {
			if err := asAdmin(errPath, firewallRemove, "share", "firewall", "remove"); err != nil {
				fmt.Println("firewall rule left in place:", err)
			}
		}
		fmt.Println("share off (set the phones' proxy back to Off)")
	case "firewall": // internal: run as administrator by "share on/off"
		if len(args) < 2 {
			return errors.New("usage: snisplit share firewall add|remove")
		}
		run := firewallAllow
		if args[1] == "remove" {
			run = firewallRemove
		}
		return writeErr(errPath, run())
	default:
		return errors.New("usage: snisplit share on|off")
	}
	return nil
}

func showShare(pac string) {
	page := strings.Replace(pac, "/proxy.pac?all=1", phonePath, 1)
	fmt.Println()
	fmt.Println("Scan with the phone's camera (same Wi-Fi), then follow the page:")
	printQR(os.Stdout, page)
	fmt.Println("  setup page:  ", page)
	fmt.Println("  proxy (PAC): ", pac)
}
