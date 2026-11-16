package main

// Sharing with phones ("snisplit share on"): the proxy also listens on the
// local network, so a phone on the same Wi-Fi can use it through an automatic
// proxy (PAC) address, with the same unblocking and ad blocking as this
// computer. Only this computer and devices on the local network get in.

import (
	"errors"
	"fmt"
	"html"
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

// servePhonePage explains, in Vietnamese, how to set a phone up. On this
// computer it also shows a QR code that opens the same page on the phone.
func (p *proxy) servePhonePage(c net.Conn, local bool) {
	ip := lanIP()
	var body string
	switch {
	case !p.cfg.share:
		body = `<h1>Chưa bật chia sẻ</h1><p>Trên máy tính, bật <b>Share with phones</b> ở biểu tượng snisplit cạnh đồng hồ, hoặc chạy <code>snisplit share on</code>.</p>`
	case ip == nil:
		body = `<h1>Không thấy mạng nội bộ</h1><p>Máy tính chưa kết nối Wi-Fi hoặc mạng dây trong nhà.</p>`
	default:
		pac := html.EscapeString(sharedURL(ip, p.cfg.port, "/proxy.pac?all=1"))
		page := html.EscapeString(sharedURL(ip, p.cfg.port, phonePath))
		if local {
			body += `<h1>Dùng snisplit trên điện thoại</h1>
<p>Điện thoại phải dùng <b>cùng Wi-Fi</b> với máy tính này. Mở camera điện thoại và quét mã:</p>
<p class="qr"><img src="` + phoneQRPath + `" alt="Mã QR" width="232" height="232"></p>
<p class="muted">Hoặc mở trên điện thoại: <code>` + page + `</code></p>`
		} else {
			body += `<h1>Dùng snisplit trên điện thoại này</h1>`
		}
		body += `<h2>1. Sao chép địa chỉ này</h2>
<div class="copy"><code id="pac">` + pac + `</code><button onclick="cp()">Sao chép</button></div>
<h2>2. Dán vào cài đặt Wi-Fi</h2>
<p><b>iPhone, iPad:</b> Cài đặt → Wi-Fi → bấm <b>ⓘ</b> cạnh mạng đang dùng → <b>Định cấu hình proxy</b> → <b>Tự động</b> → dán vào ô <b>URL</b> → Lưu.</p>
<p><b>Android:</b> Cài đặt → Wi-Fi → bấm vào (hoặc bánh răng cạnh) mạng đang dùng → Sửa / Nâng cao → <b>Proxy</b> → <b>Tự động cấu hình proxy</b> (Proxy Auto-Config) → dán vào ô <b>URL PAC</b> → Lưu.</p>
<h2>Lưu ý</h2>
<ul><li>Máy tính phải đang bật và chạy snisplit. Khi máy tính tắt, điện thoại tự đi thẳng, vẫn dùng mạng bình thường.</li>
<li>Trang bị chặn mở được, và nếu máy tính bật chặn quảng cáo thì điện thoại cũng được chặn.</li>
<li>Ứng dụng nào không theo cài đặt proxy của Wi-Fi thì không được áp dụng.</li>
<li>Muốn tắt: vào lại chỗ Proxy, chọn <b>Tắt</b> / <b>Không</b>.</li></ul>`
	}
	doc := `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>snisplit trên điện thoại</title><style>
:root{--bg:#fff;--fg:#14181f;--muted:#5b6472;--card:#f3f5f8;--accent:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e8ecf2;--muted:#9aa4b2;--card:#1a2029;--accent:#6ea0ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:640px;margin:0 auto;padding:24px 16px 48px}h1{font-size:24px;margin:0 0 12px}h2{font-size:18px;margin:24px 0 8px}
code{font:14px ui-monospace,Consolas,monospace;word-break:break-all}.muted{color:var(--muted)}
.qr{background:#fff;display:inline-block;padding:12px;border-radius:12px}
.copy{display:flex;gap:8px;align-items:center;background:var(--card);padding:12px;border-radius:10px}
.copy code{flex:1}button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:10px 14px;font:inherit;cursor:pointer}
li{margin:4px 0}</style></head><body><main>` + body + `</main><script>
function cp(){var t=document.getElementById('pac').textContent,b=event.target;
function ok(){b.textContent='Đã sao chép'}
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok);return}
var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
try{document.execCommand('copy');ok()}catch(e){}document.body.removeChild(a)}</script></body></html>`
	writeResponse(c, "text/html; charset=utf-8", []byte(doc))
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
