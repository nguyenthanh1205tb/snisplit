package main

// The phone setup page ("snisplit share on"). An iPhone gets a configuration
// profile that sets the Wi-Fi's automatic proxy in a few taps (iOS lets no
// web page or QR code change proxy settings by itself); Android, which has
// no such thing, gets the address to paste and only its own steps.

import (
	"crypto/rand"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
)

const phoneProfilePath = "/snisplit/snisplit.mobileconfig"

// phoneKind guesses the device from its browser: "ios", "android" or "".
func phoneKind(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "iPod"):
		return "ios"
	case strings.Contains(ua, "Android"):
		return "android"
	}
	return ""
}

// servePhonePage explains, in Vietnamese, how to set a phone up. On this
// computer it shows a QR code that opens the page on the phone.
func (p *proxy) servePhonePage(c net.Conn, req *http.Request, local bool) {
	ip := lanIP()
	var body string
	switch {
	case !p.cfg.share:
		body = `<h1>Chưa bật chia sẻ</h1><p>Trên máy tính, bật <b>Share with phones</b> ở biểu tượng snisplit cạnh đồng hồ, hoặc chạy <code>snisplit share on</code>.</p>`
	case ip == nil:
		body = `<h1>Không thấy mạng nội bộ</h1><p>Máy tính chưa kết nối Wi-Fi hoặc mạng dây trong nhà.</p>`
	default:
		pac := html.EscapeString(sharedURL(ip, p.cfg.port, "/proxy.pac?all=1"))
		kind := phoneKind(req.UserAgent())
		if local {
			kind = ""
			body = `<h1>Dùng snisplit trên điện thoại</h1>
<p>Điện thoại phải dùng <b>cùng Wi-Fi</b> với máy tính này. Mở camera điện thoại và quét mã:</p>
<p class="qr"><img src="` + phoneQRPath + `" alt="Mã QR" width="232" height="232"></p>
<p class="muted">Hoặc mở trên điện thoại: <code>` + html.EscapeString(sharedURL(ip, p.cfg.port, phonePath)) + `</code><br>
iPhone: trang đó cho tải một hồ sơ cài sẵn mọi thứ. Android: dán một địa chỉ vào cài đặt Wi-Fi.</p>`
		} else {
			body = `<h1>Dùng snisplit trên điện thoại này</h1>`
		}
		copyBox := `<div class="row"><code id="pac">` + pac + `</code><button type="button" onclick="cp(this)">Sao chép</button></div>`
		iosManual := `<p>Cài đặt → Wi-Fi → bấm <b>ⓘ</b> cạnh mạng đang dùng → <b>Định cấu hình proxy</b> → <b>Tự động</b> → dán địa chỉ trên vào ô <b>URL</b> → Lưu.</p>`
		ios := `<h2>iPhone, iPad: cài tự động</h2>
<form action="` + phoneProfilePath + `" method="get">
<label for="ssid">Tên Wi-Fi đang dùng (đúng chữ hoa, chữ thường):</label>
<div class="row"><input id="ssid" name="ssid" value="` + html.EscapeString(currentSSID()) + `" required maxlength="32" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="Ví dụ: Nha Minh 5G">
<button type="submit">Tải hồ sơ</button></div></form>
<ol><li>Bấm <b>Cho phép</b> khi iPhone hỏi tải hồ sơ cấu hình.</li>
<li>Mở <b>Cài đặt</b> → <b>Đã tải về hồ sơ</b> (ngay dưới tên bạn) → <b>Cài đặt</b> → nhập mật mã máy.</li>
<li>Nếu được hỏi, nhập <b>mật khẩu Wi-Fi</b>. Xong.</li></ol>
<p class="muted">Mở trang này bằng <b>Safari</b>: trình duyệt khác không tải được hồ sơ. iOS ghi "Chưa được xác minh" vì hồ sơ không có chữ ký của công ty; hồ sơ chỉ đặt proxy cho Wi-Fi này.
Gỡ: Cài đặt → Cài đặt chung → VPN &amp; Quản lý thiết bị → snisplit → Xoá hồ sơ, rồi bấm vào Wi-Fi và nhập lại mật khẩu.</p>`
		android := `<h2>Android</h2>
<p><b>1.</b> Sao chép địa chỉ này:</p>` + copyBox + `
<p><b>2.</b> Cài đặt → Wi-Fi → bấm vào mạng đang dùng (hoặc bánh răng ⚙ cạnh nó) → <b>Sửa</b> hoặc <b>Nâng cao</b> → <b>Proxy</b> → <b>Tự động</b> (Proxy Auto-Config) → dán vào ô <b>URL PAC</b> → <b>Lưu</b>.</p>
<p class="muted">Samsung: bấm ⚙ cạnh Wi-Fi → <b>Xem thêm</b> → Proxy → Tự động. Muốn tắt: chọn Proxy → <b>Không</b>.</p>`
		switch kind {
		case "ios":
			body += ios + `<details><summary>Cách làm tay</summary>` + copyBox + iosManual + `</details>`
		case "android":
			body += android
		default:
			body += ios + `<details><summary>iPhone: cách làm tay</summary>` + copyBox + iosManual + `</details>` + android
		}
		body += `<h2>Lưu ý</h2>
<ul><li>Máy tính phải đang bật và chạy snisplit. Khi máy tính tắt, điện thoại tự đi thẳng, vẫn dùng mạng bình thường.</li>
<li>Trang bị chặn mở được, và nếu máy tính bật chặn quảng cáo thì điện thoại cũng được chặn.</li>
<li>Chỉ áp dụng khi dùng Wi-Fi này, không ảnh hưởng 4G. Ứng dụng nào không theo cài đặt proxy thì không được áp dụng.</li></ul>`
	}
	writeResponse(c, "text/html; charset=utf-8", []byte(phonePageHead+body+phonePageTail))
}

const phonePageHead = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>snisplit trên điện thoại</title><style>
:root{--bg:#fff;--fg:#14181f;--muted:#5b6472;--card:#f3f5f8;--line:#d5dae2;--accent:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e8ecf2;--muted:#9aa4b2;--card:#1a2029;--line:#2c3440;--accent:#6ea0ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:640px;margin:0 auto;padding:24px 16px 48px}h1{font-size:24px;margin:0 0 12px}h2{font-size:18px;margin:28px 0 8px}
code{font:14px ui-monospace,Consolas,monospace;word-break:break-all}.muted{color:var(--muted);font-size:14px}
.qr{background:#fff;display:inline-block;padding:12px;border-radius:12px}
.row{display:flex;gap:8px;align-items:center;background:var(--card);padding:10px;border-radius:10px;margin:8px 0}
.row code,.row input{flex:1;min-width:0}
input{font:inherit;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg)}
button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:10px 14px;font:inherit;cursor:pointer;white-space:nowrap}
details{margin:12px 0}summary{cursor:pointer;color:var(--muted)}li{margin:4px 0}label{display:block;margin-top:8px}
</style></head><body><main>`

const phonePageTail = `</main><script>
function cp(b){var t=document.getElementById('pac').textContent;
function ok(){b.textContent='Đã sao chép'}
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok);return}
var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
try{document.execCommand('copy');ok()}catch(e){}document.body.removeChild(a)}
</script></body></html>`

// servePhoneProfile sends an iOS configuration profile for the Wi-Fi named
// in ?ssid=, with this computer's PAC as its automatic proxy.
func (p *proxy) servePhoneProfile(c net.Conn, req *http.Request) {
	ssid := strings.TrimSpace(req.URL.Query().Get("ssid"))
	ip := lanIP()
	if !p.cfg.share || ip == nil || ssid == "" || len(ssid) > 32 {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	body := mobileconfig(ssid, sharedURL(ip, p.cfg.port, "/proxy.pac?all=1"))
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/x-apple-aspen-config\r\n"+
		"Content-Disposition: attachment; filename=\"snisplit.mobileconfig\"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	io.WriteString(c, body)
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// mobileconfig builds the profile: one Wi-Fi payload for ssid whose proxy is
// the PAC at pac, falling back to a direct connection when the computer is
// off. It holds no password; iOS asks for it while installing. The fixed
// identifiers make a newer profile replace an older one.
func mobileconfig(ssid, pac string) string {
	x := html.EscapeString // also valid XML escaping
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key><string>com.apple.wifi.managed</string>
			<key>PayloadVersion</key><integer>1</integer>
			<key>PayloadIdentifier</key><string>io.github.nguyenthanh1205tb.snisplit.wifi</string>
			<key>PayloadUUID</key><string>` + newUUID() + `</string>
			<key>PayloadDisplayName</key><string>Wi-Fi ` + x(ssid) + ` qua snisplit</string>
			<key>SSID_STR</key><string>` + x(ssid) + `</string>
			<key>HIDDEN_NETWORK</key><false/>
			<key>AutoJoin</key><true/>
			<key>EncryptionType</key><string>Any</string>
			<key>ProxyType</key><string>Auto</string>
			<key>ProxyPACURL</key><string>` + x(pac) + `</string>
			<key>ProxyPACFallbackAllowed</key><true/>
		</dict>
	</array>
	<key>PayloadDisplayName</key><string>snisplit</string>
	<key>PayloadDescription</key><string>Vào được trang bị chặn và chặn quảng cáo qua máy tính chạy snisplit, khi dùng Wi-Fi ` + x(ssid) + `.</string>
	<key>PayloadIdentifier</key><string>io.github.nguyenthanh1205tb.snisplit</string>
	<key>PayloadOrganization</key><string>snisplit</string>
	<key>PayloadRemovalDisallowed</key><false/>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadUUID</key><string>` + newUUID() + `</string>
	<key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`
}
