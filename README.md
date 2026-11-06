# snisplit

A tiny local proxy that gets around **SNI-based DPI blocking** — the kind of
ISP filter that reads the website name from the start of an HTTPS connection
and resets it. Written for Steam being blocked in Vietnam, works for any site
blocked the same way.

* **No driver, no VPN.** Traffic still goes straight to the real server; only
  the first packet of each connection is reshaped.
* **No admin rights to run.** Admin/sudo is needed once, to edit the hosts file.
* **Single binary** for Windows, macOS and Linux. Standard library only.

## How it works

The TLS *ClientHello* — the first message of every HTTPS connection — carries
the server name (SNI) in plain text. The ISP's filter looks for blocked names
in it. snisplit cuts the ClientHello into two TLS records **through the middle
of the name** and sends the pieces as separate TCP segments, so no packet ever
contains the full name. Servers reassemble it as the TLS spec requires; the
filter does not. For plain HTTP the `Host:` header is sent as `hoSt:` (header
names are case-insensitive) and split the same way.

Apps reach snisplit in one of two ways:

| Mode | How | Works for |
|---|---|---|
| **Transparent** (default) | `snisplit hosts install` points the blocked names at `127.0.0.1`; snisplit listens on 443/80, reads the real destination from the SNI and connects to it (resolved over DNS-over-HTTPS, so the hosts file and ISP DNS are bypassed) | every app, including Steam |
| **Proxy / PAC** | set the system proxy to `http://127.0.0.1:8881/proxy.pac` | browsers and apps that honour the system proxy |

The proxy never decrypts anything — after the first message it just relays bytes.

## Install

### Windows

In PowerShell (no admin needed):

```powershell
wget https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

This downloads the latest release, checks its SHA-256, installs
`snisplit.exe` to `%LOCALAPPDATA%\Programs\snisplit` and adds it to your PATH.
Open a new terminal afterwards. Run the same commands again to update.

### macOS / Linux (Homebrew)

```sh
brew install nguyenthanh1205tb/tap/snisplit
```

Linux only — let it listen on ports 443/80 without root:

```sh
sudo setcap cap_net_bind_service=+ep "$(readlink -f "$(command -v snisplit)")"
```

(re-run after each `brew upgrade`, or run snisplit with sudo instead).

### From source

```sh
go install github.com/nguyenthanh1205tb/snisplit@latest
```

## Quick start (Steam)

```sh
snisplit check            # 1. confirm the block and that splitting gets through
snisplit hosts install    # 2. once - Windows: terminal "Run as administrator"
                          #             macOS/Linux: sudo "$(command -v snisplit)" hosts install
snisplit start            # 3. run in the background
```

Then fully exit Steam (tray icon → Exit) and open it again.

To start automatically at login:

* Windows: `snisplit autostart on`
* macOS/Linux: `brew services start snisplit`

Example `snisplit check` output on a filtered connection:

```
HOST                    IP              DIRECT  SPLIT (both)
store.steampowered.com  23.77.15.30     RESET   OK
api.steampowered.com    23.44.5.56      RESET   OK
steamcommunity.com      104.89.103.51   RESET   OK

3 blocked, all reachable with splitting -> snisplit will work.
```

## Commands

| Command | |
|---|---|
| `snisplit run` | run in the foreground (Ctrl+C to stop) |
| `snisplit start` / `stop` / `status` | run in the background / stop it / show state |
| `snisplit check [host ...]` | real TLS handshakes, direct vs split (`--all` tests the whole list) |
| `snisplit hosts install` / `remove` / `show` | manage the hosts-file block (admin/sudo) |
| `snisplit autostart on` / `off` | start at login (Windows; use `brew services` elsewhere) |
| `snisplit version` | |

Useful flags for `run` / `start`:

| Flag | Default | |
|---|---|---|
| `--mode` | `both` | `both` (2 records, 3 TCP segments), `record`, `tcp`, `none` |
| `--delay` | `10ms` | pause between pieces |
| `--port` | `8881` | HTTP proxy, PAC and status port |
| `--transparent` | `true` | listen on 443/80 for hosts-file names |
| `--dns` | `doh` | `doh` (Google/Cloudflare by IP) or `system` |
| `--preset` / `--list` | `steam` | built-in list, or your own file |
| `-v` | off | verbose log |

The log lives in `%LOCALAPPDATA%\snisplit\snisplit.log` (Windows),
`~/Library/Caches/snisplit/` (macOS) or `~/.cache/snisplit/` (Linux).

## Other sites

Write a list — one hostname per line, `#` for comments; a leading dot
(`.example.com`) means "this domain and all subdomains" for the PAC file only,
because the hosts file has no wildcards:

```
www.example.com
cdn.example.com
.example.com
```

```sh
snisplit check --list mysites.txt --all
snisplit hosts install --list mysites.txt
snisplit start --list mysites.txt
```

## Uninstall

```sh
snisplit stop
snisplit autostart off                 # Windows
snisplit hosts remove                  # as Administrator / with sudo
```

Then delete `%LOCALAPPDATA%\Programs\snisplit` (and remove it from PATH) on
Windows, or `brew uninstall snisplit`. The hosts file is backed up to
`hosts.snisplit.bak` next to it before every change.

## Troubleshooting

* **Site still blocked** – run `snisplit check <host>`; try `--mode record`,
  `--mode tcp` or a longer `--delay 50ms`. Some ISPs also block by IP, which
  splitting cannot fix.
* **A page loads partly** – it uses a hostname that is not in the list. Look at
  the browser's network tab or `snisplit run -v`, add the name, re-run
  `hosts install`.
* **"cannot listen on port 443"** – another program (IIS, Skype, a local web
  server) uses it, or on Linux you need the `setcap` line above.
* **Sites in the list stop loading** – the proxy is not running while the hosts
  entries are installed. `snisplit start`, or `snisplit hosts remove`.

## Tiếng Việt (tóm tắt)

snisplit giúp vào các trang bị nhà mạng chặn theo SNI (ví dụ Steam) bằng cách
tách gói ClientHello để bộ lọc không đọc được tên miền. Không cần driver, không
phải VPN, không làm chậm mạng.

```powershell
# Windows - cài đặt
wget https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1

snisplit check            # kiểm tra
snisplit hosts install    # chạy 1 lần trong terminal "Run as administrator"
snisplit start            # chạy nền, rồi khởi động lại Steam
snisplit autostart on     # tự chạy khi đăng nhập
```

macOS/Linux: `brew install nguyenthanh1205tb/tap/snisplit`, rồi
`sudo "$(command -v snisplit)" hosts install` và `brew services start snisplit`.

## Disclaimer

snisplit only changes how your own computer sends its own traffic. You are
responsible for complying with the laws and terms of service that apply to you.

## License

MIT
