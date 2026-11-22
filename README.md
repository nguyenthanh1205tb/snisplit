<p align="center"><img src="assets/logo.png" width="112" alt="snisplit logo"></p>

<h1 align="center">snisplit</h1>

<p align="center"><b>Steam bị chặn. 1 lệnh. Hết.</b><br>
<a href="#tiếng-việt">Tiếng Việt</a> · <a href="#install">English</a></p>

<p align="center">
<a href="https://github.com/nguyenthanh1205tb/snisplit/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/nguyenthanh1205tb/snisplit"></a>
<a href="https://github.com/nguyenthanh1205tb/snisplit/actions/workflows/ci.yml"><img alt="Tests" src="https://github.com/nguyenthanh1205tb/snisplit/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/nguyenthanh1205tb/snisplit/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/nguyenthanh1205tb/snisplit/actions/workflows/codeql.yml/badge.svg"></a>
<a href="https://scorecard.dev/viewer/?uri=github.com/nguyenthanh1205tb/snisplit"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/nguyenthanh1205tb/snisplit/badge"></a>
<a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/nguyenthanh1205tb/snisplit"></a>
</p>

## Tiếng Việt

Nhà mạng chặn Steam. Cái này gỡ chặn. Không VPN, không chậm.

Mở PowerShell, dán:

```powershell
irm https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/install.ps1 | iex
```

Hỏi quyền thì bấm Yes. Mở lại Steam. Hết.

- `snisplit browser on`: trang khác bị chặn, trên trình duyệt
- `snisplit dns on`: cho mọi ứng dụng
- `snisplit adblock on`: chặn quảng cáo
- `snisplit doctor`: lỗi thì chạy cái này
- `snisplit uninstall`: gỡ

Mã nguồn mở. Không driver. Không gửi dữ liệu đi đâu. [Chi tiết](#what-snisplit-does-on-your-computer).

---

Gets around ISP blocking of sites like Steam (e.g. in Vietnam). No VPN, no driver,
full speed.

## Install

**Windows**: open PowerShell, paste this line and press Enter:

```powershell
irm https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/install.ps1 | iex
```

Click **Yes** if Windows asks for permission. That's it: snisplit runs now, starts
with Windows, and has an icon next to the clock. Restart Steam if it was open.

Prefer to look first? Read [`install.ps1`](install.ps1), or download
`snisplit_windows_amd64.exe` from [Releases](https://github.com/nguyenthanh1205tb/snisplit/releases/latest)
and [verify it](#verify-a-download).

**macOS / Linux** (needs [Homebrew](https://brew.sh)):

```sh
brew install nguyenthanh1205tb/tap/snisplit
sudo snisplit hosts install && brew services start snisplit
```

## Extras

```sh
snisplit browser on    # open any blocked website in your browsers
snisplit dns on        # the same for every app, not just browsers (Windows)
snisplit adblock on    # block ads and trackers (browsers, or every app with dns on)
```

All are also in the tray icon menu (Windows). Use `off` to turn them off.

`dns on` points your computer's DNS at snisplit, which looks names up over DNS-over-HTTPS,
answers ad domains with `0.0.0.0`, and sends sites blocked by name through its own listeners.
It finds such sites by itself: the first time an app asks for a name, one TLS handshake
checks whether the ISP cuts it off. If snisplit is not running, Windows falls back to your
previous DNS server, so the internet keeps working.


## Something not working?

```sh
snisplit doctor
```

It checks everything and tells you what to do. [Report a bug](https://github.com/nguyenthanh1205tb/snisplit/issues/new/choose)
with its output, or ask in [Discussions](https://github.com/nguyenthanh1205tb/snisplit/discussions).

## Update / uninstall

```sh
snisplit update
snisplit uninstall
```

(Homebrew: `brew upgrade snisplit`, and `brew uninstall snisplit` after `snisplit uninstall`.)

## What snisplit does on your computer

snisplit only splits the first, unencrypted message of a connection (the TLS
ClientHello) so the site name is never whole in one packet. It never decrypts HTTPS,
has no certificate of its own, cannot see pages, passwords or cookies, and sends no
telemetry or usage data anywhere.

**What it changes** (all undone by `snisplit uninstall`):

| Where | What |
|---|---|
| hosts file | A block between `# BEGIN snisplit` and `# END snisplit` pointing Steam's names at `127.0.0.1` (a backup is kept as `hosts.snisplit.bak`) |
| Start at login | A `snisplit` entry in your user's Run key (Task Manager → Startup apps) |
| Files | The program in `%LOCALAPPDATA%\Programs\snisplit`; log, learned sites and lists in `%LOCALAPPDATA%\snisplit`; settings in `%APPDATA%\snisplit` |
| PATH | That program folder, so `snisplit` works in a terminal |
| Proxy setting | Only with `snisplit browser on`: your user's "Use setup script" address |
| DNS setting | Only with `snisplit dns on`: connected adapters use `127.0.0.1` first and your previous server second; Windows 11 "DNS over HTTPS" flags on those adapters are put aside meanwhile. Everything is saved in `%APPDATA%\snisplit\dns-backup.json` and put back by `snisplit dns off` |
| Network | Listens on `127.0.0.1` ports 8881, 443 and 80 (and 53 with `dns on`), which only this computer can reach |

**What it connects to on its own:**

- The sites you open, directly (no server in between). If a site's usual addresses are blocked,
  its other servers: IPv6, the ones it uses for other countries, or other servers of its CDN
  (Cloudflare, Google, Akamai, CloudFront) once a TLS handshake has shown they hold the site's certificate
- DNS-over-HTTPS servers (Google, Cloudflare, AdGuard, OpenDNS, DNS.SB, Quad9) to look up blocked sites; in browser mode, every site you open.
  For a site blocked by address, Google's is also asked which servers the site uses in a few other countries
- With `dns on`, the first time an app asks for a name (then once a day): one TLS handshake to
  that site, to find out whether the ISP blocks it by name
- GitHub, once a day: the newest site list and [strategy](lists/strategy.json)
- With ad blocking on, once a day: the [HaGeZi](https://github.com/hagezi/dns-blocklists) and [hostsVN](https://github.com/bigdargon/hostsVN) lists
- Steam's store, every few hours: a self-test that it still gets through
- Updates are only checked when you click "Check for updates" or run `snisplit update`

## Verify a download

Every release file is built from the tagged source by
[GitHub Actions](.github/workflows/release.yml), never on a personal computer, and comes with
a [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
signed by GitHub. With the [GitHub CLI](https://cli.github.com):

```sh
gh attestation verify snisplit_windows_amd64.exe --repo nguyenthanh1205tb/snisplit
```

Or compare the SHA-256 with `checksums.txt` from the same release (the installer does this for you):

```powershell
Get-FileHash snisplit_windows_amd64.exe
```

The program is not code-signed yet, so Windows SmartScreen or Defender may warn about
a new, rarely downloaded file. Security reports: [SECURITY.md](SECURITY.md).
Changes in each version: [CHANGELOG.md](CHANGELOG.md).

## License

MIT
