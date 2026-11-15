<p align="center"><img src="assets/logo.png" width="112" alt="snisplit logo"></p>

<h1 align="center">snisplit</h1>

Bypass ISP blocking that reads the site name (SNI) from HTTPS connections —
e.g. Steam in Vietnam. snisplit splits the TLS ClientHello so the name never
appears whole in one packet. No driver, no VPN, traffic goes straight to the
real server.

## Install

**Windows** (PowerShell):

```powershell
wget https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The script downloads the latest release, checks its SHA-256 and adds `snisplit`
to your PATH. Or download `snisplit_windows_amd64.exe` from
[Releases](https://github.com/nguyenthanh1205tb/snisplit/releases/latest), rename it to
`snisplit.exe` and run it from a terminal.

Or with [Scoop](https://scoop.sh):

```powershell
scoop bucket add snisplit https://github.com/nguyenthanh1205tb/snisplit
scoop install snisplit
```

**macOS / Linux**:

```sh
brew install nguyenthanh1205tb/tap/snisplit
```

On Linux, also run `sudo setcap cap_net_bind_service=+ep "$(readlink -f "$(command -v snisplit)")"`.

## Usage

```sh
snisplit check            # show what is blocked and whether snisplit gets through
snisplit hosts install    # once, as Administrator (Windows) or with sudo
snisplit start            # run in the background, then restart Steam
```

Start at login: `snisplit autostart on` (Windows, also shows a tray icon to start/stop
the proxy, open the log, run diagnostics and install updates) or
`brew services start snisplit` (macOS/Linux).
Show the tray icon now with `snisplit tray`.

Something wrong? `snisplit doctor` checks the whole setup and says how to fix it.

Other commands: `snisplit stop`, `snisplit status`, `snisplit update`,
`snisplit hosts update` (newest site list from GitHub), `snisplit hosts remove`.

## Any blocked website in your browser

```sh
snisplit browser on       # off to undo
```

Browsers then send every site through snisplit. Sites that are not blocked go
straight through; a site that gets blocked is split from then on, without adding
it to any list.

## When the ISP blocks harder

snisplit tries to stay a step ahead on its own:

- **7 ways to split**: `both`, `record`, `tcp`, `chunk`, `disorder` (first piece sent
  with a TTL too low to reach the ISP), `slow`, `oob`. The first one that gets through
  is remembered per site. `snisplit check` shows which ones work from your network.
- **Blocked addresses**: other addresses of the site are tried, and the one that works is remembered.
- **DNS**: 8 DNS-over-HTTPS providers, and the last good answers are kept for when all of them are blocked.
- **Self-test** every few hours; the tray icon turns amber and Windows shows a notice if nothing gets through.
- **New tricks without an update**: the order of methods, timings and DNS servers come from
  [`lists/strategy.json`](lists/strategy.json), refreshed daily.

If the ISP blocks everything a split can beat, give snisplit a proxy to fall back on for
those sites only, for example [Cloudflare WARP](https://one.one.one.one/) in proxy mode:

```sh
snisplit upstream socks5://127.0.0.1:40000     # off to remove
```

## Other sites

```sh
snisplit check example.com                    # is it blocked, and does snisplit help?
snisplit hosts add example.com cdn.example.com
snisplit hosts del example.com
```

Names you add are kept when you run `hosts install` again. For many names, use a
file with one hostname per line: `snisplit hosts install --list mysites.txt`.

## Uninstall

```sh
snisplit browser off
snisplit stop
snisplit autostart off
snisplit hosts remove     # as Administrator / with sudo
```

Then delete `%LOCALAPPDATA%\Programs\snisplit`, or `brew uninstall snisplit`.

## License

MIT
