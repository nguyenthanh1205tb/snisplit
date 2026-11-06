<p align="center"><img src="docs/logo.png" width="112" alt="snisplit logo"></p>

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

snisplit runs under a supervisor that restarts it if it crashes, and picks the
split method that works for each site on its own (`--mode auto`).

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
snisplit stop
snisplit autostart off
snisplit hosts remove     # as Administrator / with sudo
```

Then delete `%LOCALAPPDATA%\Programs\snisplit`, or `brew uninstall snisplit`.

## License

MIT
