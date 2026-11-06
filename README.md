# snisplit

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

Start at login: `snisplit autostart on` (Windows) or `brew services start snisplit` (macOS/Linux).

Other commands: `snisplit stop`, `snisplit status`, `snisplit hosts remove`.

## Other sites

Put one hostname per line in a file (start from `snisplit hosts show`), then:

```sh
snisplit hosts install --list mysites.txt
```

## Uninstall

```sh
snisplit stop
snisplit autostart off
snisplit hosts remove     # as Administrator / with sudo
```

Then delete `%LOCALAPPDATA%\Programs\snisplit`, or `brew uninstall snisplit`.

## License

MIT
