<p align="center"><img src="assets/logo.png" width="112" alt="snisplit logo"></p>

<h1 align="center">snisplit</h1>

Gets around ISP blocking of sites like Steam (e.g. in Vietnam). No VPN, no driver,
full speed.

## Install

**Windows**: open PowerShell, paste this line and press Enter:

```powershell
irm https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/install.ps1 | iex
```

Click **Yes** if Windows asks for permission. That's it: snisplit runs now, starts
with Windows, and has an icon next to the clock. Restart Steam if it was open.

**macOS / Linux** (needs [Homebrew](https://brew.sh)):

```sh
brew install nguyenthanh1205tb/tap/snisplit
sudo snisplit hosts install && brew services start snisplit
```

## Extras

```sh
snisplit browser on    # open any blocked website in your browsers
snisplit adblock on    # block ads and trackers in your browsers
```

Both are also in the tray icon menu (Windows). Use `off` to turn them off.

## Something not working?

```sh
snisplit doctor
```

It checks everything and tells you what to do.

## Update / uninstall

```sh
snisplit update
snisplit uninstall
```

(Homebrew: `brew upgrade snisplit`, and `brew uninstall snisplit` after `snisplit uninstall`.)

## License

MIT
