# Changelog

## v0.10.0 (2026-11-16)

- `snisplit dns on` (Windows): every app, not just browsers. The computer's DNS points at
  snisplit, which looks names up over DNS-over-HTTPS, answers ad domains with 0.0.0.0 (with ad
  blocking on) and sends sites blocked by name through its own listeners. New blocked sites are
  found by themselves: the first time an app asks for a name, one TLS handshake checks it.
  Windows falls back to the previous DNS server whenever snisplit is not running, and
  `snisplit dns off` puts everything back, including Windows 11 "DNS over HTTPS" settings
- `snisplit share on`: phones and tablets on the same Wi-Fi use snisplit too, with the same
  unblocking and ad blocking. The tray shows a QR code that opens a setup page on the phone,
  in Vietnamese, with the steps for that phone: on an iPhone, paste one address (no Wi-Fi
  password needed) or install a configuration profile; on Android, paste one address.
  Phones find the computer by its name (`<computer>.local`), so they keep working when the
  router gives it another address. Only the local network can connect; phones go direct
  when the computer is off
- Both in the tray menu: "All apps (system DNS)", "Share with phones (Wi-Fi)", "Phone setup"
- `settings.json` is read even when an editor saved it with a byte order mark

## v0.9.1 (2026-11-16)

- The tray icon no longer goes missing after logging in to Windows: it waits for the taskbar,
  starts itself again if the icon cannot be added, and the proxy brings it back if it stops
  (unless you chose "Quit icon"). The proxy starts after 10 seconds even if the icon is late
- The tray writes `tray.log` next to `snisplit.log`, including the report of any crash

## v0.9.0 (2026-11-16)

- Sites blocked by IP address get through too, still directly and at full speed: when every
  usual address of a site fails, snisplit tries its IPv6 addresses, the servers it uses in other
  countries (DNS client subnet), then other servers of its CDN (Cloudflare, Google, Akamai,
  CloudFront), each checked with a TLS handshake against the site's certificate first. What
  worked is remembered. Works for Steam and for every site in browser mode
- Connections start on the next address after 400 ms instead of waiting for a dead one to time out
- `snisplit status` counts connections that needed another address
- Strategy version 2: the regions and CDNs to use can be updated without a release

## v0.8.4 (2026-11-16)

- Dependency updates: `golang.org/x/sys` v0.50.0 (building from source now needs
  Go 1.26 or newer), and the GitHub Actions used to build and attest releases
  (`checkout` v7, `setup-go` v7, `attest-build-provenance` v4)

## v0.8.3 (2026-11-16)

- Every release file now comes with a build provenance attestation from GitHub:
  `gh attestation verify <file> --repo nguyenthanh1205tb/snisplit` proves it was
  built from this repository by GitHub Actions
- Code scanning (CodeQL), dependency updates (Dependabot) and an OpenSSF Scorecard;
  GitHub Actions pinned to commit hashes, workflow permissions kept to the minimum
- Fuzz tests for everything that parses outside data (ClientHello, DNS answers,
  block lists, the strategy file)
- `golang.org/x/sys` updated to v0.44.0 (GO-2026-5024; the affected function was
  never called by snisplit)
- `SECURITY.md`, this changelog, issue templates, and a "what snisplit does on your
  computer" section in the README and on the website

## v0.8.2 (2026-11-16)

- "Start at login" respects Task Manager's Disable: the tray checkbox and
  `snisplit doctor` show it, and `snisplit autostart on` turns it back on
- New website: https://nguyenthanh1205tb.github.io/snisplit/ (Vietnamese, light and dark)

## v0.8.1 (2026-11-16)

- One-command install on Windows: `irm …/install.ps1 | iex` installs, edits the hosts
  file (one administrator prompt), starts snisplit and turns on start at login
- `snisplit uninstall` undoes everything and removes the program
- `sudo snisplit hosts install` on Linux also lets snisplit use ports 443/80

## v0.8.0 (2026-11-16)

- Ad blocking in browser mode: `snisplit adblock on`, ~235k ad, tracker and malware
  domains (HaGeZi Multi NORMAL + hostsVN), updated daily, with allow/block lists

## v0.7.1 (2026-11-16)

- Browser mode now sets the system proxy the way Windows Settings does, so Chrome
  and Edge follow it

## v0.7.0 (2026-11-16)

- Seven ways to split the TLS ClientHello (`chunk`, `disorder`, `slow` and `oob` are new);
  the one that works is remembered per site
- Tries other addresses of a site that is blocked by address
- DNS over HTTPS to 8 providers, with the last good answers kept on disk
- Strategy (order of methods, timings, DNS servers) refreshed from GitHub daily
- Self-test every few hours, with a Windows notification when nothing gets through
- `snisplit browser on`: every website in your browsers, blocked ones found automatically
- `snisplit upstream`: a SOCKS5/HTTP proxy for sites no split gets through
- More Steam CDN names (e.g. `avatars.steamstatic.com`, the avatar in the title bar)

## v0.6.0 (2026-11-06)

- `snisplit doctor` checks the whole setup and says how to fix problems
- `snisplit hosts update` gets the newest site list; the tray offers it when it changes

## v0.5.0 (2026-11-06)

- New logo and Windows icon

## v0.4.0 – v0.4.1 (2026-11-06)

- Windows tray icon: start/stop, start at login, log, updates

## v0.3.0 – v0.3.1 (2026-11-06)

- `snisplit update`, Scoop bucket

## v0.2.0 (2026-11-06)

- Automatic split mode, supervisor that restarts the proxy, `hosts add/del`, status counters

## v0.1.0 (2026-11-06)

- First release
