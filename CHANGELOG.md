# Changelog

## v0.8.3 (2026-11-16)

- Every release file now comes with a build provenance attestation from GitHub:
  `gh attestation verify <file> --repo nguyenthanh1205tb/snisplit` proves it was
  built from this repository by GitHub Actions
- Code scanning (CodeQL), dependency updates (Dependabot) and an OpenSSF Scorecard
- `SECURITY.md`, this changelog, issue templates, and a "what snisplit does on your
  computer" section in the README

## v0.8.2 (2026-11-16)

- "Start at login" respects Task Manager's Disable: the tray checkbox and
  `snisplit doctor` show it, and `snisplit autostart on` turns it back on

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
