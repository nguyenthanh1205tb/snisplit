# Security

## Reporting a vulnerability

Please report security problems privately through
[GitHub's private vulnerability reporting](https://github.com/nguyenthanh1205tb/snisplit/security/advisories/new),
not in a public issue. You should get an answer within a few days. Báo lỗi bảo mật
qua liên kết trên, đừng đăng công khai.

Only the latest release gets fixes; `snisplit update` (or running the installer again)
moves you to it.

## What snisplit can and cannot see

snisplit only reorders and splits the first message of each connection (the TLS
ClientHello, which is not encrypted anyway). It never decrypts HTTPS, has no
certificate of its own and cannot read pages, passwords or cookies. It sends no
telemetry. The README's "What snisplit does on your computer" section lists every
change it makes and every server it talks to.

## Verifying a download

Release files are built by GitHub Actions from the tagged source, and each one
has a build provenance attestation:

```sh
gh attestation verify snisplit_windows_amd64.exe --repo nguyenthanh1205tb/snisplit
```

The installer also checks every download against `checksums.txt`.
