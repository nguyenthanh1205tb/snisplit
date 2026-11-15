# snisplit installer for Windows. In PowerShell:
#
#   irm https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/install.ps1 | iex
#
# Downloads the release, checks its SHA-256 against checksums.txt, installs it
# to %LOCALAPPDATA%\Programs\snisplit, adds that folder to the user PATH, then
# sets snisplit up: hosts file entries (Windows asks for administrator rights
# once), start at login, and starts the proxy and its tray icon.
# Running it again updates snisplit.
param(
    [string]$Version = 'latest',
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\snisplit",
    [switch]$NoPathUpdate,      # portable install: do not touch the user PATH
    [switch]$NoSetup,           # only install the program
    [string]$BaseUrl = ''       # download from a mirror instead of GitHub releases
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo  = 'nguyenthanh1205tb/snisplit'
$arch  = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'amd64' }
$asset = "snisplit_windows_$arch.exe"
$base  = if ($BaseUrl) { $BaseUrl.TrimEnd('/') }
         elseif ($Version -eq 'latest') { "https://github.com/$repo/releases/latest/download" }
         else { "https://github.com/$repo/releases/download/$Version" }
$exe = Join-Path $InstallDir 'snisplit.exe'

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("snisplit-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    Write-Host "Downloading snisplit ($Version, $arch)..."
    Invoke-WebRequest "$base/$asset"        -OutFile "$tmp\$asset"        -UseBasicParsing
    Invoke-WebRequest "$base/checksums.txt" -OutFile "$tmp\checksums.txt" -UseBasicParsing

    $line = Get-Content "$tmp\checksums.txt" | Where-Object { $_ -match "\s\*?$([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $line) { throw "$asset not listed in checksums.txt" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual   = (Get-FileHash "$tmp\$asset" -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) { throw "checksum mismatch for $asset (expected $expected, got $actual)" }

    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    if (Test-Path $exe) {
        # Stop this copy (proxy, supervisor, tray icon) so it can be replaced.
        & $exe stop 2>$null | Out-Null
        Get-CimInstance Win32_Process -Filter "Name='snisplit.exe'" |
            Where-Object { $_.ExecutablePath -eq $exe } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        Remove-Item "$exe.old" -Force -ErrorAction SilentlyContinue
        Rename-Item $exe "$exe.old" -ErrorAction SilentlyContinue   # works even if still in use
    }
    Move-Item "$tmp\$asset" $exe -Force
    Remove-Item "$exe.old" -Force -ErrorAction SilentlyContinue
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (-not $NoPathUpdate -and ($userPath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ";$InstallDir").TrimStart(';'), 'User')
}
$env:Path = "$env:Path;$InstallDir"
Write-Host "Installed $(& $exe version) to $InstallDir"

if ($NoSetup) { return }

# 1. hosts file: needs administrator rights only when something changes.
& $exe hosts install *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Windows will now ask for administrator rights to edit the hosts file. Click Yes."
    try {
        $p = Start-Process $exe -ArgumentList 'hosts', 'install' -Verb RunAs -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -ne 0) { throw "exit code $($p.ExitCode)" }
    } catch {
        Write-Warning "The hosts file was not changed ($($_.Exception.Message))."
        Write-Warning "Run this in PowerShell opened as Administrator: snisplit hosts install"
    }
}

# 2. start at login, then start the proxy and the tray icon now.
& $exe autostart on | Out-Null
& $exe start | Out-Null
& $exe tray | Out-Null

Write-Host @"

Done. snisplit is running (look for its icon next to the clock) and starts with Windows.
Restart Steam if it is open.

Optional, for any blocked website in your browsers, and to block ads:
  snisplit browser on
  snisplit adblock on
"@
