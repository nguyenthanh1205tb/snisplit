# snisplit installer for Windows.
#
#   wget https://raw.githubusercontent.com/nguyenthanh1205tb/snisplit/main/install.ps1 -OutFile install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# Downloads the release binary, verifies its SHA-256 against checksums.txt,
# installs it to %LOCALAPPDATA%\Programs\snisplit and adds that folder to the
# user PATH. No administrator rights needed.
param(
    [string]$Version = 'latest',
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\snisplit",
    [switch]$NoPathUpdate,      # portable install: do not touch the user PATH
    [string]$BaseUrl = ''       # download from a mirror instead of GitHub releases
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo  = 'nguyenthanh1205tb/snisplit'
$arch  = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'amd64' }
$asset = "snisplit_windows_$arch.exe"
$base  = if ($BaseUrl) { $BaseUrl.TrimEnd('/') }
         elseif ($Version -eq 'latest') { "https://github.com/$repo/releases/latest/download" }
         else { "https://github.com/$repo/releases/download/$Version" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("snisplit-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    Write-Host "Downloading $asset ($Version)..."
    Invoke-WebRequest "$base/$asset"        -OutFile "$tmp\$asset"        -UseBasicParsing
    Invoke-WebRequest "$base/checksums.txt" -OutFile "$tmp\checksums.txt" -UseBasicParsing

    $line = Get-Content "$tmp\checksums.txt" | Where-Object { $_ -match "\s\*?$([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $line) { throw "$asset not listed in checksums.txt" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual   = (Get-FileHash "$tmp\$asset" -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) { throw "checksum mismatch for $asset (expected $expected, got $actual)" }
    Write-Host "Checksum OK"

    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    $exe = Join-Path $InstallDir 'snisplit.exe'
    $wasRunning = $false
    if (Test-Path $exe) {                      # stop a running copy so it can be replaced
        $wasRunning = (& $exe status 2>$null | Select-String '^running' -Quiet)
        & $exe stop 2>$null | Out-Null
    }
    Move-Item "$tmp\$asset" $exe -Force
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (-not $NoPathUpdate -and ($userPath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ";$InstallDir").TrimStart(';'), 'User')
    Write-Host "Added $InstallDir to your PATH (open a new terminal to use 'snisplit')."
}
$env:Path = "$env:Path;$InstallDir"

& $exe version
if ($wasRunning) { & $exe start }

Write-Host @"

Installed to $exe

Next steps:
  snisplit check              # see what is blocked and whether splitting helps
  snisplit hosts install      # once, in a terminal opened as Administrator
  snisplit start              # run in the background, then restart Steam
  snisplit autostart on       # optional: start at login
"@
