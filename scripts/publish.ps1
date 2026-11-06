# One-time publish of snisplit to GitHub (creates PUBLIC repos):
#   1. creates github.com/nguyenthanh1205tb/snisplit and pushes main
#   2. tags the version -> the release workflow builds binaries + checksums.txt
#   3. fills in the Homebrew formula's version/sha256 and creates
#      github.com/nguyenthanh1205tb/homebrew-tap
#
# Expects the tap checkout next to this repo:  <parent>\snisplit, <parent>\homebrew-tap
#
#   powershell -ExecutionPolicy Bypass -File .\scripts\publish.ps1
param([string]$Version = 'v0.1.0')
$ErrorActionPreference = 'Stop'
$owner = 'nguyenthanh1205tb'
$repo  = Split-Path -Parent $PSScriptRoot          # ...\snisplit
$tap   = Join-Path (Split-Path -Parent $repo) 'homebrew-tap'
if (-not (Test-Path "$tap\Formula\snisplit.rb")) { throw "tap checkout not found at $tap" }

function Run([string]$exe) {   # run a native command, stop on failure
    & $exe @args
    if ($LASTEXITCODE -ne 0) { throw "$exe $args failed ($LASTEXITCODE)" }
}

# ---- 1. main repo
Set-Location $repo
Run gh repo create "$owner/snisplit" --public --source . --remote origin --push `
    --description "Bypass SNI-based DPI blocking (e.g. Steam in Vietnam) by splitting the TLS ClientHello. No driver, no VPN."
Run gh repo edit "$owner/snisplit" --add-topic dpi,sni,censorship-circumvention,steam,proxy,golang

# ---- 2. release
Run git tag -a $Version -m "snisplit $Version"
Run git push origin $Version
Write-Host "Waiting for the release workflow..."
$runId = $null
foreach ($i in 1..30) {
    Start-Sleep 4
    $runId = gh run list -R "$owner/snisplit" --workflow release.yml --branch $Version --limit 1 --json databaseId --jq '.[0].databaseId'
    if ($runId) { break }
}
if (-not $runId) { throw "release workflow did not start" }
Run gh run watch $runId -R "$owner/snisplit" --exit-status
Run gh release view $Version -R "$owner/snisplit"

# ---- 3. Homebrew tap
$tar = Join-Path $env:TEMP "snisplit-$Version.tar.gz"
Invoke-WebRequest "https://github.com/$owner/snisplit/archive/refs/tags/$Version.tar.gz" -OutFile $tar -UseBasicParsing
$sha = (Get-FileHash $tar -Algorithm SHA256).Hash.ToLower()
Remove-Item $tar
$formula = "$tap\Formula\snisplit.rb"
$text = [IO.File]::ReadAllText($formula)
$text = $text -replace '(refs/tags/)[^"]+(\.tar\.gz")', "`${1}$Version`${2}" -replace 'sha256 "[^"]*"', "sha256 `"$sha`""
[IO.File]::WriteAllText($formula, $text, (New-Object Text.UTF8Encoding $false))
Write-Host "formula: $Version  sha256 $sha"

Set-Location $tap
Run git add -A
Run git commit -q -m "snisplit $Version"
Run gh repo create "$owner/homebrew-tap" --public --source . --remote origin --push `
    --description "Homebrew formulae (brew install $owner/tap/snisplit)"

Write-Host "`nDone:"
Write-Host "  https://github.com/$owner/snisplit/releases/tag/$Version"
Write-Host "  brew install $owner/tap/snisplit"
