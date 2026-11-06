# Submits packaging/winget/<version> to microsoft/winget-pkgs as a pull request.
# Needs the GitHub CLI logged in. Creates (once) a public fork of winget-pkgs
# under your account. Microsoft's bots validate and test the package; the first
# PR also asks you to accept their Contributor License Agreement in a comment.
#
#   powershell -ExecutionPolicy Bypass -File .\scripts\winget-submit.ps1 -Version 0.5.0
param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = 'Stop'

# Runs a native command: stderr is shown (not treated as a PowerShell error),
# stdout is returned, a non-zero exit code stops the script.
function Run([string]$exe) {
    $ErrorActionPreference = 'Continue'
    $out = & $exe @args 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { Write-Host $_.ToString() } else { $_ }
    }
    if ($LASTEXITCODE -ne 0) { throw "$exe $args failed ($LASTEXITCODE)" }
    $out
}

$id     = 'nguyenthanh1205tb.snisplit'
$src    = Join-Path (Split-Path -Parent $PSScriptRoot) "packaging\winget\$Version"
$dest   = "manifests/n/nguyenthanh1205tb/snisplit/$Version"
$branch = "snisplit-$Version"
if (-not (Test-Path $src)) { throw "no manifests at $src" }
Run winget validate --manifest $src | Out-Host

$me = Run gh api user --jq .login
$ErrorActionPreference = 'Continue'
& gh repo view "$me/winget-pkgs" 2>&1 | Out-Null
$hasFork = $LASTEXITCODE -eq 0
$ErrorActionPreference = 'Stop'
if (-not $hasFork) {
    Run gh repo fork microsoft/winget-pkgs --clone=false | Out-Host
    Start-Sleep 10
}
Run gh repo sync "$me/winget-pkgs" --branch master | Out-Host
$sha = Run gh api "repos/$me/winget-pkgs/git/ref/heads/master" --jq .object.sha
Run gh api "repos/$me/winget-pkgs/git/refs" -f ref="refs/heads/$branch" -f sha=$sha | Out-Null

foreach ($f in Get-ChildItem $src -Filter *.yaml) {
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.FullName))
    Run gh api -X PUT "repos/$me/winget-pkgs/contents/$dest/$($f.Name)" `
        -f message="New package: $id version $Version" -f content=$b64 -f branch=$branch | Out-Null
    Write-Host "uploaded $dest/$($f.Name)"
}

$body = @"
- [x] Have you signed the [Contributor License Agreement](https://cla.opensource.microsoft.com/microsoft/winget-pkgs)?
- [ ] Is there a linked Issue?

Manifests

- [x] Have you checked that there aren't other open [pull requests](https://github.com/microsoft/winget-pkgs/pulls) for the same manifest update/change?
- [x] This PR only modifies one (1) manifest
- [x] Have you [validated](https://github.com/microsoft/winget-pkgs/blob/master/doc/Authoring.md#validation) your manifest locally with ``winget validate --manifest <path>``?
- [ ] Have you tested your manifest locally with ``winget install --manifest <path>``?
- [x] Does your manifest conform to the [1.12 schema](https://github.com/microsoft/winget-pkgs/tree/master/doc/manifest/schema/1.12.0)?

snisplit is a portable command-line tool (single exe, MIT licensed): https://github.com/nguyenthanh1205tb/snisplit
"@
Run gh pr create -R microsoft/winget-pkgs --base master --head "${me}:$branch" `
    --title "New package: $id version $Version" --body $body | Out-Host
