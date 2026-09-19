# Builds a release folder with everything needed to run on a clean Windows machine.
#
# Usage:  pwsh -File scripts/make-release.ps1 [-Version v1.0.0]
#
# Output: dist/zapret-cpp/  (zip it and upload to GitHub Releases)

param(
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root "build"
$dist  = Join-Path $root "dist\zapret-cpp"

Write-Host "== configure & build =="
cmake -S $root -B $build -G Ninja
cmake --build $build

Write-Host "== stage release =="
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force -Path $dist | Out-Null

Copy-Item (Join-Path $build "zapret-cpp.exe") $dist

$wd = Join-Path $root "third_party\windivert\x64"
foreach ($f in @("WinDivert.dll", "WinDivert64.sys")) {
    $src = Join-Path $wd $f
    if (-not (Test-Path $src)) {
        throw "missing $src - run the WinDivert download step first"
    }
    Copy-Item $src $dist
}

Copy-Item (Join-Path $root "README.md") $dist

$zip = Join-Path $root "dist\zapret-cpp-$Version.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $dist "*") -DestinationPath $zip

Write-Host ""
Write-Host "release ready:" -ForegroundColor Green
Get-ChildItem $dist | ForEach-Object { "  {0,-24} {1,10} bytes" -f $_.Name, $_.Length }
Write-Host "  archive: $zip"
Write-Host ""
Write-Host "reminder: end users must run zapret-cpp.exe AS ADMINISTRATOR."
