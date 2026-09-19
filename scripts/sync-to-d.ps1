# Syncs the working tree from the Desktop "source of truth" into D:\zapret-cpp.
# Run this before committing. It copies only source/config files (never build
# output) and reports a clear diff summary.
#
# Usage:  pwsh -File scripts/sync-to-d.ps1

param(
    [string]$Source = (Join-Path $env:USERPROFILE "Desktop\zapret-cpp"),
    [string]$Target = "D:\zapret-cpp"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Source)) { throw "source not found: $Source" }
if (-not (Test-Path $Target)) { throw "target not found: $Target" }

$items = @("src", "tests", "scripts")
$files = @("CMakeLists.txt", "README.md", ".gitignore", "LICENSE")

Write-Host "syncing $Source -> $Target"

foreach ($d in $items) {
    $s = Join-Path $Source $d
    if (Test-Path $s) {
        Copy-Item -Recurse -Force $s $Target
        Write-Host "  dir  $d"
    }
}

foreach ($f in $files) {
    $s = Join-Path $Source $f
    if (Test-Path $s) {
        Copy-Item -Force $s $Target
        Write-Host "  file $f"
    }
}

Write-Host ""
Write-Host "git status in target:" -ForegroundColor Cyan
git -C $Target status --short
