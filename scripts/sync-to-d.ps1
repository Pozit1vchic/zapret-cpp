# Syncs the working tree from the Desktop "source of truth" into D:\zapret-cpp,
# then REBUILDS there so D:\zapret-cpp\build\zapret-cpp.exe is always current.
# Run this before committing or before running the tool from D:.
#
# Usage:  pwsh -File scripts/sync-to-d.ps1
#         pwsh -File scripts/sync-to-d.ps1 -NoBuild

param(
    [string]$Source = (Join-Path $env:USERPROFILE "Desktop\zapret-cpp"),
    [string]$Target = "D:\zapret-cpp",
    [switch]$NoBuild
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

if (-not $NoBuild) {
    Write-Host ""
    Write-Host "rebuilding in $Target" -ForegroundColor Cyan
    $dstBuild = Join-Path $Target "build"
    $wdX64 = Join-Path $Target "third_party\windivert\x64"

    if (Test-Path (Join-Path $Target "CMakeLists.txt")) {
        $cache = Join-Path $dstBuild "CMakeCache.txt"
        if (Test-Path $cache) {
            $cached = Select-String -Path $cache -Pattern '^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)$' |
                      ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
            if ($cached -and ($cached -replace '/','\' -ne ($Target -replace '/','\'))) {
                Write-Host "  stale CMake cache ($cached) -> wiping $dstBuild" -ForegroundColor Yellow
                Remove-Item -Recurse -Force $dstBuild
            }
        }

        cmake -S $Target -B $dstBuild -G Ninja | Out-Host
        cmake --build $dstBuild | Out-Host

        $exe = Join-Path $dstBuild "zapret-cpp.exe"
        if (Test-Path $exe) {
            foreach ($f in @("WinDivert.dll", "WinDivert64.sys")) {
                $src = Join-Path $wdX64 $f
                if (Test-Path $src) { Copy-Item -Force $src $dstBuild }
            }
            Write-Host ""
            Write-Host ("built: {0}  {1} bytes  {2}" -f $exe, (Get-Item $exe).Length,
                         (Get-Item $exe).LastWriteTime) -ForegroundColor Green
        } else {
            Write-Warning "build finished but $exe not found"
        }
    } else {
        Write-Warning "no CMakeLists.txt in target, skipped build"
    }
}

Write-Host ""
Write-Host "git status in target:" -ForegroundColor Cyan
git -C $Target status --short

