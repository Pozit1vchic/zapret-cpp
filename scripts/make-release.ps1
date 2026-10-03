# Build a clean Windows x64 release from the CURRENT source tree.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1 -Version v2.0.0

param([string]$Version = "v2.0.0")

$ErrorActionPreference = "Stop"
$root  = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root "build-release"
$distRoot = Join-Path $root "dist"
$stage = Join-Path $distRoot "zapret-cpp"
$zip = Join-Path $distRoot "zapret-cpp-$Version-win64.zip"

if (Test-Path $build) { Remove-Item -Recurse -Force $build }

$hasNinja = $null -ne (Get-Command ninja -ErrorAction SilentlyContinue)
$hasMsvc  = $null -ne (Get-Command cl.exe -ErrorAction SilentlyContinue)
$hasGxx   = $null -ne (Get-Command g++.exe -ErrorAction SilentlyContinue)
if ($hasNinja) {
    Write-Host "== configure (Ninja) ==" -ForegroundColor Cyan
    cmake -S $root -B $build -G Ninja -DCMAKE_BUILD_TYPE=Release -DZC_BUILD_TESTS=ON | Out-Host
    cmake --build $build | Out-Host
    ctest --test-dir $build --output-on-failure | Out-Host
    $exe = Join-Path $build "zapret-cpp.exe"
} elseif ($hasMsvc) {
    Write-Host "== configure (Visual Studio) ==" -ForegroundColor Cyan
    cmake -S $root -B $build -A x64 -DZC_BUILD_TESTS=ON | Out-Host
    cmake --build $build --config Release --parallel | Out-Host
    ctest --test-dir $build -C Release --output-on-failure | Out-Host
    $exe = Join-Path $build "Release\zapret-cpp.exe"
} elseif ($hasGxx) {
    Write-Host "== configure (MinGW Makefiles) ==" -ForegroundColor Cyan
    cmake -S $root -B $build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DZC_BUILD_TESTS=ON | Out-Host
    cmake --build $build --parallel | Out-Host
    ctest --test-dir $build --output-on-failure | Out-Host
    $exe = Join-Path $build "zapret-cpp.exe"
} else {
    throw "No supported C++ toolchain found. Install Ninja+compiler, Visual Studio C++ tools, or MinGW-w64."
}
if (-not (Test-Path $exe)) { throw "build succeeded but executable is missing: $exe" }

Write-Host "== stage ==" -ForegroundColor Cyan
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stage "config") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stage "lists") | Out-Null

Copy-Item $exe $stage
$wd = Join-Path $root "third_party\windivert\x64"
foreach ($name in @("WinDivert.dll", "WinDivert64.sys")) {
    $src = Join-Path $wd $name
    if (-not (Test-Path $src)) { throw "missing WinDivert runtime: $src" }
    Copy-Item $src $stage
}
Copy-Item (Join-Path $root "third_party\windivert\LICENSE") (Join-Path $stage "WinDivert-LICENSE.txt")
Copy-Item (Join-Path $root "config\rules.txt") (Join-Path $stage "config\rules.txt")
Copy-Item (Join-Path $root "lists\exclude.txt") (Join-Path $stage "lists\exclude.txt")
Copy-Item (Join-Path $root "lists\hostlist.example.txt") (Join-Path $stage "lists\hostlist.example.txt")
foreach ($name in @("README.md", "AUDIT.md", "NOTICE.md")) {
    Copy-Item (Join-Path $root $name) $stage
}

$prefix = $stage + [IO.Path]::DirectorySeparatorChar
$hashes = Get-ChildItem $stage -File -Recurse | Sort-Object FullName | ForEach-Object {
    $h = Get-FileHash $_.FullName -Algorithm SHA256
    $rel = $_.FullName.Replace($prefix, "")
    "{0}  {1}" -f $h.Hash.ToLowerInvariant(), $rel
}
$hashes | Set-Content -Encoding ascii (Join-Path $stage "SHA256SUMS.txt")

if (-not (Test-Path $distRoot)) { New-Item -ItemType Directory -Force -Path $distRoot | Out-Null }
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal

Write-Host "release ready: $zip" -ForegroundColor Green
Get-FileHash $zip -Algorithm SHA256 | Format-List
