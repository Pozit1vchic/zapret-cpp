param([ValidateSet("Debug", "Release")][string]$Config = "Release")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root "build"

$hasNinja = $null -ne (Get-Command ninja -ErrorAction SilentlyContinue)
$hasMsvc  = $null -ne (Get-Command cl.exe -ErrorAction SilentlyContinue)
$hasGxx   = $null -ne (Get-Command g++.exe -ErrorAction SilentlyContinue)
if ($hasNinja) {
    cmake -S $root -B $build -G Ninja "-DCMAKE_BUILD_TYPE=$Config" -DZC_BUILD_TESTS=ON | Out-Host
    cmake --build $build | Out-Host
    ctest --test-dir $build --output-on-failure | Out-Host
    $exe = Join-Path $build "zapret-cpp.exe"
} elseif ($hasMsvc) {
    cmake -S $root -B $build -A x64 -DZC_BUILD_TESTS=ON | Out-Host
    cmake --build $build --config $Config --parallel | Out-Host
    ctest --test-dir $build -C $Config --output-on-failure | Out-Host
    $exe = Join-Path $build "$Config\\zapret-cpp.exe"
} elseif ($hasGxx) {
    cmake -S $root -B $build -G "MinGW Makefiles" "-DCMAKE_BUILD_TYPE=$Config" -DZC_BUILD_TESTS=ON | Out-Host
    cmake --build $build --parallel | Out-Host
    ctest --test-dir $build --output-on-failure | Out-Host
    $exe = Join-Path $build "zapret-cpp.exe"
} else {
    throw "No supported C++ toolchain found."
}
Write-Host "built: $exe" -ForegroundColor Green
