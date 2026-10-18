# Builds hmkpm_cli for aarch64 Android with the NDK, compiling the vendored Lua
# sources in. Mirrors the CI recipe so a local build and a released binary come
# from the same inputs.
#
#   powershell -ExecutionPolicy Bypass -File build.sh.ps1
#   powershell -ExecutionPolicy Bypass -File build.sh.ps1 -Out helper\hmkpm_cli
param(
    [string]$Out = "helper\hmkpm_cli_new",
    [string]$Ndk = $env:ANDROID_NDK_HOME,
    [string]$Api = "31"
)
$ErrorActionPreference = "Stop"

# Without an explicit NDK, take the newest one under the SDK.
if (-not $Ndk) {
    $sdk = $env:ANDROID_SDK_ROOT
    if (-not $sdk) { $sdk = $env:ANDROID_HOME }
    if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk" }
    $candidate = Get-ChildItem (Join-Path $sdk "ndk") -Directory -ErrorAction SilentlyContinue |
        Sort-Object { [version]($_.Name -replace '[^\d.].*$', '') } -Descending |
        Select-Object -First 1
    if ($candidate) { $Ndk = $candidate.FullName }
}
if (-not $Ndk) { throw "NDK not found; set ANDROID_NDK_HOME or pass -Ndk" }

$cc = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang.cmd"
if (-not (Test-Path $cc)) { throw "compiler not found: $cc" }

$luaSrcs = @(Get-ChildItem "helper\vendor\lua" -Filter *.c | ForEach-Object { "helper/vendor/lua/" + $_.Name })
# loslib's tmpnam use is deprecated upstream and irrelevant here: run_lua never
# opens the os library, so this file's only reachable code is unused.
$clangArgs = @(
    "-O2", "-static", "-Wall", "-Wextra", "-Wno-unused-parameter",
    "-Wno-deprecated-declarations",
    "-I", "helper/vendor/lua",
    "helper/hmkpm_cli.c"
) + $luaSrcs + @("-lm", "-o", $Out)

& $cc @clangArgs
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
$size = (Get-Item $Out).Length
Write-Host "built $Out ($([math]::Round($size/1MB, 2)) MB)"
