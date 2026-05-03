Param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [string]$BuildDirectory = "build"
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -ne "Desktop" -and $PSVersionTable.PSEdition -ne "Core") {
    throw "PowerShell execution environment is unsupported. Run in Windows PowerShell 7+ or Windows PowerShell."
}

if (-not (Test-Path $BuildDirectory)) {
    New-Item -ItemType Directory -Path $BuildDirectory | Out-Null
}

$toolchainArg = @()
$vcpkgRoot = $env:VCPKG_ROOT
if (-not [string]::IsNullOrWhiteSpace($vcpkgRoot) -and (Test-Path (Join-Path $vcpkgRoot "scripts\\buildsystems\\vcpkg.cmake"))) {
    $toolchain = Join-Path $vcpkgRoot "scripts\\buildsystems\\vcpkg.cmake"
    Write-Host "[INFO] Found VCPKG_ROOT. Using vcpkg toolchain: $toolchain"
    $toolchainArg = @("-DCMAKE_TOOLCHAIN_FILE=$toolchain")
} else {
    Write-Host "[WARN] VCPKG_ROOT not set or vcpkg toolchain missing. Proceeding with system dependencies."
}

cmake -S . -B $BuildDirectory -G "Visual Studio 17 2022" -A x64 @toolchainArg -DNETSENTINEL_ENABLE_TEST_DEPENDENCIES=ON
cmake --build $BuildDirectory --config $Configuration
ctest --test-dir $BuildDirectory --output-on-failure -C $Configuration

$exe = Join-Path $BuildDirectory "bin\\$Configuration\\netsentinel11.exe"
if (Test-Path $exe) {
    & $exe --smoke
} else {
    Write-Host "[WARN] Expected smoke executable missing: $exe"
}

