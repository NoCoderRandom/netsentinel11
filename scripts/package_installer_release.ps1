param(
    [string]$SourceAppDir = "",
    [string]$OutputDir = "dist",
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"

function Resolve-SourceAppDir {
    param([string]$Requested)

    if ($Requested -and (Test-Path $Requested)) {
        return (Resolve-Path $Requested).Path
    }

    $latestPortable = Get-ChildItem -Path "dist" -Directory -Filter "NetSentinel11-portable-release-*" -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        Select-Object -First 1

    if ($latestPortable) {
        $candidate = Join-Path $latestPortable.FullName "app"
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    $fallback = "build-qt-msvc\bin\Release"
    if (Test-Path $fallback) {
        return (Resolve-Path $fallback).Path
    }

    throw "No source app directory found. Build first or pass -SourceAppDir."
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$source = Resolve-SourceAppDir -Requested $SourceAppDir
$dist = New-Item -ItemType Directory -Force -Path $OutputDir
$packageName = "NetSentinel11-installer-release-$stamp"
$stageRoot = Join-Path $dist.FullName $packageName
$appDir = Join-Path $stageRoot "app"
$zipPath = Join-Path $dist.FullName "$packageName.zip"

if (Test-Path $stageRoot) {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $appDir | Out-Null

Copy-Item -Path (Join-Path $source "*") -Destination $appDir -Recurse -Force

$setup = @'
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\NetSentinel11"
)

$ErrorActionPreference = "Stop"

$source = Join-Path $PSScriptRoot "app"
if (!(Test-Path $source)) {
    throw "App folder not found: $source"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $source "*") -Destination $InstallDir -Recurse -Force

$shortcutDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$shortcutPath = Join-Path $shortcutDir "NetSentinel11.lnk"
$target = Join-Path $InstallDir "netsentinel11_gui.exe"

if (Test-Path $target) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $target
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "NetSentinel11 local network scanner"
    $shortcut.Save()
}

Write-Host "NetSentinel11 installed to $InstallDir"
'@

$uninstall = @'
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\NetSentinel11"
)

$ErrorActionPreference = "Stop"

$shortcutPath = Join-Path (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs") "NetSentinel11.lnk"
if (Test-Path $shortcutPath) {
    Remove-Item -LiteralPath $shortcutPath -Force
}

if (Test-Path $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

Write-Host "NetSentinel11 removed from $InstallDir"
'@

$readme = @"
# NetSentinel11 installer-style release

Version: $Version
Generated: $stamp

## Install

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Default install location:

```text
%LOCALAPPDATA%\Programs\NetSentinel11
```

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

## Notes

This installer-style package does not install drivers, create firewall rules, register services, or change startup behavior.

MSI/MSIX packaging is prepared separately in `packaging\windows` and should be signed before broad public distribution.
"@

Set-Content -Path (Join-Path $stageRoot "setup.ps1") -Value $setup -Encoding UTF8
Set-Content -Path (Join-Path $stageRoot "uninstall.ps1") -Value $uninstall -Encoding UTF8
Set-Content -Path (Join-Path $stageRoot "INSTALLER_README.md") -Value $readme -Encoding UTF8

if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $stageRoot "*") -DestinationPath $zipPath -Force

$hash = Get-FileHash -Algorithm SHA256 -Path $zipPath
Write-Output "INSTALLER_STAGE=$stageRoot"
Write-Output "INSTALLER_ZIP=$zipPath"
Write-Output "INSTALLER_SHA256=$($hash.Hash)"
