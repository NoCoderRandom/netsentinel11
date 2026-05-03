param(
    [string]$ReleaseDir = "build-qt-msvc\bin\Release",
    [string]$DistDir = "dist",
    [string]$QtBin = "C:\Qt\6.8.3\msvc2022_64\bin",
    [switch]$SkipDeploy
)

$ErrorActionPreference = "Stop"

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$releasePath = Resolve-Path $ReleaseDir
$distPath = New-Item -ItemType Directory -Force -Path $DistDir
$packageName = "NetSentinel11-portable-release-$stamp"
$stageRoot = Join-Path $distPath.FullName $packageName
$appRoot = Join-Path $stageRoot "app"
$docsRoot = Join-Path $stageRoot "docs"
$reportsRoot = Join-Path $stageRoot "reports"
$toolsRoot = Join-Path $stageRoot "tools"
$zipPath = Join-Path $distPath.FullName "$packageName.zip"
$reportPath = Join-Path "reports" "portable_release_package_scripted_$stamp.md"

if (!(Test-Path (Join-Path $releasePath "netsentinel11_gui.exe"))) {
    throw "Release GUI executable not found in $releasePath"
}
if (!(Test-Path (Join-Path $releasePath "netsentinel11.exe"))) {
    throw "Release CLI executable not found in $releasePath"
}

if (!$SkipDeploy) {
    $deploy = Join-Path $QtBin "windeployqt.exe"
    if (!(Test-Path $deploy)) {
        throw "windeployqt.exe not found at $deploy. Pass -SkipDeploy only if the Release folder is already deployed."
    }
    & $deploy --release --no-translations --no-system-d3d-compiler --no-opengl-sw (Join-Path $releasePath "netsentinel11_gui.exe")
}

if (Test-Path $stageRoot) {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $appRoot, $docsRoot, $reportsRoot, $toolsRoot | Out-Null

Copy-Item -Path (Join-Path $releasePath "*") -Destination $appRoot -Recurse -Force

$docCandidates = @(
    "RELEASE_TEST_GUIDE.md",
    "README.md",
    "README_FIRST_HUMAN.md",
    "PROJECT_PROGRESS.md",
    "REAL_LAN_TEST_REPORT.md",
    "GUI_MILESTONE_PLAN.md",
    "FINAL_COMPLETION_CHECKLIST.md",
    "OPEN_SOURCE_RELEASE_NOTES.md",
    "LICENSE",
    "LICENSE.md",
    "COPYING"
)

foreach ($doc in $docCandidates) {
    if (Test-Path $doc) {
        Copy-Item -Path $doc -Destination $docsRoot -Force
    }
}

$toolCandidates = @(
    "scripts\validate_release_gui.ps1",
    "scripts\validate_gui_window_automation.ps1"
)
foreach ($tool in $toolCandidates) {
    if (Test-Path $tool) {
        Copy-Item -Path $tool -Destination $toolsRoot -Force
    }
}

$latestReports = @(
    "release_gui_validation_*.md",
    "scan_discovery_fix_report_*.md",
    "portable_release_package_refreshed_*.md",
    "router_truth_comparison_*.md"
)
foreach ($pattern in $latestReports) {
    $file = Get-ChildItem "reports" -Filter $pattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -ne $file) {
        Copy-Item -Path $file.FullName -Destination $reportsRoot -Force
    }
}

$readme = @"
NetSentinel11 portable Windows build
====================================

Start the GUI:
  app\netsentinel11_gui.exe

Run a safe authorized LAN scan from a terminal:
  app\netsentinel11.exe gui action --id scan.trigger --target 192.168.50.0/24 --apply --confirm

Run local diagnostics:
  app\netsentinel11.exe gui action --id diagnostics.dhcp
  app\netsentinel11.exe gui action --id diagnostics.dns --target localhost
  app\netsentinel11.exe gui action --id diagnostics.traceroute --target 127.0.0.1
  app\netsentinel11.exe gui action --id outage.check --target 127.0.0.1

Safety:
  Only scan networks you own or have explicit authorization to test.
  Do not scan public IPs without authorization.
  Do not exploit, brute force, spoof, deauth, MITM, or use stealth behavior.

More details:
  docs\RELEASE_TEST_GUIDE.md
"@
Set-Content -Path (Join-Path $stageRoot "README_PORTABLE.txt") -Value $readme -Encoding UTF8

$installer = @'
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\NetSentinel11",
    [switch]$NoDesktopShortcut
)

$ErrorActionPreference = "Stop"
$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceApp = Join-Path $sourceRoot "app"

if (!(Test-Path (Join-Path $sourceApp "netsentinel11_gui.exe"))) {
    throw "Portable app folder is missing netsentinel11_gui.exe"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $sourceApp "*") -Destination $InstallDir -Recurse -Force

$launch = @"
@echo off
start "" "%LOCALAPPDATA%\NetSentinel11\netsentinel11_gui.exe"
"@
Set-Content -Path (Join-Path $InstallDir "Start NetSentinel11.bat") -Value $launch -Encoding ASCII

if (!$NoDesktopShortcut) {
    $desktop = [Environment]::GetFolderPath("Desktop")
    if ($desktop) {
        $shortcutPath = Join-Path $desktop "NetSentinel11.lnk"
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = Join-Path $InstallDir "netsentinel11_gui.exe"
        $shortcut.WorkingDirectory = $InstallDir
        $shortcut.Description = "NetSentinel11 network scanner"
        $shortcut.Save()
    }
}

Write-Output "INSTALLED_TO=$InstallDir"
Write-Output "START_EXE=$(Join-Path $InstallDir 'netsentinel11_gui.exe')"
'@
Set-Content -Path (Join-Path $stageRoot "install.ps1") -Value $installer -Encoding UTF8

$uninstaller = @'
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\NetSentinel11",
    [switch]$KeepDesktopShortcut
)

$ErrorActionPreference = "Stop"

if (Test-Path $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

if (!$KeepDesktopShortcut) {
    $desktop = [Environment]::GetFolderPath("Desktop")
    if ($desktop) {
        $shortcutPath = Join-Path $desktop "NetSentinel11.lnk"
        if (Test-Path $shortcutPath) {
            Remove-Item -LiteralPath $shortcutPath -Force
        }
    }
}

Write-Output "UNINSTALLED_FROM=$InstallDir"
'@
Set-Content -Path (Join-Path $stageRoot "uninstall.ps1") -Value $uninstaller -Encoding UTF8

$hashLines = New-Object System.Collections.Generic.List[string]
Get-ChildItem -Path $stageRoot -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($stageRoot.Length + 1).Replace("\", "/")
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    $hashLines.Add("$hash  $relative")
}
Set-Content -Path (Join-Path $stageRoot "SHA256SUMS.txt") -Value $hashLines -Encoding UTF8

if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $stageRoot "*") -DestinationPath $zipPath -Force

$zipHash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
$zipSize = (Get-Item $zipPath).Length

New-Item -ItemType Directory -Force -Path "reports" | Out-Null
$report = @"
# Scripted Portable Release Package - $stamp

## Artifact
- Zip: $zipPath
- SHA256: $zipHash
- Size bytes: $zipSize

## Staging folder
- $stageRoot

## Included
- app/: Release GUI, CLI, Qt runtime files, and plugins.
- docs/: human release guide and selected project status documents.
- reports/: latest validation evidence copied from the repository reports folder.
- tools/: validation scripts for release/screenshots/window automation.
- README_PORTABLE.txt
- install.ps1
- uninstall.ps1
- SHA256SUMS.txt

## Start command

    app\netsentinel11_gui.exe

## Safe LAN test command

    app\netsentinel11.exe gui action --id scan.trigger --target 192.168.50.0/24 --apply --confirm

## Optional per-user install command

    powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
"@
Set-Content -Path $reportPath -Value $report -Encoding UTF8

Write-Output "PORTABLE_STAGE=$stageRoot"
Write-Output "PORTABLE_ZIP=$zipPath"
Write-Output "PORTABLE_SHA256=$zipHash"
Write-Output "PORTABLE_REPORT=$reportPath"
