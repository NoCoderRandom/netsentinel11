param(
    [string]$ReleaseDir = "build-qt-msvc\bin\Release",
    [string]$OutputRoot = "reports\screenshots",
    [switch]$SkipLan
)

$ErrorActionPreference = "Stop"

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$gui = Join-Path $ReleaseDir "netsentinel11_gui.exe"
$cli = Join-Path $ReleaseDir "netsentinel11.exe"
$outDir = Join-Path $OutputRoot "release_gui_validation_$stamp"
$log = Join-Path "logs" "release_gui_validation_$stamp.log"

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

if (!(Test-Path $gui)) {
    throw "GUI executable not found: $gui"
}
if (!(Test-Path $cli)) {
    throw "CLI executable not found: $cli"
}

function Run-Step {
    param(
        [string]$Label,
        [scriptblock]$Command
    )
    "===== $Label =====" | Tee-Object -FilePath $log -Append
    $output = & $Command 2>&1
    $output | Tee-Object -FilePath $log -Append
    "" | Tee-Object -FilePath $log -Append
}

$lightViews = @("dashboard", "devices", "map", "scan", "security", "timeline", "bandwidth", "reports", "settings", "wifi")
$darkViews = @("dashboard", "devices", "security", "reports", "settings")

foreach ($view in $lightViews) {
    $path = Join-Path $outDir "$view-light.png"
    Run-Step "screenshot $view light" { & $gui --screenshot $path --view $view --theme light }
    if (!(Test-Path $path)) {
        throw "Expected screenshot was not created: $path"
    }
}

foreach ($view in $darkViews) {
    $path = Join-Path $outDir "$view-dark.png"
    Run-Step "screenshot $view dark" { & $gui --screenshot $path --view $view --theme dark }
    if (!(Test-Path $path)) {
        throw "Expected screenshot was not created: $path"
    }
}

Run-Step "GUI action live DHCP" { & $cli gui action --id diagnostics.dhcp }
Run-Step "GUI action live DNS" { & $cli gui action --id diagnostics.dns --target localhost }
Run-Step "GUI action live local traceroute" { & $cli gui action --id diagnostics.traceroute --target 127.0.0.1 }
Run-Step "GUI action live local outage" { & $cli gui action --id outage.check --target 127.0.0.1 }
Run-Step "GUI action router service identification" { & $cli gui action --id diagnostics.service --target 192.168.50.1 --apply --confirm }

if (!$SkipLan) {
    Run-Step "GUI action authorized LAN scan" { & $cli gui action --id scan.trigger --target 192.168.50.0/24 --apply --confirm }
}

$report = Join-Path "reports" "release_gui_validation_$stamp.md"
$body = @"
# Release GUI Validation - $stamp

## Status
PASS

## Executables
- GUI: $gui
- CLI: $cli

## Screenshots
- Folder: $outDir
- Light views: $($lightViews -join ', ')
- Dark views: $($darkViews -join ', ')

## GUI backend actions
- diagnostics.dhcp
- diagnostics.dns
- diagnostics.traceroute
- outage.check
- diagnostics.service
$(if (!$SkipLan) { "- scan.trigger against authorized 192.168.50.0/24" } else { "- scan.trigger skipped by request" })

## Log
- $log
"@
Set-Content -Path $report -Value $body -Encoding UTF8

Write-Output "RELEASE_GUI_VALIDATION_REPORT=$report"
Write-Output "RELEASE_GUI_SCREENSHOTS=$outDir"
Write-Output "RELEASE_GUI_VALIDATION_LOG=$log"
