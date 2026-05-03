param(
    [string]$BuildDir = "build",
    [string]$OutputDir = "dist",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

Write-Host "NetSentinel11 WiX packaging dry-run plan"
Write-Host "BuildDir: $BuildDir"
Write-Host "OutputDir: $OutputDir"
Write-Host "Configuration: $Configuration"
Write-Host "This script does not install Npcap, create firewall rules, register services, or sign binaries."
Write-Host "Future release workflow: render Product.wxs.in, run candle.exe/light.exe, then sign with SignTool."
