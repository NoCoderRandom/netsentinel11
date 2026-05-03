param(
    [string]$GuiExe = "build-qt-msvc\bin\Release\netsentinel11_gui.exe",
    [string[]]$NavigationLabels = @("Dashboard", "Devices", "Reports", "Settings"),
    [int]$StartupTimeoutSeconds = 20
)

$ErrorActionPreference = "Stop"

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -ItemType Directory -Force -Path "logs", "reports" | Out-Null
$log = Join-Path "logs" "gui_window_automation_$stamp.log"
$report = Join-Path "reports" "gui_window_automation_$stamp.md"

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NetSentinelMouseNative {
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);
  public const uint LEFTDOWN = 0x0002;
  public const uint LEFTUP = 0x0004;
}
'@

$resolvedGui = Resolve-Path $GuiExe
$process = Start-Process -FilePath $resolvedGui.Path -PassThru -WindowStyle Normal
$clicked = New-Object System.Collections.Generic.List[string]
$textSample = New-Object System.Collections.Generic.List[string]

try {
    $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 250
        $process.Refresh()
    } while ($process.MainWindowHandle -eq 0 -and (Get-Date) -lt $deadline)

    if ($process.MainWindowHandle -eq 0) {
        throw "GUI main window did not appear within $StartupTimeoutSeconds seconds."
    }

    $root = [System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
    $windowName = $root.Current.Name
    $className = $root.Current.ClassName
    "WindowName=$windowName" | Tee-Object -FilePath $log -Append
    "ClassName=$className" | Tee-Object -FilePath $log -Append

    $all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($element in $all) {
        $name = $element.Current.Name
        if ($name -and $name.Trim().Length -gt 0 -and !$textSample.Contains($name.Trim())) {
            $textSample.Add($name.Trim())
        }
        if ($textSample.Count -ge 80) {
            break
        }
    }

    $mustHave = @("NetSentinel11", "Dashboard", "Scan", "Devices", "Reports", "Settings")
    foreach ($label in $mustHave) {
        if (!($textSample -contains $label)) {
            throw "Expected UI Automation text was not found: $label"
        }
    }

    foreach ($label in $NavigationLabels) {
        $condition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::NameProperty,
            $label
        )
        $element = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        if ($null -eq $element) {
            throw "Navigation element not found: $label"
        }
        $rect = $element.Current.BoundingRectangle
        if ($rect.Width -le 0 -or $rect.Height -le 0) {
            throw "Navigation element has no clickable bounds: $label"
        }
        $x = [int]($rect.Left + ($rect.Width / 2))
        $y = [int]($rect.Top + ($rect.Height / 2))
        [NetSentinelMouseNative]::SetCursorPos($x, $y) | Out-Null
        [NetSentinelMouseNative]::mouse_event([NetSentinelMouseNative]::LEFTDOWN, 0, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 80
        [NetSentinelMouseNative]::mouse_event([NetSentinelMouseNative]::LEFTUP, 0, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 500
        $clicked.Add("$label at $x,$y")
        "Clicked $label at $x,$y" | Tee-Object -FilePath $log -Append
    }

    $body = @"
# GUI Window Automation - $stamp

## Result
PASS

## Executable
- $($resolvedGui.Path)

## Window
- Name: $windowName
- Class: $className

## Clicked navigation
$(($clicked | ForEach-Object { "- $_" }) -join "`n")

## UI Automation text sample
````text
$(($textSample | Select-Object -First 80) -join "`n")
````

## Log
- $log
"@
    Set-Content -Path $report -Value $body -Encoding UTF8
    Add-Content -Path PROJECT_PROGRESS.md -Value "`n`n$body"

    Write-Output "GUI_WINDOW_AUTOMATION_REPORT=$report"
    Write-Output "GUI_WINDOW_AUTOMATION_LOG=$log"
} finally {
    if (!$process.HasExited) {
        $process.CloseMainWindow() | Out-Null
        Start-Sleep -Seconds 2
        if (!$process.HasExited) {
            $process.Kill()
        }
    }
}
