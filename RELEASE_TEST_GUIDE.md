# NetSentinel11 Release Test Guide

This guide is for safe local testing of the Windows Release build.

## Current portable package

- Package: `dist/NetSentinel11-portable-release-20260502_224910.zip`
- SHA256: `06B31062D13BC01621585151AC2D82DBF5250BB26250945584E011539A145E20`

## Run the GUI

1. Extract the portable zip.
2. Start `netsentinel11_gui.exe`.
3. Use the dashboard, devices, scan, security, reports, bandwidth, and settings screens.

Optional no-admin install from the extracted package:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
```

## Run a safe authorized LAN scan

Only scan networks you own or have explicit permission to test.

```powershell
netsentinel11.exe gui action --id scan.trigger --target 192.168.50.0/24 --apply --confirm
```

Expected success output includes:

```text
GUI_ACTION_OK
dry_run=false
arp_count=<number>
icmp_reachable_count=<number>
icmp_probed_count=<number>
```

## Run real local diagnostics

```powershell
netsentinel11.exe gui action --id diagnostics.dhcp
netsentinel11.exe gui action --id diagnostics.dns --target localhost
netsentinel11.exe gui action --id diagnostics.traceroute --target 127.0.0.1
netsentinel11.exe gui action --id outage.check --target 127.0.0.1
netsentinel11.exe gui action --id diagnostics.service --target 192.168.50.1 --apply --confirm
```

## Repeat the Release GUI validation

From the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\validate_release_gui.ps1
```

This creates screenshots and a validation report under `reports/`.

## Latest validation evidence

- GUI validation: `reports/release_gui_validation_20260502_220842.md`
- Packaged portable validation: `reports/packaged_portable_validation_20260502_224314.md`
- Package contents validation: `reports/package_contents_validation_20260502_224914.md`
- Packaged GUI window automation: `reports/gui_window_automation_20260502_224919.md`
- Packaged GUI screenshot/action validation: `reports/release_gui_validation_20260502_224935.md`
- Scripted package report: `reports/portable_release_package_scripted_20260502_224910.md`
- Portable install script validation: `reports/portable_installer_script_validation_20260502_224635.md`
- Discovery fix report: `reports/scan_discovery_fix_report_20260502_220258.md`
- Router truth files: `data/ground_truth/router_clients_by_band_192_168_50_20260502_220258.csv`

## Safety rules

- Do not scan public IPs without authorization.
- Do not brute-force credentials.
- Do not exploit services.
- Do not use MITM, ARP spoofing, deauth, stealth, or packet injection.
- Keep tests to authorized local LANs such as `192.168.50.0/24` or `192.168.1.0/24`.
