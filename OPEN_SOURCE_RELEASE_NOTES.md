# NetSentinel11 Open Source Release Notes

## Current validated package

- Package: `dist/NetSentinel11-portable-release-20260502_224910.zip`
- SHA256: `06B31062D13BC01621585151AC2D82DBF5250BB26250945584E011539A145E20`
- Package report: `reports/portable_release_package_scripted_20260502_224910.md`
- Packaged validation report: `reports/packaged_portable_validation_20260502_224314.md`
- Portable install script validation: `reports/portable_installer_script_validation_20260502_224635.md`
- Package contents validation: `reports/package_contents_validation_20260502_224914.md`
- Packaged GUI window automation: `reports/gui_window_automation_20260502_224919.md`
- Packaged GUI screenshot/action validation: `reports/release_gui_validation_20260502_224935.md`

## What is included

- Windows 11 Qt 6 GUI executable.
- CLI scanner executable.
- Qt runtime deployment files and plugins.
- Human release test guide.
- Latest validation reports and checksums.
- No-admin `install.ps1` and `uninstall.ps1` scripts for the portable package.
- Safe authorized LAN scan action from the GUI command layer.

## Validated capabilities

- Release build succeeds.
- Portable package launches the GUI in screenshot mode.
- GUI validation covers light and dark screens.
- GUI action layer validates:
  - Live DHCP adapter discovery.
  - Live Windows DNS lookup.
  - Live local traceroute.
  - Live local outage check.
  - Live authorized router service identification.
  - Live authorized LAN scan trigger.
- Authorized LAN scan tested against `192.168.50.0/24`.
- Router ground truth comparison saved under `data/ground_truth/`.

## Important discovery improvement

The scanner previously depended too heavily on ARP/cache results. That caused reachable devices to be missed when they were not already present in ARP results.

The current Release build adds:

- Bounded live ICMP CIDR sweep for `scan icmp`.
- Supplemental live ICMP sweep inside `scan session`.
- Honest GUI scan counts:
  - `arp_count`
  - `icmp_reachable_count`
  - `icmp_probed_count`

Latest observed authorized GUI scan result:

```text
arp_count=13
icmp_reachable_count=12
icmp_probed_count=254
dry_run=false
```

## Safety boundaries

Use NetSentinel11 only on networks you own or have explicit authorization to test.

The validated release workflow does not use:

- Exploit payloads.
- Credential brute forcing.
- MITM.
- ARP spoofing.
- Deauthentication.
- Stealth behavior.
- Public IP scanning.

## Known limitations

- The current artifact is a portable zip, not a signed installer.
- WiX Toolset is installed, but MSI creation is blocked until a human reviews/accepts the WiX OSMF EULA. Codex did not accept that legal agreement on the user's behalf.
- Some mobile or privacy-randomized devices may still be invisible if they do not answer ARP, ICMP, TCP, mDNS, SSDP, NetBIOS, or other safe discovery methods at scan time.
- Router-provided client lists can see associated Wi-Fi clients that a Windows host cannot always probe directly.
- The GUI has screenshot/action validation, but deeper mouse/keyboard click automation should continue before a formal stable release.
- Optional `windeployqt` warnings about DirectX shader compiler files were observed; they did not block GUI launch, but should be reviewed before installer signing.

## Recommended tester workflow

1. Read `RELEASE_TEST_GUIDE.md`.
2. Extract the portable zip.
3. Launch `app\netsentinel11_gui.exe`.
4. Run a safe authorized scan only on your own LAN.
5. Save the console output and any router truth list if reporting discovery accuracy issues.

## Reporting issues

When reporting a discovery issue, include:

- Windows version.
- Network CIDR tested.
- Whether the LAN was authorized.
- App command used.
- Console output.
- Router truth list if available.
- Whether the missing device answers Windows `ping`.
- Whether the missing device appears in `arp -a`.
