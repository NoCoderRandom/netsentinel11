# Release packaging

NetSentinel11 uses two user-facing Windows release channels plus source builds.

## 1. Portable release

The portable release is the simplest artifact for early testers and open-source friends.

```powershell
cmake --build build-qt-msvc --config Release
powershell -ExecutionPolicy Bypass -File scripts\package_portable_release.ps1
```

Expected output:

- `dist\NetSentinel11-v0.1.0-portable-windows-x64-clean\`
- `dist\NetSentinel11-v0.1.0-portable-windows-x64.zip`
- SHA256 checksum printed by the script

Users unzip the package and run:

```powershell
NetSentinel11.exe
```

## 2. Installer-style release

The installer-style release wraps the deployed app with setup/uninstall scripts. It is useful before signed MSI/MSIX publishing is ready.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package_installer_release.ps1
```

Expected output:

- `dist\NetSentinel11-v0.1.0-installer-windows-x64-clean\`
- `dist\NetSentinel11-v0.1.0-installer-windows-x64.zip`

## 3. MSI/MSIX path

WiX/MSIX templates live in `packaging\windows`.

Important release rule:

- The maintainer must personally accept any WiX/OSMF EULA or signing requirements.
- Do not bundle drivers, firewall rules, packet capture, service registration, or startup tasks without clear user-visible consent.
- Code signing should be added before broad public distribution.

## Public privacy checklist

Before publishing release notes, screenshots, or reports:

- Do not include the maintainer's real name.
- Do not include public Internet IP addresses.
- Do not include personal Windows profile paths.
- Local private examples such as `192.168.1.0/24` are acceptable.
- Do not publish router admin exports, MAC address truth tables, private logs, or raw LAN reports.

## Suggested release assets

- Portable ZIP.
- Installer-style ZIP or signed MSI/MSIX.
- Screenshot collage from `docs/assets/screenshots`.
- SHA256 checksum.
- Short release notes focused on features, safety, and known limitations.
