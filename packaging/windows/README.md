# NetSentinel11 Windows Packaging

This folder contains safe packaging templates for future Release builds.

- `build_wix.ps1` prepares a WiX packaging workflow without installing drivers or modifying firewall rules.
- `Product.wxs.in` is a WiX template with service/tray placeholders.
- `msix_manifest_template.xml` is a minimal MSIX manifest template.

Npcap detection, firewall rules, service registration, auto-update, and code signing must remain explicit and user-visible.
