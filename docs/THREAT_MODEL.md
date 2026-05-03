# Threat Model

Assets:

- Device inventory and labels.
- Workspace history and scan timelines.
- Local API tokens.
- Reports and exports.
- Optional service/tray permissions.
- Optional packet capture capability.

Primary mitigations:

- Local-only defaults.
- Mock/dry-run verification paths.
- Explicit confirmation for risky actions.
- No ARP spoofing, deauthentication, MITM, exploit payloads, or stealth behavior.
- Installer permissions are explained before they are requested.
