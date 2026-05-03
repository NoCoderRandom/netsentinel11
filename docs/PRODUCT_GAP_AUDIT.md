# Product Gap Audit And Expanded Backlog

Last updated: 2026-05-02

This audit maps the first 50 prompts to the expanded NetSentinel11 mission and records the remaining product gaps in a way that is safe, testable, and honest about Windows desktop limitations.

## Current baseline

The project now has a local-first scanner foundation, device inventory, timeline, diagnostics, security heuristics, reporting, GUI-independent models, installer planning, and a hardening checkpoint. The important baseline behavior is that scanning stays local and authorized by default, mock and dry-run paths exist for verification, and risky controls require explicit confirmation.

## Expanded mission gaps

| Gap | Current status | Required direction | Planned prompts |
|---|---|---|---|
| Per-device bandwidth | Not yet implemented beyond roadmap/docs | Create source-aware interfaces, source confidence, rollups, top talkers, dashboard, reports, and policy hooks | 52-65 |
| Top talkers | Not yet implemented | Rank bandwidth usage from attributed data and show confidence | 61-65 |
| Safe enforcement backends | Advisory internet controls exist; real bandwidth enforcement is pending | Add reversible router/DNS/local-firewall backends with explicit confirmation and no spoofing | 66-68 |
| Digital-presence-style history | Timeline exists; privacy-focused presence experience is pending | Add opt-in presence history, family profiles, notifications, and minimization | 69-70 |
| Wi-Fi sweet spot logging | Wi-Fi scan/channel analysis exists; manual location logger is pending | Add user-triggered RSSI snapshots with location labels and low-impact storage | 71 |
| Nearby Wi-Fi environment view | Basic Wi-Fi visibility exists; polished environment view is pending | Present passive AP trends and quality context without nearby-client tracking | 72 |
| Optional agent architecture | Not yet implemented | Add authenticated mock-first collector protocol and only support explicit installs | 79 |
| API/service hardening | Local API and service stubs exist; hardening remains | Add auditability, safer defaults, least privilege, and token lifecycle | 78, 80 |
| Accessibility and low-resource mode | Not yet implemented | Add UI-independent accessibility/localization hooks and reduced-load settings | 82 |
| Release candidate readiness | Hardening checklist exists; RC polish remains | Complete simulation suite, privacy pass, packaging checks, final acceptance audit | 83-86 |

## Normal Windows desktop limitations

Per-device bandwidth cannot be faithfully implemented on a normal switched Windows desktop without a real visibility source. NetSentinel11 must label bandwidth data by source and confidence rather than pretending a desktop can magically see every device's traffic.

Valid future sources include:

- This PC's own Windows network counters.
- Optional Npcap capture on visible or mirrored traffic with explicit consent.
- Read-only SNMP router counters.
- UPnP/IGD router counters where available.
- NetFlow, sFlow, or IPFIX exported by an authorized router/firewall.
- Router plugins such as OpenWrt-style read-only integrations.
- Optional installed agents on authorized devices.

Invalid approaches remain out of scope:

- ARP spoofing.
- MITM interception.
- Deauthentication.
- Packet injection disruption.
- Credential guessing or default-password login attempts.
- Exploit payloads.
- Stealth behavior.

## Backlog commitments

| Backlog item | Safe acceptance criteria | Planned prompt |
|---|---|---|
| Bandwidth source abstraction | A GUI-independent interface reports source name, confidence, capability, and clear unavailable messages | 52 |
| Optional Npcap detection | Missing Npcap produces a friendly explanation and no capture attempt | 53 |
| Local machine bandwidth | Reports only this PC traffic and states that limitation | 54 |
| Visible LAN capture source | Requires explicit capture availability and labels incomplete switched-network visibility | 55 |
| SNMP router source | Read-only, user-configured, no credential attacks, clear failure messages | 56 |
| UPnP/IGD counter source | Read-only counters only and honest aggregate/per-device limitation text | 57 |
| Flow collector | Local collector accepts explicitly configured exporters only | 58 |
| Router plugin SDK | Fixture-tested read-only contract with least-privilege guidance | 59 |
| OpenWrt read-only plugin | No command execution; only documented read-only stats endpoints or fixtures | 60 |
| Attribution engine | Merges observations with confidence instead of overclaiming precision | 61 |
| Rollups and retention | Stores bandwidth history locally with retention controls | 62 |
| Top talkers and anomaly alerts | Alerts explain source, confidence, threshold, and why the alert fired | 63 |
| Bandwidth dashboard | UI model displays source limitations visibly | 64 |
| Bandwidth reports | Exports include measurement source and confidence notes | 65 |
| Quota policies | Dry-run evaluation before enforcement and local audit output | 66 |
| Safe bandwidth limit backends | Only reversible documented router/DNS/local-firewall backends | 67 |
| Unknown-device autoblock safe mode | Advisory/dry-run first, explicit confirmation for real enforcement | 68 |
| Digital presence history | Opt-in history with private labels and retention controls | 69 |
| Family profiles and notifications | Clear quiet hours, opt-in alerts, and local-first data | 70 |
| Wi-Fi sweet spot logger | Manual location labels, local snapshots, no nearby-client tracking | 71 |
| Nearby Wi-Fi environment | Passive AP environment only, no disruptive wireless behavior | 72 |
| Optional agent protocol | Mock agent first, authenticated protocol, explicit install language | 79 |

## Non-developer verification path

Build:

```powershell
cmake --build build --config Debug --target netsentinel_gap_audit_smoke netsentinel11
```

Run tests:

```powershell
ctest --test-dir build --output-on-failure -R "gap_audit_smoke|hardening_cli_mock" -C Debug
```

Safe local-only smoke command:

```powershell
.\build\bin\Debug\netsentinel11.exe hardening report --subnet 192.168.50.0/24 --devices 24 --seed 51
```

Expected behavior:

- The build succeeds.
- The gap audit test prints `GAP_AUDIT_SMOKE_OK`.
- The hardening command prints `HARDENING_REPORT_OK`.
- No packets are sent by the gap audit or hardening mock report.
