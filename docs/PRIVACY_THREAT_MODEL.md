# Privacy Threat Model And Data Minimization

Date: 2026-05-02

## Sensitive local data

- Device names and hostnames.
- IP addresses and MAC addresses.
- Vendor hints and device types.
- Presence history.
- Traffic/bandwidth history.
- Report exports.
- Logs that may accidentally include secrets, tokens, router credentials, or SNMP community strings.

## Default minimization settings

- Redact IP addresses before sharing logs.
- Redact MAC addresses before sharing logs.
- Redact secrets before sharing logs.
- Require export acknowledgement for reports that may contain private device data.
- Keep default text in English.

## Retention defaults

- Inventory: 90 days.
- Traffic history: 30 days.
- Presence history: 14 days.
- Logs: 14 days.
- Report exports: 30 days.

## Export warning

Reports can contain private device data. Exported reports should be shared only with authorized recipients, and users should acknowledge the warning before export workflows that leave the local machine.

## Verification

```powershell
cmake --build build --config Debug --target netsentinel_api netsentinel_privacy_policy_smoke netsentinel11
ctest --test-dir build --output-on-failure -R "privacy_policy_smoke|privacy_review_cli_mock" -C Debug
build\bin\Debug\netsentinel11.exe privacy review --mock --export --ack-export --output reports\privacy_prompt83.md
```
