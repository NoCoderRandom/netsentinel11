# Accessibility, Localization, And Low Resource Mode

Date: 2026-05-02

## Implemented readiness layer

- Keyboard navigation checklist for the final Qt GUI.
- Screen-reader label checklist for scan controls, device cards, severity badges, progress, reports, and settings.
- High-DPI/scalable layout guidance.
- Default English language key file under `i18n/en-US.txt`.
- Low-resource scan settings for older Windows 11 PCs and slow networks.
- CLI verification that does not require Qt6 or live network scanning.

## Low-resource scan defaults

- Timeout: 12 seconds.
- Max concurrency: 2.
- Max QPS: 4.
- Schedule interval: 30 minutes.
- Default probes: ARP and ICMP only.
- No default TCP fan-out.

## Verification

```powershell
cmake --build build --config Debug --target netsentinel_ui netsentinel_accessibility_low_resource_smoke netsentinel11
ctest --test-dir build --output-on-failure -R "accessibility_low_resource_smoke|gui_accessibility_cli_mock" -C Debug
build\bin\Debug\netsentinel11.exe gui accessibility --low-resource --high-contrast --language en-US --output reports\accessibility_prompt82.md
```
