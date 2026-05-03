# Windows Service And Tray Hardening

Date: 2026-05-02

## Product rule

The Windows service and tray controller must be optional, visible, and easy to stop or remove. NetSentinel11 must not create hidden persistence or stealth behavior.

## Implemented controls

- `tray status` shows whether monitoring is running.
- `tray start` records visible user-controlled monitoring state.
- `tray stop` records a stopped state.
- `tray cleanup` removes local tray state and logs for uninstall cleanup.
- `tray hardening` prints or writes a human-readable hardening plan.
- Local logs are written to a disclosed path.
- Crash recovery is bounded by a visible restart limit.
- Hidden persistence is explicitly marked as not allowed.

## Verification

```powershell
cmake --build build --config Debug --target netsentinel_service netsentinel_tray_service_hardening_smoke netsentinel11
ctest --test-dir build --output-on-failure -R "tray_service_hardening_smoke|tray_hardening_cli_mock|tray_status_cli_mock|tray_start_cli_mock|tray_stop_cli_mock" -C Debug
build\bin\Debug\netsentinel11.exe tray hardening --mock --output reports\tray_hardening_prompt80.md
build\bin\Debug\netsentinel11.exe tray start --mock --profile monitor --interval 2 --scope 192.168.50.0/24 --restart-limit 3
build\bin\Debug\netsentinel11.exe tray status --mock
build\bin\Debug\netsentinel11.exe tray stop --mock
build\bin\Debug\netsentinel11.exe tray cleanup --mock
```

## Remaining production work

- Wire these controls into the final Qt tray UI.
- Apply real Windows Service Control Manager recovery policy in the installer.
- Add signed executable metadata and service description.
- Confirm uninstall cleanup in the final installer package.
