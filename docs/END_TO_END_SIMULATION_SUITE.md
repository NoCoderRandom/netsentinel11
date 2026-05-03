# End To End Simulation Suite

Date: 2026-05-02

## Coverage

- Mock discovery.
- Mock monitoring.
- Mock alerts.
- Metadata-only security checks.
- Mock bandwidth/top-talkers.
- Advisory/dry-run blocking backend.
- Mock reports with privacy warning expectations.

## Deterministic devices

The suite uses routers, phones, cameras, IoT devices, PCs, guests, tablets, and NAS fixtures. It does not scan real networks.

## CI-friendly targets

- Complete under 2 seconds.
- Open no sockets.
- Send no packets.
- Keep device fixtures deterministic.
- Exercise blocking in advisory/dry-run mode only.

## Verification

```powershell
cmake --build build --config Debug --target netsentinel_api netsentinel_e2e_simulation_smoke netsentinel11
ctest --test-dir build --output-on-failure -R "e2e_simulation_smoke|e2e_simulation_cli_mock" -C Debug
build\bin\Debug\netsentinel11.exe simulation run --mock --output reports\e2e_simulation_prompt84.md
```
