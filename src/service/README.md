# service

Background service/tray orchestration scaffold.

Current state
- Provides a stubbed tray-control contract in `include/netsentinel/service/tray_service.h`.
- CLI entry points (`netsentinel11 tray status|start|stop`) are implemented and backed by a persisted state file.
- State persistence is file-based for safe local mock workflows until true Windows Service integration exists.

Roadmap
- Replace file-backed stub with Windows service process control (SCM install, lifecycle control).
- Wire tray icon/menu surface to this state contract and surface real monitoring telemetry.
- Add secure IPC and hardened transport for commands (`start`, `stop`, `status`) once service host is implemented.
