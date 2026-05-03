# engine_cpp

Core C++20 domain model and engine contract implementation.

- Network interface/scope abstractions
- Device identity and session models
- Probe and scan profile serialization
- Security findings and report summaries
- Error discipline (`ErrorCode`, `Error`, `Result<T>`)
- Structured logging (`Logger`)
- Mock scan contract with explicit error paths (`run_dry_scan`, `enumerate_adapters`)
- Adapter inventory bridge to C17 netcore (`list_network_adapters`, mock and live mode)
- Scan scope proposal module (`propose_scan_scope_from_adapter`, `propose_scan_scope_from_custom_cidr`)
- Safe C17 probe boundary scaffold (`netcore_boundary`) with cancellation and rate-limiter stubs
- ARP discovery C17 module + C++ wrapper (`discover_arp_devices`) with mock-safe outputs
- ICMP probe execution flow (`discover_icmp_hosts`) using ARP hosts and ping boundary wrapper
- TCP liveness hint flow (`discover_tcp_liveness`) with common ports and liveness states (open/closed/timeout/error)
- Prompt 11 (scan orchestration) added:
  - Scan session runner (`run_scan_session`) orchestrating ARP, ICMP, TCP
  - Progress event callback for user-safe staging visibility
  - Pause/cancel safety state handling and deterministic mock behavior in full session mode
  - Configuration for max-concurrency, qps, and jitter

JSON roundtrip behavior is local-only and safe in this stage.
