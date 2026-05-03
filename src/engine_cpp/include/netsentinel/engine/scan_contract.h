#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "netsentinel/engine/domain_model.h"
#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct ScanDependencies {
    bool permission_granted = true;
    bool adapters_available = true;
};

struct ScanCancellation {
    bool requested = false;
    bool pause_requested = false;
};

enum class ScanProgressKind {
    started,
    stage_started,
    stage_progress,
    host_result,
    stage_complete,
    completed,
    cancelled,
    paused,
    failed
};

struct ScanProgressEvent {
    ScanProgressKind kind = ScanProgressKind::started;
    std::string stage;
    std::size_t stage_index = 0;
    std::size_t stage_total = 0;
    std::size_t current = 0;
    std::size_t total = 0;
    std::string target;
    std::string message;
};

using ScanProgressCallback = std::function<void(const ScanProgressEvent&)>;

struct ScanSessionRunOptions {
    bool mock_mode = false;
    std::size_t max_concurrency = 4;
    std::size_t max_qps = 16;
    long long jitter_ms_min = 0;
    long long jitter_ms_max = 0;
    std::vector<std::string> enabled_probes;
    std::vector<int> tcp_port_hints;
    std::size_t schedule_interval_minutes = 0;
    std::string snmp_target;
    std::string snmp_community;
    std::string snmp_version = "2c";
    ScanProgressCallback on_progress;
};

Result<NetworkScope> validate_scope(const NetworkScope& scope);
Result<std::vector<NetworkInterface>> enumerate_adapters(const ScanDependencies& dependencies);
Result<ScanSession> run_dry_scan(const ScanProfile& profile, const ScanDependencies& dependencies, const ScanCancellation& cancellation);
Result<ScanSession> run_scan_session(
    const ScanProfile& profile,
    const ScanDependencies& dependencies,
    const ScanCancellation& cancellation,
    const ScanSessionRunOptions& options = {}
);

} // namespace netsentinel::engine
