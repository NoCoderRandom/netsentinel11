#pragma once

#include <string>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct ProbeBoundaryConfig {
    long long connect_timeout_ms = 1500;
    long long total_timeout_ms = 3000;
    unsigned int max_qps = 10;
};

struct ProbeExecutionResult {
    std::string target;
    bool success = false;
    bool timed_out = false;
    bool cancelled = false;
    long long elapsed_ms = 0;
    std::string details;
};

Result<ProbeExecutionResult> run_probe(const std::string& target, const ProbeBoundaryConfig& config, bool request_cancel, bool mock_mode);
Result<ProbeExecutionResult> run_stub_probe(const std::string& target, const ProbeBoundaryConfig& config, bool request_cancel = false);
Result<ProbeExecutionResult> run_tcp_connect_probe(
    const std::string& target,
    int port,
    const ProbeBoundaryConfig& config,
    bool request_cancel = false,
    bool mock_mode = false
);

} // namespace netsentinel::engine
