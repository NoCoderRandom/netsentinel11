#pragma once

#include <cstddef>
#include <string>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct HostnameResolutionConfig {
    long long timeout_ms = 850;
    long long cache_ttl_ms = 5 * 60 * 1000;
    bool cache_enabled = true;
    bool mock_mode = false;
};

struct HostnameResolution {
    bool resolved = false;
    bool timed_out = false;
    std::string hostname;
    std::string source;
    int confidence = 0;
    std::string details;
};

Result<HostnameResolution> resolve_hostname_for_ip(
    const std::string& ip_address,
    const HostnameResolutionConfig& config = {}
);

Result<std::size_t> clear_hostname_resolution_cache();

} // namespace netsentinel::engine

