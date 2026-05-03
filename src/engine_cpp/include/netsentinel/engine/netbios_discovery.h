#pragma once

#include <cstddef>
#include <string>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct NetBiosDiscoveryConfig {
    long long timeout_ms = 500;
    long long cache_ttl_ms = 5 * 60 * 1000;
    bool cache_enabled = true;
    bool mock_mode = false;
};

struct NetBiosDiscovery {
    bool resolved = false;
    bool timed_out = false;
    std::string device_name;
    std::string workgroup;
    std::string source;
    int confidence = 0;
    std::string details;
};

Result<NetBiosDiscovery> resolve_netbios_name_for_ip(
    const std::string& ip_address,
    const NetBiosDiscoveryConfig& config = {}
);

Result<std::size_t> clear_netbios_discovery_cache();

} // namespace netsentinel::engine
