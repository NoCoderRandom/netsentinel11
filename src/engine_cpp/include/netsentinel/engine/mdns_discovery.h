#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct MdnsDiscoveryConfig {
    long long query_timeout_ms = 700;
    long long response_wait_ms = 650;
    std::size_t max_services = 128;
    bool mock_mode = false;
};

struct MdnsService {
    std::string service_name;
    std::string service_instance;
    std::string device_type_hint;
    std::string target;
    int port = 0;
    long long ttl_ms = 0;
    std::string source;
    int confidence = 0;
    std::string details;
};

Result<std::vector<MdnsService>> discover_mdns_services(const MdnsDiscoveryConfig& config = {});

} // namespace netsentinel::engine
