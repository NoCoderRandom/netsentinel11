#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct SsdpDiscoveryConfig {
    long long query_timeout_ms = 800;
    long long response_wait_ms = 900;
    long long http_timeout_ms = 600;
    std::size_t max_devices = 128;
    bool parse_description = true;
    bool mock_mode = false;
};

struct SsdpDevice {
    std::string target;
    std::string usn;
    std::string st;
    std::string nt;
    std::string location;
    std::string manufacturer;
    std::string model_name;
    std::string device_type;
    std::string friendly_name;
    std::string presentation_url;
    std::string server;
    long long ttl_ms = 0;
    std::string source;
    int confidence = 0;
    std::string details;
};

Result<std::vector<SsdpDevice>> discover_ssdp_devices(const SsdpDiscoveryConfig& config = {});

} // namespace netsentinel::engine
