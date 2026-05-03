#pragma once

#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct ArpDevice {
    std::string ip_address;
    std::string mac_address;
    long long latency_ms = 0;
    std::string adapter_id;
};

struct ArpDiscoveryRequest {
    std::string cidr_or_range;
    std::size_t max_host_count = 1024;
    bool only_local = true;
    bool mock_mode = false;
};

Result<std::vector<ArpDevice>> discover_arp_devices(const ArpDiscoveryRequest& request);

} // namespace netsentinel::engine

