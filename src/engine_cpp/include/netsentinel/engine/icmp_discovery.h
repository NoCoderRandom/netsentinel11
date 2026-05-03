#pragma once

#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct IcmpPingHost {
    std::string ip_address;
    bool ping_ok = false;
    long long ping_latency_ms = 0;
    bool from_arp_cache = false;
    std::string adapter_id;
};

Result<std::vector<IcmpPingHost>> discover_icmp_hosts(
    const std::string& cidr_or_range,
    bool mock_mode,
    std::size_t max_qps = 16,
    bool request_cancel = false
);

} // namespace netsentinel::engine
