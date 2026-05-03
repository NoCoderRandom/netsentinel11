#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct AdapterInventoryEntry {
    std::string adapter_id;
    std::string interface_name;
    std::optional<std::string> friendly_name;
    std::optional<std::string> mac_address;

    std::vector<std::string> ipv4_addresses;
    std::vector<std::string> ipv6_addresses;

    std::optional<std::string> gateway;
    bool dhcp_enabled = false;
    std::int64_t link_speed_mbps = 0;
    bool up = false;

    std::vector<std::string> dns_servers;
};

Result<std::vector<AdapterInventoryEntry>> list_network_adapters(bool mock_mode = false);

} // namespace netsentinel::engine

