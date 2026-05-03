#include "netsentinel/engine/adapter_inventory.h"
#include "netsentinel/engine/logger.h"

#include "netsentinel/netcore/adapter_inventory.h"

#include <vector>

namespace {

std::vector<std::string> copy_address_list(char** values, int count) {
    std::vector<std::string> out;
    if (!values || count <= 0) {
        return out;
    }
    out.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        if (values[i] && values[i][0] != '\0') {
            out.push_back(values[i]);
        }
    }
    return out;
}

std::optional<std::string> clone_optional(const char* value) {
    if (!value || value[0] == '\0') {
        return std::nullopt;
    }
    return std::string(value);
}

std::vector<netsentinel::engine::AdapterInventoryEntry> mock_adapters() {
    return {
        netsentinel::engine::AdapterInventoryEntry{
            .adapter_id = "mock-ethernet-001",
            .interface_name = "Ethernet",
            .friendly_name = "Mock Ethernet Adapter",
            .mac_address = "AA:BB:CC:00:11:22",
            .ipv4_addresses = {"192.168.1.10"},
            .ipv6_addresses = {"fe80::1"},
            .gateway = "192.168.1.1",
            .dhcp_enabled = true,
            .link_speed_mbps = 1000,
            .up = true,
            .dns_servers = {"192.168.1.1", "1.1.1.1"}
        },
        netsentinel::engine::AdapterInventoryEntry{
            .adapter_id = "mock-wifi-001",
            .interface_name = "Wi-Fi",
            .friendly_name = "Mock Wi-Fi Adapter",
            .mac_address = "AA:BB:CC:33:44:55",
            .ipv4_addresses = {"10.0.0.2"},
            .ipv6_addresses = {"fe80::2"},
            .gateway = "10.0.0.1",
            .dhcp_enabled = true,
            .link_speed_mbps = 300,
            .up = false,
            .dns_servers = {"10.0.0.1", "9.9.9.9"}
        }
    };
}

} // namespace

namespace netsentinel::engine {

Result<std::vector<AdapterInventoryEntry>> list_network_adapters(bool mock_mode) {
    Logger::instance().info("adapter_inventory", "listing adapters");
    if (mock_mode) {
        Logger::instance().info("adapter_inventory", "using mock inventory (test mode)");
        return Result<std::vector<AdapterInventoryEntry>>::ok(mock_adapters());
    }

    ns_adapter_info* adapters = nullptr;
    int count = 0;
    const int result = ns_list_network_adapters(&adapters, &count);
    if (result != 0) {
        Logger::instance().warning("adapter_inventory", "ns_list_network_adapters failed");
        return Result<std::vector<AdapterInventoryEntry>>::fail(
            ErrorCode::internal,
            "native adapter enumeration failed",
            "ns_list_network_adapters returned a non-zero status"
        );
    }

    std::vector<AdapterInventoryEntry> out;
    out.reserve(count > 0 ? static_cast<std::size_t>(count) : 0U);
    for (int i = 0; i < count; ++i) {
        AdapterInventoryEntry entry;
        entry.adapter_id = adapters[i].interface_id ? adapters[i].interface_id : "";
        entry.interface_name = (adapters[i].friendly_name && adapters[i].friendly_name[0] != '\0') ?
            adapters[i].friendly_name : (adapters[i].interface_id ? adapters[i].interface_id : "(unknown)");
        entry.friendly_name = clone_optional(adapters[i].friendly_name);
        entry.mac_address = clone_optional(adapters[i].mac_address);
        entry.ipv4_addresses = copy_address_list(adapters[i].ipv4_addresses, adapters[i].ipv4_count);
        entry.ipv6_addresses = copy_address_list(adapters[i].ipv6_addresses, adapters[i].ipv6_count);
        entry.gateway = clone_optional(adapters[i].gateway);
        entry.dhcp_enabled = adapters[i].dhcp_enabled != 0;
        entry.link_speed_mbps = adapters[i].link_speed_mbps;
        entry.up = adapters[i].up != 0;
        entry.dns_servers = copy_address_list(adapters[i].dns_servers, adapters[i].dns_servers_count);
        out.push_back(std::move(entry));
    }
    ns_free_network_adapters(adapters, count);

    return Result<std::vector<AdapterInventoryEntry>>::ok(std::move(out));
}

} // namespace netsentinel::engine
