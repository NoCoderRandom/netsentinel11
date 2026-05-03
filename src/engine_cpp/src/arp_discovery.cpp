#include "netsentinel/engine/arp_discovery.h"
#include "netsentinel/engine/logger.h"

#include "netsentinel/netcore/arp_discovery.h"

#include <utility>

namespace netsentinel::engine {

Result<std::vector<ArpDevice>> discover_arp_devices(const ArpDiscoveryRequest& request) {
    Logger::instance().info("arp_discovery", "starting arp discovery");
    if (request.max_host_count == 0) {
        return Result<std::vector<ArpDevice>>::fail(
            ErrorCode::invalid_input,
            "invalid arp request",
            "max_host_count must be greater than zero"
        );
    }
    if (request.cidr_or_range.empty()) {
        return Result<std::vector<ArpDevice>>::fail(
            ErrorCode::invalid_input,
            "invalid cidr input",
            "scan scope cannot be empty"
        );
    }
    for (char ch : request.cidr_or_range) {
        if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '/' || ch == '-') {
            continue;
        }
        return Result<std::vector<ArpDevice>>::fail(
            ErrorCode::invalid_input,
            "invalid cidr input",
            "scan scope must be a CIDR-like range"
        );
    }

    if (request.mock_mode) {
        std::vector<ArpDevice> mock_devices;
        mock_devices.push_back({
            .ip_address = "192.168.1.101",
            .mac_address = "AA:BB:CC:11:22:33",
            .latency_ms = 5,
            .adapter_id = "mock-ethernet-001"
        });
        mock_devices.push_back({
            .ip_address = "192.168.1.102",
            .mac_address = "AA:BB:CC:44:55:66",
            .latency_ms = 15,
            .adapter_id = "mock-ethernet-001"
        });
        Logger::instance().info("arp_discovery", "completed mock arp discovery");
        return Result<std::vector<ArpDevice>>::ok(std::move(mock_devices));
    }

    int out_count = 0;
    ns_arp_discovery_result* raw = nullptr;
    const int status = ns_arp_discover(
        request.cidr_or_range.c_str(),
        static_cast<int>(request.max_host_count),
        request.only_local ? 1 : 0,
        &raw,
        &out_count
    );
    if (status != 0) {
        return Result<std::vector<ArpDevice>>::fail(
            ErrorCode::internal,
            "arp discovery failed",
            "low-level arp discovery returned a failure"
        );
    }

    std::vector<ArpDevice> out;
    out.reserve(out_count > 0 ? static_cast<std::size_t>(out_count) : 0U);
    for (int i = 0; i < out_count; ++i) {
        ArpDevice device;
        device.ip_address = raw[i].ip_address ? raw[i].ip_address : "";
        device.mac_address = raw[i].mac_address ? raw[i].mac_address : "";
        device.latency_ms = raw[i].latency_ms;
        device.adapter_id = raw[i].adapter_id ? raw[i].adapter_id : "";
        out.push_back(std::move(device));
    }
    ns_free_arp_discovery(raw, out_count);

    Logger::instance().info("arp_discovery", "completed arp discovery");
    return Result<std::vector<ArpDevice>>::ok(std::move(out));
}

} // namespace netsentinel::engine
