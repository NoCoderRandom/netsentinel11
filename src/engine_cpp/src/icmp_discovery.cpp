#include "netsentinel/engine/icmp_discovery.h"
#include "netsentinel/engine/arp_discovery.h"
#include "netsentinel/engine/logger.h"
#include "netsentinel/engine/netcore_boundary.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <sstream>
#include <thread>

namespace netsentinel::engine {

namespace {

bool parse_ipv4(const std::string& value, std::array<unsigned int, 4>& octets) {
    char dot1 = 0;
    char dot2 = 0;
    char dot3 = 0;
    std::stringstream ss{value};
    ss >> octets[0] >> dot1 >> octets[1] >> dot2 >> octets[2] >> dot3 >> octets[3];
    if (!ss || dot1 != '.' || dot2 != '.' || dot3 != '.') {
        return false;
    }
    return std::all_of(octets.begin(), octets.end(), [](unsigned int octet) {
        return octet <= 255;
    });
}

std::uint32_t ipv4_to_u32(const std::array<unsigned int, 4>& octets) {
    return (static_cast<std::uint32_t>(octets[0]) << 24) |
        (static_cast<std::uint32_t>(octets[1]) << 16) |
        (static_cast<std::uint32_t>(octets[2]) << 8) |
        static_cast<std::uint32_t>(octets[3]);
}

std::string u32_to_ipv4(std::uint32_t value) {
    std::ostringstream out;
    out << ((value >> 24) & 0xff) << "."
        << ((value >> 16) & 0xff) << "."
        << ((value >> 8) & 0xff) << "."
        << (value & 0xff);
    return out.str();
}

std::vector<std::string> expand_live_cidr_hosts(const std::string& cidr_or_range, std::size_t max_hosts) {
    const auto slash = cidr_or_range.find('/');
    const std::string address = slash == std::string::npos ? cidr_or_range : cidr_or_range.substr(0, slash);
    int prefix = 32;
    if (slash != std::string::npos) {
        try {
            prefix = std::stoi(cidr_or_range.substr(slash + 1));
        } catch (...) {
            return {};
        }
    }
    if (prefix < 16 || prefix > 32) {
        return {};
    }

    std::array<unsigned int, 4> octets{};
    if (!parse_ipv4(address, octets)) {
        return {};
    }

    const std::uint32_t ip = ipv4_to_u32(octets);
    const std::uint32_t mask = prefix == 0 ? 0u : (0xffffffffu << (32 - prefix));
    const std::uint32_t network = ip & mask;
    const std::uint32_t host_count = prefix == 32 ? 1u : (1u << (32 - prefix));
    if (host_count > max_hosts + 2) {
        return {};
    }

    std::vector<std::string> hosts;
    const std::uint32_t first = host_count <= 2 ? network : network + 1;
    const std::uint32_t last = host_count <= 2 ? network + host_count - 1 : network + host_count - 2;
    for (std::uint32_t current = first; current <= last && hosts.size() < max_hosts; ++current) {
        hosts.push_back(u32_to_ipv4(current));
        if (current == 0xffffffffu) {
            break;
        }
    }
    return hosts;
}

bool has_host(const std::vector<IcmpPingHost>& hosts, const std::string& ip) {
    return std::any_of(hosts.begin(), hosts.end(), [&ip](const IcmpPingHost& host) {
        return host.ip_address == ip;
    });
}

} // namespace

Result<std::vector<IcmpPingHost>> discover_icmp_hosts(
    const std::string& cidr_or_range,
    bool mock_mode,
    std::size_t max_qps,
    bool request_cancel
) {
    Logger::instance().info("icmp_discovery", "starting icmp discovery");

    ArpDiscoveryRequest request{
        .cidr_or_range = cidr_or_range.empty() ? "192.168.1.0/24" : cidr_or_range,
        .max_host_count = 1024,
        .only_local = true,
        .mock_mode = mock_mode
    };
    const auto devices = discover_arp_devices(request);
    if (!devices) {
        return Result<std::vector<IcmpPingHost>>::fail(
            devices.error().code,
            "icmp discovery blocked",
            "arp prerequisite failed before ping sweep"
        );
    }

    std::vector<IcmpPingHost> candidates;
    candidates.reserve(devices.value().size() + 256);
    for (const auto& device : devices.value()) {
        candidates.push_back(IcmpPingHost{
            .ip_address = device.ip_address,
            .ping_ok = false,
            .ping_latency_ms = 0,
            .from_arp_cache = true,
            .adapter_id = device.adapter_id
        });
    }

    if (!mock_mode) {
        for (const auto& ip : expand_live_cidr_hosts(request.cidr_or_range, 1024)) {
            if (!has_host(candidates, ip)) {
                candidates.push_back(IcmpPingHost{
                    .ip_address = ip,
                    .ping_ok = false,
                    .ping_latency_ms = 0,
                    .from_arp_cache = false,
                    .adapter_id = "icmp-cidr-sweep"
                });
            }
        }
    }

    std::vector<IcmpPingHost> out(candidates.size());
    const std::size_t effective_qps = std::max<std::size_t>(1, max_qps);
    const std::size_t chunk_size = std::min<std::size_t>(32, effective_qps);
    const ProbeBoundaryConfig config{
        .connect_timeout_ms = 250,
        .total_timeout_ms = 500,
        .max_qps = static_cast<unsigned int>(effective_qps)
    };

    for (std::size_t chunk = 0; chunk < candidates.size(); chunk += chunk_size) {
        const std::size_t chunk_end = std::min(chunk + chunk_size, candidates.size());
        std::vector<std::future<std::pair<std::size_t, IcmpPingHost>>> futures;
        futures.reserve(chunk_end - chunk);
        for (std::size_t i = chunk; i < chunk_end; ++i) {
            futures.push_back(std::async(std::launch::async, [&, i]() {
                auto host = candidates[i];
                const auto ping = mock_mode
                    ? run_stub_probe(host.ip_address, config)
                    : run_probe(host.ip_address, config, request_cancel, false);
                if (ping) {
                    host.ping_ok = ping.value().success;
                    host.ping_latency_ms = ping.value().elapsed_ms;
                } else if (ping.error().code == ErrorCode::timeout) {
                    host.ping_ok = false;
                    host.ping_latency_ms = 0;
                }
                return std::make_pair(i, std::move(host));
            }));
        }
        for (auto& future : futures) {
            auto [index, host] = future.get();
            out[index] = std::move(host);
        }
        if (!mock_mode && chunk_end < candidates.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }

    Logger::instance().info("icmp_discovery", "completed icmp discovery");
    return Result<std::vector<IcmpPingHost>>::ok(std::move(out));
}

} // namespace netsentinel::engine
