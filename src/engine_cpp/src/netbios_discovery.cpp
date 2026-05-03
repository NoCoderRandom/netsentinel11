#include "netsentinel/engine/netbios_discovery.h"
#include "netsentinel/engine/logger.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

namespace {

struct CacheEntry {
    std::chrono::steady_clock::time_point cached_at = {};
    netsentinel::engine::NetBiosDiscovery value{};
};

std::mutex g_cache_mutex;
std::unordered_map<std::string, CacheEntry> g_cache;

void write_u16(std::vector<std::uint8_t>& out, std::size_t pos, std::uint16_t value) {
    out[pos] = static_cast<std::uint8_t>(value >> 8);
    out[pos + 1] = static_cast<std::uint8_t>(value & 0xFF);
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& data, std::size_t pos) {
    return (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
}

std::string trim_netbios_name(std::string value) {
    while (!value.empty() && value.front() == 0) {
        value.erase(value.begin());
    }
    while (!value.empty() && value.back() == ' ') {
        value.pop_back();
    }
    while (!value.empty() && value.back() == 0) {
        value.pop_back();
    }
    while (!value.empty() && value.front() == ' ') {
        value.erase(value.begin());
    }
    return value;
}

std::string encode_netbios_name(std::string_view name) {
    std::string padded(name);
    padded.resize(16, ' ');
    std::string encoded;
    encoded.reserve(32);
    for (std::size_t i = 0; i < 16; ++i) {
        const auto c = static_cast<std::uint8_t>(padded[i]);
        encoded.push_back(static_cast<char>('A' + ((c >> 4) & 0x0F)));
        encoded.push_back(static_cast<char>('A' + (c & 0x0F)));
    }
    return encoded;
}

std::vector<std::uint8_t> build_nbns_status_request() {
    std::string encoded = encode_netbios_name("*");
    std::vector<std::uint8_t> request(12 + 1 + 32 + 1 + 2 + 2, 0);
    write_u16(request, 0, 0xB00B);
    write_u16(request, 2, 0x0010);
    write_u16(request, 4, 0x0001);
    // answers/auth/additional already zero

    std::size_t pos = 12;
    request[pos++] = 0x20;
    for (const char c : encoded) {
        request[pos++] = static_cast<std::uint8_t>(c);
    }
    request[pos++] = 0x00;
    write_u16(request, pos, 0x0021);
    pos += 2;
    write_u16(request, pos, 0x0001);
    pos += 2;
    request.resize(pos);
    return request;
}

std::vector<std::string_view> split_octets(std::string_view ip) {
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= ip.size(); ++i) {
        if (i == ip.size() || ip[i] == '.') {
            parts.push_back(ip.substr(start, i - start));
            start = i + 1;
        }
    }
    return parts;
}

bool is_ipv4_like(std::string_view ip) {
    const auto parts = split_octets(ip);
    if (parts.size() != 4) {
        return false;
    }
    for (const auto part : parts) {
        if (part.empty()) {
            return false;
        }
        if (part.size() > 3) {
            return false;
        }
        int value = 0;
        for (const char c : part) {
            if (c < '0' || c > '9') {
                return false;
            }
            value = value * 10 + (c - '0');
            if (value > 255) {
                return false;
            }
        }
    }
    return true;
}

bool skip_dns_name(const std::vector<std::uint8_t>& data, std::size_t& pos) {
    if (pos >= data.size()) {
        return false;
    }
    while (pos < data.size()) {
        const auto label_len = data[pos];
        if (label_len == 0) {
            ++pos;
            return true;
        }
        if ((label_len & 0xC0) == 0xC0) {
            // Pointer compression: 2-byte jump
            pos += 2;
            return true;
        }
        ++pos;
        if (pos + label_len > data.size()) {
            return false;
        }
        pos += label_len;
    }
    return false;
}

bool parse_nbns_status(
    const std::vector<std::uint8_t>& data,
    std::size_t pos,
    const std::size_t rdlen,
    std::string& out_name,
    std::string& out_workgroup,
    bool& out_resolved
) {
    const auto end = pos + rdlen;
    if (pos >= end || end > data.size()) {
        return false;
    }
    const auto name_count = data[pos];
    ++pos;
    out_resolved = false;

    for (std::size_t i = 0; i < name_count; ++i) {
        if (pos + 18 > end) {
            break;
        }
        std::string raw_name(reinterpret_cast<const char*>(&data[pos]), 15);
        const auto trimmed = trim_netbios_name(raw_name);
        const auto flags = static_cast<std::uint16_t>(data[pos + 17] << 8 | data[pos + 16]);
        const bool is_group = (flags & 0x8000) != 0;

        if (!trimmed.empty()) {
            if (!is_group && out_name.empty() && trimmed != "*") {
                out_name = trimmed;
                out_resolved = true;
            }
            if (is_group && out_workgroup.empty()) {
                out_workgroup = trimmed;
            }
        }

        pos += 18;
    }

    return out_resolved || !out_workgroup.empty();
}

bool cache_lookup(
    const std::string& ip_address,
    const long long cache_ttl_ms,
    netsentinel::engine::NetBiosDiscovery& out
) {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    const auto it = g_cache.find(ip_address);
    if (it == g_cache.end()) {
        return false;
    }
    if (!it->second.value.resolved && cache_ttl_ms <= 0) {
        return false;
    }
    const auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - it->second.cached_at
    ).count();
    if (cache_ttl_ms > 0 && age_ms > cache_ttl_ms) {
        g_cache.erase(it);
        return false;
    }
    out = it->second.value;
    return true;
}

void cache_store(const std::string& ip_address, const netsentinel::engine::NetBiosDiscovery& value) {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    g_cache[ip_address] = CacheEntry{
        .cached_at = std::chrono::steady_clock::now(),
        .value = value
    };
}

netsentinel::engine::NetBiosDiscovery build_mock_result(const std::string& ip_address) {
    std::string safe_ip = ip_address;
    std::replace(safe_ip.begin(), safe_ip.end(), '.', '-');
    return {
        .resolved = true,
        .timed_out = false,
        .device_name = "NB-" + safe_ip,
        .workgroup = "WORKGROUP",
        .source = "mock-netbios",
        .confidence = 72,
        .details = "deterministic mock netbios table response"
    };
};

} // namespace

namespace netsentinel::engine {

Result<NetBiosDiscovery> resolve_netbios_name_for_ip(
    const std::string& ip_address,
    const NetBiosDiscoveryConfig& config
) {
    Logger::instance().info("netbios", "starting netbios name discovery");

    if (!config.mock_mode && !is_ipv4_like(ip_address)) {
        Logger::instance().warning("netbios", "invalid ip passed to netbios resolver");
        return Result<NetBiosDiscovery>::fail(
            ErrorCode::invalid_input,
            "invalid netbios target",
            "ip_address must be a valid IPv4 dotted decimal value"
        );
    }
    if (config.mock_mode) {
        const auto out = build_mock_result(ip_address);
        if (config.cache_enabled) {
            cache_store(ip_address, out);
        }
        Logger::instance().info("netbios", "netbios mock result ready");
        return Result<NetBiosDiscovery>::ok(std::move(out));
    }

    if (config.cache_enabled) {
        NetBiosDiscovery cached;
        if (cache_lookup(ip_address, config.cache_ttl_ms, cached)) {
            Logger::instance().info("netbios", "netbios cache hit");
            return Result<NetBiosDiscovery>::ok(std::move(cached));
        }
    }

    WSADATA wsa_data{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        const int ws_error = WSAGetLastError();
        return Result<NetBiosDiscovery>::fail(
            ErrorCode::internal,
            "netbios name discovery failed",
            std::string("WSAStartup failed with error ") + std::to_string(ws_error)
        );
    }

    SOCKET socket_handle = INVALID_SOCKET;
    NetBiosDiscovery out;
    do {
        socket_handle = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_handle == INVALID_SOCKET) {
            const int socket_error = WSAGetLastError();
            out.resolved = false;
            out.timed_out = false;
            out.source = "udp-netbios";
            out.confidence = 0;
            out.details = std::string("socket create failed: ") + std::to_string(socket_error);
            break;
        }

        const int timeout = static_cast<int>(config.timeout_ms <= 0 ? 500 : config.timeout_ms);
        ::setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        u_long non_blocking = 0;
        ::ioctlsocket(socket_handle, FIONBIO, &non_blocking);

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(137);
        if (::inet_pton(AF_INET, ip_address.c_str(), &address.sin_addr) != 1) {
            out.resolved = false;
            out.timed_out = false;
            out.source = "udp-netbios";
            out.confidence = 0;
            out.details = "invalid ip string for network conversion";
            break;
        }

        const auto request = build_nbns_status_request();
        if (const int sent = ::sendto(
            socket_handle,
            reinterpret_cast<const char*>(request.data()),
            static_cast<int>(request.size()),
            0,
            reinterpret_cast<sockaddr*>(&address),
            static_cast<int>(sizeof(address))
        ); sent != static_cast<int>(request.size())) {
            out.resolved = false;
            out.timed_out = false;
            out.source = "udp-netbios";
            out.confidence = 0;
            out.details = std::string("send failed with error ") + std::to_string(WSAGetLastError());
            break;
        }

        sockaddr_in from{};
        int from_len = sizeof(from);
        std::vector<std::uint8_t> response(1024, 0);
        const int bytes_received = ::recvfrom(
            socket_handle,
            reinterpret_cast<char*>(response.data()),
            static_cast<int>(response.size()),
            0,
            reinterpret_cast<sockaddr*>(&from),
            &from_len
        );
        if (bytes_received <= 0) {
            const int recv_error = WSAGetLastError();
            out.resolved = false;
            out.timed_out = (recv_error == WSAETIMEDOUT || recv_error == WSAEWOULDBLOCK);
            out.source = "udp-netbios";
            out.confidence = 0;
            if (out.timed_out) {
                out.details = "netbios request timed out";
            } else {
                out.details = std::string("udp recv failed with error ") + std::to_string(recv_error);
            }
            break;
        }
        response.resize(static_cast<std::size_t>(bytes_received));
        if (response.size() < 12) {
            out.resolved = false;
            out.timed_out = false;
            out.source = "udp-netbios";
            out.details = "malformed netbios response";
            out.confidence = 0;
            break;
        }

        const auto answers = read_u16(response, 6);
        const auto questions = read_u16(response, 4);
        std::size_t pos = 12;
        for (std::size_t qi = 0; qi < questions; ++qi) {
            if (!skip_dns_name(response, pos)) {
                out.resolved = false;
                out.timed_out = false;
                out.source = "udp-netbios";
                out.details = "malformed netbios question block";
                out.confidence = 0;
                break;
            }
            if (pos + 4 > response.size()) {
                out.resolved = false;
                out.timed_out = false;
                out.source = "udp-netbios";
                out.details = "malformed netbios question block";
                out.confidence = 0;
                break;
            }
            pos += 4;
        }
        if (!out.details.empty()) {
            break;
        }

        bool resolved = false;
        std::string device_name;
        std::string workgroup;
        for (std::size_t ai = 0; ai < answers && pos < response.size(); ++ai) {
            if (pos + 12 > response.size()) {
                out.resolved = false;
                out.details = "malformed netbios answer header";
                out.confidence = 0;
                break;
            }
            const auto rr_type = read_u16(response, pos + 2);
            const auto rr_len = read_u16(response, pos + 10);
            pos += 12;
            if (pos + rr_len > response.size()) {
                out.resolved = false;
                out.timed_out = false;
                out.source = "udp-netbios";
                out.confidence = 0;
                out.details = "malformed netbios answer length";
                break;
            }
            if (rr_type == 0x0021) {
                std::string candidate_device;
                std::string candidate_workgroup;
                if (parse_nbns_status(response, pos, rr_len, candidate_device, candidate_workgroup, resolved)) {
                    if (!candidate_device.empty()) {
                        device_name = candidate_device;
                    }
                    if (!candidate_workgroup.empty()) {
                        workgroup = candidate_workgroup;
                    }
                }
            }
            pos += rr_len;
        }

        if (out.details.empty()) {
            out.resolved = !device_name.empty();
            out.timed_out = false;
            out.device_name = device_name;
            out.workgroup = workgroup;
            out.source = "udp-netbios";
            out.confidence = out.resolved ? 78 : 24;
            if (out.resolved) {
                if (!workgroup.empty()) {
                    out.details = "resolved via nbns status response";
                } else {
                    out.details = "resolved via nbns status response without workgroup name";
                }
            } else {
                out.details = "no nbns netbios names returned";
            }
        }
    } while (false);

    closesocket(socket_handle);
    WSACleanup();

    if (config.cache_enabled) {
        cache_store(ip_address, out);
    }
    if (!out.resolved && out.source == "udp-netbios" && !out.details.empty()) {
        if (out.timed_out) {
            return Result<NetBiosDiscovery>::fail(ErrorCode::timeout, "netbios name discovery timed out", out.details);
        }
        if (out.device_name.empty()) {
            return Result<NetBiosDiscovery>::fail(ErrorCode::internal, "netbios name discovery failed", out.details);
        }
        return Result<NetBiosDiscovery>::ok(std::move(out));
    }
    if (out.source == "udp-netbios" && out.device_name.empty() && out.workgroup.empty()) {
        return Result<NetBiosDiscovery>::fail(ErrorCode::internal, "netbios name discovery unavailable", out.details);
    }
    return Result<NetBiosDiscovery>::ok(std::move(out));
}

Result<std::size_t> clear_netbios_discovery_cache() {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    const auto count = g_cache.size();
    g_cache.clear();
    return Result<std::size_t>::ok(count);
}

} // namespace netsentinel::engine
