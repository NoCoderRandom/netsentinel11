#include "netsentinel/engine/logger.h"
#include "netsentinel/engine/mdns_discovery.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cctype>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

namespace {

using netsentinel::engine::MdnsService;

struct ServiceDescriptor {
    const char* type;
    const char* device_type_hint;
};

const std::array<ServiceDescriptor, 10> k_common_mdns_services{{
    {"_ipp._tcp.local", "printer"},
    {"_http._tcp.local", "web"},
    {"_https._tcp.local", "secure-web"},
    {"_airplay._tcp.local", "airplay"},
    {"_workstation._tcp.local", "smb"},
    {"_smb._tcp.local", "smb"},
    {"_googlecast._tcp.local", "casting"},
    {"_spotify-connect._tcp.local", "media"},
    {"_homekit._tcp.local", "homekit"},
    {"_services._dns-sd._udp.local", "mdns-index"}
}};

struct ParsedService {
    std::string service_name;
    std::string instance;
    std::string device_type_hint;
    std::string target;
    int port = 0;
    long long ttl_ms = 0;
    bool has_srv = false;
};

void write_u16(std::vector<std::uint8_t>& out, std::size_t offset, std::uint16_t value) {
    out[offset] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>(value & 0xFF);
}

void write_u32(std::vector<std::uint8_t>& out, std::size_t offset, std::uint32_t value) {
    out[offset] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[offset + 2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[offset + 3] = static_cast<std::uint8_t>(value & 0xFF);
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& data, std::size_t pos) {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[pos] << 8) | data[pos + 1]);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& data, std::size_t pos) {
    return static_cast<std::uint32_t>(
        (static_cast<std::uint32_t>(data[pos]) << 24)
        | (static_cast<std::uint32_t>(data[pos + 1]) << 16)
        | (static_cast<std::uint32_t>(data[pos + 2]) << 8)
        | static_cast<std::uint32_t>(data[pos + 3])
    );
}

std::string service_hint_from_type(std::string_view service_type) {
    for (const auto& service : k_common_mdns_services) {
        if (service.type == service_type) {
            return service.device_type_hint;
        }
    }
    return "network-service";
}

void encode_dns_name(const std::string_view name, std::vector<std::uint8_t>& packet) {
    std::size_t start = 0;
    while (start < name.size()) {
        const auto next = name.find('.', start);
        const auto len = (next == std::string_view::npos)
            ? name.size() - start
            : next - start;
        packet.push_back(static_cast<std::uint8_t>(len));
        for (std::size_t i = 0; i < len; ++i) {
            packet.push_back(static_cast<std::uint8_t>(name[start + i]));
        }
        if (next == std::string_view::npos) {
            break;
        }
        start = next + 1;
    }
    packet.push_back(0);
}

bool decode_dns_name(
    const std::vector<std::uint8_t>& packet,
    std::size_t& pos,
    std::string& out,
    int jumps = 0
) {
    if (jumps > 12) {
        return false;
    }
    if (pos >= packet.size()) {
        return false;
    }
    out.clear();
    bool advanced = false;
    std::size_t cursor = pos;
    std::size_t steps = 0;
    while (cursor < packet.size()) {
        const std::uint8_t label_len = packet[cursor];
        if (label_len == 0) {
            ++cursor;
            if (!advanced) {
                pos = cursor;
            }
            return true;
        }
        if ((label_len & 0xC0) == 0xC0) {
            if (cursor + 1 >= packet.size()) {
                return false;
            }
            const std::uint16_t pointer = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(label_len & 0x3F) << 8) | packet[cursor + 1]
            );
            cursor = pointer;
            if (!advanced) {
                pos = cursor + 2;
                advanced = true;
            }
            if (++jumps > 12) {
                return false;
            }
            continue;
        }
        if (cursor + 1 + label_len > packet.size()) {
            return false;
        }
        if (steps > 0) {
            out.push_back('.');
        }
        for (std::size_t i = 0; i < label_len; ++i) {
            out.push_back(static_cast<char>(packet[cursor + 1 + i]));
        }
        cursor += 1 + label_len;
        if (!advanced) {
            pos = cursor;
        }
        ++steps;
    }
    return false;
}

bool is_suffix_case_insensitive(std::string_view text, std::string_view suffix) {
    if (suffix.size() > text.size()) {
        return false;
    }
    const auto offset = text.size() - suffix.size();
    for (std::size_t i = 0; i < suffix.size(); ++i) {
        const char left = static_cast<char>(std::tolower(static_cast<unsigned char>(text[offset + i])));
        const char right = static_cast<char>(std::tolower(static_cast<unsigned char>(suffix[i])));
        if (left != right) {
            return false;
        }
    }
    return true;
}

bool strip_known_service_suffix(std::string_view full_name, std::string_view service_type, std::string& instance_out) {
    const auto needle = std::string(service_type);
    if (!is_suffix_case_insensitive(full_name, needle)) {
        return false;
    }
    const std::size_t suffix_begin = full_name.size() - needle.size();
    if (suffix_begin == 0) {
        return false;
    }
    const bool trailing_dot = full_name[suffix_begin - 1] == '.';
    const std::size_t instance_len = trailing_dot ? (suffix_begin - 1) : suffix_begin;
    if (instance_len == 0) {
        return false;
    }
    instance_out.assign(full_name.substr(0, instance_len));
    return true;
}

std::string make_result_key(std::string_view service_type, std::string_view instance) {
    return std::string(service_type) + "|" + std::string(instance);
}

std::vector<std::uint8_t> build_ptr_query(std::string_view service_type, std::uint16_t txid) {
    std::vector<std::uint8_t> packet(12, 0);
    write_u16(packet, 0, txid);
    write_u16(packet, 2, 0x0000);
    write_u16(packet, 4, 0x0001);
    write_u16(packet, 6, 0);
    write_u16(packet, 8, 0);
    write_u16(packet, 10, 0);
    encode_dns_name(service_type, packet);
    packet.resize(packet.size() + 4);
    write_u16(packet, packet.size() - 4, 12);
    write_u16(packet, packet.size() - 2, 1);
    return packet;
}

void set_record_if_better(std::unordered_map<std::string, ParsedService>& map, const ParsedService& candidate) {
    const auto key = make_result_key(candidate.service_name, candidate.instance);
    const auto it = map.find(key);
    if (it == map.end()) {
        map[key] = candidate;
        return;
    }
    auto& existing = it->second;
    if (candidate.ttl_ms > existing.ttl_ms) {
        existing.ttl_ms = candidate.ttl_ms;
    }
    if (!candidate.target.empty() && existing.target.empty()) {
        existing.target = candidate.target;
    }
    if (candidate.port > 0) {
        existing.port = candidate.port;
    }
    if (candidate.has_srv) {
        existing.has_srv = true;
    }
}

void parse_rr_srv_payload(
    const std::vector<std::uint8_t>& response,
    std::size_t rdata_pos,
    std::size_t rdata_len,
    ParsedService& out
) {
    if (rdata_len < 6 || rdata_pos + rdata_len > response.size()) {
        return;
    }
    const std::size_t port_pos = rdata_pos + 4;
    if (port_pos + 2 > response.size()) {
        return;
    }
    const std::size_t target_pos = rdata_pos + 6;
    if (target_pos >= response.size()) {
        return;
    }
    const std::string decoded_port_target = [&, target_pos]() {
        std::size_t cursor = target_pos;
        std::string value;
        decode_dns_name(response, cursor, value);
        return value;
    }();
    if (!decoded_port_target.empty()) {
        out.target = decoded_port_target;
    }
    out.port = static_cast<int>(read_u16(response, port_pos));
    out.has_srv = true;
}

void parse_record_block(
    const std::vector<std::uint8_t>& response,
    std::size_t& cursor,
    const std::string& service_name,
    std::unordered_map<std::string, ParsedService>& out
) {
    if (cursor + 10 >= response.size()) {
        return;
    }
    std::size_t rr_name_pos = cursor;
    std::string rr_name;
    if (!decode_dns_name(response, rr_name_pos, rr_name)) {
        return;
    }
    cursor = rr_name_pos;

    const std::size_t fixed = cursor;
    if (fixed + 10 > response.size()) {
        return;
    }
    const std::uint16_t rr_type = read_u16(response, fixed);
    const std::uint16_t rr_class = read_u16(response, fixed + 2);
    const std::uint32_t rr_ttl = read_u32(response, fixed + 4);
    const std::uint16_t rdlen = read_u16(response, fixed + 8);
    const std::size_t rdstart = fixed + 10;
    if (rdstart + rdlen > response.size()) {
        return;
    }
    cursor = rdstart + rdlen;

    (void)rr_class;
    if (rr_type == 12) {
        std::size_t rdata_cursor = rdstart;
        std::string instance_or_ptr;
        if (!decode_dns_name(response, rdata_cursor, instance_or_ptr)) {
            return;
        }
        std::string instance_name;
        if (!strip_known_service_suffix(instance_or_ptr, service_name, instance_name)) {
            return;
        }
        ParsedService item;
        item.service_name = service_name;
        item.instance = instance_name;
        item.device_type_hint = service_hint_from_type(service_name);
        item.ttl_ms = static_cast<long long>(rr_ttl) * 1000LL;
        item.target = "";
        item.port = 0;
        set_record_if_better(out, item);
        return;
    }

    if (rr_type == 33) {
        std::string instance_name;
        if (!strip_known_service_suffix(rr_name, service_name, instance_name)) {
            return;
        }
        ParsedService item;
        item.service_name = service_name;
        item.instance = instance_name;
        item.device_type_hint = service_hint_from_type(service_name);
        item.ttl_ms = static_cast<long long>(rr_ttl) * 1000LL;
        parse_rr_srv_payload(response, rdstart, rdlen, item);
        if (!item.target.empty()) {
            set_record_if_better(out, item);
        }
        return;
    }
}

std::vector<MdnsService> discover_from_packet(
    const std::string& service_name,
    const std::vector<std::uint8_t>& response,
    std::unordered_map<std::string, ParsedService>& results
) {
    std::vector<MdnsService> out;
    if (response.size() < 12) {
        return out;
    }
    const std::uint16_t qdcount = read_u16(response, 4);
    const std::uint16_t ancount = read_u16(response, 6);
    const std::uint16_t nscount = read_u16(response, 8);
    const std::uint16_t arcount = read_u16(response, 10);
    std::size_t cursor = 12;
    for (std::size_t q = 0; q < qdcount; ++q) {
        std::string skip;
        decode_dns_name(response, cursor, skip);
        if (cursor + 4 > response.size()) {
            return out;
        }
        cursor += 4;
    }

    const auto to_ints = [&](std::uint16_t total_records) {
        for (std::uint16_t i = 0; i < total_records; ++i) {
            parse_record_block(response, cursor, service_name, results);
            if (cursor >= response.size()) {
                break;
            }
        }
    };
    to_ints(ancount);
    to_ints(nscount);
    to_ints(arcount);

    out.reserve(results.size());
    for (const auto& item : results) {
        (void)item;
    }
    return out;
}

std::vector<MdnsService> collect_finalized_services(const std::unordered_map<std::string, ParsedService>& parsed, std::size_t max_services) {
    std::vector<MdnsService> out;
    out.reserve(parsed.size());
    for (const auto& [key, value] : parsed) {
        (void)key;
        MdnsService service{
            value.service_name,
            value.instance.empty() ? "unknown-instance" : value.instance,
            value.device_type_hint,
            value.target,
            value.port,
            value.ttl_ms,
            "mdns-udp",
            73,
            value.has_srv ? "PTR/SRV parsed" : "PTR-only record"
        };
        out.push_back(std::move(service));
        if (out.size() >= max_services) {
            break;
        }
    }
    std::sort(out.begin(), out.end(), [](const MdnsService& lhs, const MdnsService& rhs) {
        if (lhs.service_name != rhs.service_name) {
            return lhs.service_name < rhs.service_name;
        }
        return lhs.service_instance < rhs.service_instance;
    });
    return out;
}

std::vector<MdnsService> build_mock_services(std::size_t max_services) {
    std::vector<MdnsService> services;
    services.reserve(std::min<std::size_t>(max_services, k_common_mdns_services.size()));
    for (std::size_t i = 0; i < k_common_mdns_services.size() && services.size() < max_services; ++i) {
        services.push_back({
            k_common_mdns_services[i].type,
            std::string("Mock ") + std::to_string(i + 1) + " " + k_common_mdns_services[i].device_type_hint,
            k_common_mdns_services[i].device_type_hint,
            "mock-device-" + std::to_string(i + 1) + ".local",
            80 + static_cast<int>(i),
            120 * 1000,
            "mock-mdns",
            74,
            "deterministic mock mDNS service"
        });
    }
    return services;
}

bool receive_with_timeout(
    SOCKET socket_handle,
    std::vector<std::uint8_t>& buffer,
    int timeout_ms,
    std::size_t bytes_available_limit
) {
    const long long start_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    fd_set read_fds;
    while (true) {
        FD_ZERO(&read_fds);
        FD_SET(socket_handle, &read_fds);
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count();
        const long long remaining = start_ms + static_cast<long long>(timeout_ms) - now_ms;
        if (remaining <= 0) {
            return false;
        }
        timeval tv{};
        tv.tv_sec = static_cast<long>(remaining / 1000);
        tv.tv_usec = static_cast<long>((remaining % 1000) * 1000);
        const int selected = select(0, &read_fds, NULL, NULL, &tv);
        if (selected <= 0) {
            return false;
        }
        sockaddr_in sender{};
        int sender_len = sizeof(sender);
        const int received = recvfrom(
            socket_handle,
            reinterpret_cast<char*>(buffer.data()),
            static_cast<int>(bytes_available_limit),
            0,
            reinterpret_cast<sockaddr*>(&sender),
            &sender_len
        );
        if (received > 0) {
            buffer.resize(static_cast<std::size_t>(received));
            return true;
        }
    }
}

bool apply_service_response(
    std::unordered_map<std::string, ParsedService>& parsed,
    const std::string& service_name,
    const std::vector<std::uint8_t>& response,
    std::size_t max_services
) {
    const auto added = discover_from_packet(service_name, response, parsed);
    if (parsed.size() >= max_services) {
        return true;
    }
    (void)added;
    return parsed.size() >= max_services;
}

bool open_socket(SOCKET& socket_handle, long long timeout_ms) {
    socket_handle = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET) {
        return false;
    }

    u_long nonblocking = 0;
    if (::ioctlsocket(socket_handle, FIONBIO, &nonblocking) != 0) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
        return false;
    }

    const int recv_timeout = static_cast<int>(timeout_ms);
    if (::setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recv_timeout), sizeof(recv_timeout)) != 0) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
        return false;
    }
    const int send_timeout = recv_timeout;
    if (::setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&send_timeout), sizeof(send_timeout)) != 0) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
        return false;
    }

    int ttl = 255;
    if (::setsockopt(socket_handle, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&ttl), sizeof(ttl)) != 0) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
        return false;
    }
    return true;
}

void close_socket_if_open(SOCKET& socket_handle) {
    if (socket_handle != INVALID_SOCKET) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
    }
}

} // namespace

namespace netsentinel::engine {

Result<std::vector<MdnsService>> discover_mdns_services(const MdnsDiscoveryConfig& config) {
    Logger::instance().info("mdns", "starting mdns discovery");
    if (config.max_services == 0) {
        return Result<std::vector<MdnsService>>::fail(
            ErrorCode::invalid_input,
            "invalid mdns request",
            "max_services must be greater than zero"
        );
    }
    if (config.query_timeout_ms <= 0 || config.response_wait_ms <= 0) {
        return Result<std::vector<MdnsService>>::fail(
            ErrorCode::invalid_input,
            "invalid mdns timing",
            "query_timeout_ms and response_wait_ms must be positive"
        );
    }

    if (config.mock_mode) {
        return Result<std::vector<MdnsService>>::ok(build_mock_services(config.max_services));
    }

    WSADATA wsa_data{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        const int ws_error = WSAGetLastError();
        return Result<std::vector<MdnsService>>::fail(
            ErrorCode::internal,
            "mdns discovery failed",
            std::string("WSAStartup failed with error ") + std::to_string(ws_error)
        );
    }

    SOCKET socket_handle = INVALID_SOCKET;
    std::unordered_map<std::string, ParsedService> parsed;
    std::vector<MdnsService> out;
    if (!open_socket(socket_handle, config.response_wait_ms)) {
        const int last_error = WSAGetLastError();
        WSACleanup();
        return Result<std::vector<MdnsService>>::fail(
            ErrorCode::internal,
            "mdns discovery socket failed",
            std::string("unable to open UDP socket: ") + std::to_string(last_error)
        );
    }

    const std::uint16_t txid = static_cast<std::uint16_t>(
        std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFF
    );
    const int timeout_ms = static_cast<int>(config.query_timeout_ms);
    sockaddr_in mdns_addr{};
    mdns_addr.sin_family = AF_INET;
    mdns_addr.sin_port = htons(5353);
    ::inet_pton(AF_INET, "224.0.0.251", &mdns_addr.sin_addr);

    std::vector<std::uint8_t> response(1500);
    for (std::size_t service_index = 0; service_index < k_common_mdns_services.size(); ++service_index) {
        const auto& service = k_common_mdns_services[service_index];
        if (parsed.size() >= config.max_services) {
            break;
        }
        const auto query = build_ptr_query(service.type, static_cast<std::uint16_t>(txid + service_index));
        const int sent = ::sendto(
            socket_handle,
            reinterpret_cast<const char*>(query.data()),
            static_cast<int>(query.size()),
            0,
            reinterpret_cast<const sockaddr*>(&mdns_addr),
            static_cast<int>(sizeof(mdns_addr))
        );
        if (sent != static_cast<int>(query.size())) {
            Logger::instance().warning(
                "mdns",
                std::string("failed to send mdns query for ") + service.type
            );
            continue;
        }

        const long long deadline = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count() + static_cast<long long>(config.response_wait_ms);

        while (std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count() < deadline) {
            if (!receive_with_timeout(socket_handle, response, timeout_ms, response.size())) {
                break;
            }
            const auto before = parsed.size();
            apply_service_response(parsed, service.type, response, config.max_services);
            if (parsed.size() >= config.max_services) {
                break;
            }
            if (parsed.size() == before) {
                // Keep listening up to timeout; no new service was parsed from this response.
                continue;
            }
        }
    }

    out = collect_finalized_services(parsed, config.max_services);
    close_socket_if_open(socket_handle);
    WSACleanup();
    return Result<std::vector<MdnsService>>::ok(std::move(out));
}

} // namespace netsentinel::engine
