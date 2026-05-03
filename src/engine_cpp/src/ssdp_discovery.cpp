#include "netsentinel/engine/logger.h"
#include "netsentinel/engine/ssdp_discovery.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

namespace {

constexpr int k_ssdp_port = 1900;
constexpr int k_http_default_port = 80;
constexpr long long k_rate_limit_ms = 60;

struct ParsedSsdpResponse {
    std::string target;
    std::string usn;
    std::string st;
    std::string nt;
    std::string location;
    std::string server;
    std::string device_type_hint;
    long long ttl_ms = 0;
};

void trim_in_place(std::string& value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    value = value.substr(start, end - start);
}

std::string lower_ascii(std::string_view value) {
    std::string out;
    out.resize(value.size());
    std::transform(value.begin(), value.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool parse_ipv4_parts(std::string_view ip, int& a, int& b, int& c, int& d) {
    int octets[4] = {0, 0, 0, 0};
    int part = 0;
    int current = 0;
    if (ip.empty()) {
        return false;
    }
    for (std::size_t i = 0; i <= ip.size(); ++i) {
        if (i == ip.size() || ip[i] == '.') {
            if (part >= 4 || current > 255) {
                return false;
            }
            octets[part++] = current;
            current = 0;
            continue;
        }
        if (ip[i] < '0' || ip[i] > '9') {
            return false;
        }
        current = current * 10 + (ip[i] - '0');
    }
    if (part != 4) {
        return false;
    }
    a = octets[0];
    b = octets[1];
    c = octets[2];
    d = octets[3];
    (void)d;
    return true;
}

bool is_private_ipv4(std::string_view ip) {
    int a = 0;
    int b = 0;
    int c = 0;
    int d = 0;
    if (!parse_ipv4_parts(ip, a, b, c, d)) {
        return false;
    }
    if (a == 10) {
        return true;
    }
    if (a == 172 && b >= 16 && b <= 31) {
        return true;
    }
    if (a == 192 && b == 168) {
        return true;
    }
    if (a == 169 && b == 254) {
        return true;
    }
    if (a == 127) {
        return true;
    }
    (void)c;
    (void)d;
    return false;
}

bool parse_header(std::string_view line, std::string_view expected, std::string& value) {
    const std::string lower_expected = lower_ascii(expected);
    const auto lower_line = lower_ascii(line);
    if (lower_line.size() <= lower_expected.size() + 1) {
        return false;
    }
    if (lower_line.rfind(lower_expected, 0) != 0) {
        return false;
    }
    const auto colon = line.find(':');
    if (colon == std::string_view::npos) {
        return false;
    }
    value.assign(line.substr(colon + 1));
    trim_in_place(value);
    return !value.empty();
}

std::string build_msearch_query() {
    return "M-SEARCH * HTTP/1.1\r\n"
           "HOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\n"
           "MX: 1\r\n"
           "ST: ssdp:all\r\n"
           "USER-AGENT: netsentinel11/0.1\r\n"
           "\r\n";
}

bool parse_cache_control(std::string_view cache_control, long long& ttl_ms) {
    const auto lower = lower_ascii(cache_control);
    const auto marker = std::string_view("max-age=");
    const auto pos = lower.find(marker);
    if (pos == std::string_view::npos) {
        return false;
    }
    long long ttl = 0;
    std::size_t cursor = pos + marker.size();
    while (cursor < cache_control.size()) {
        const char ch = cache_control[cursor];
        if (ch < '0' || ch > '9') {
            break;
        }
        ttl = ttl * 10 + static_cast<long long>(ch - '0');
        ++cursor;
    }
    if (ttl <= 0) {
        return false;
    }
    ttl_ms = ttl * 1000LL;
    return true;
}

void split_url(const std::string& location, std::string& host, int& port, std::string& path) {
    host.clear();
    path.clear();
    port = k_http_default_port;
    if (location.rfind("http://", 0) != 0) {
        return;
    }
    const auto after_scheme = location.substr(7);
    const auto slash = after_scheme.find('/');
    const std::string host_port = (slash == std::string::npos)
        ? after_scheme
        : after_scheme.substr(0, slash);
    path = (slash == std::string::npos) ? "/" : after_scheme.substr(slash);
    if (path.empty()) {
        path = "/";
    }
    const auto colon = host_port.find(':');
    if (colon == std::string::npos) {
        host = host_port;
        return;
    }
    host = host_port.substr(0, colon);
    if (colon + 1 < host_port.size()) {
        try {
            port = std::stoi(host_port.substr(colon + 1));
        } catch (...) {
            port = k_http_default_port;
        }
    }
}

bool parse_xml_tag(std::string_view text, std::string_view tag, std::string& out) {
    const auto lower_text = lower_ascii(text);
    const auto lower_tag = lower_ascii(tag);
    const std::string open = "<" + lower_tag + ">";
    const std::string close = "</" + lower_tag + ">";
    const auto open_pos = lower_text.find(open);
    if (open_pos == std::string_view::npos) {
        return false;
    }
    const auto close_pos = lower_text.find(close, open_pos + open.size());
    if (close_pos == std::string_view::npos || close_pos <= open_pos) {
        return false;
    }
    out.assign(text.substr(open_pos + open.size(), close_pos - (open_pos + open.size())));
    trim_in_place(out);
    return !out.empty();
}

bool parse_http_description(
    const std::string& location,
    long long http_timeout_ms,
    netsentinel::engine::SsdpDevice& device,
    std::string& details
) {
    std::string host;
    int port = 0;
    std::string path;
    split_url(location, host, port, path);
    if (host.empty() || port <= 0) {
        details = "invalid LOCATION URL";
        return false;
    }
    if (!is_private_ipv4(host)) {
        details = "skipped description parse for non-private host";
        return false;
    }

    std::string service(std::to_string(port));
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* results = nullptr;
    if (const int resolve_error = getaddrinfo(host.c_str(), service.c_str(), &hints, &results); resolve_error != 0) {
        details = std::string("description DNS failed: ") + gai_strerror(resolve_error);
        return false;
    }

    SOCKET sock = INVALID_SOCKET;
    bool connected = false;
    for (addrinfo* node = results; node; node = node->ai_next) {
        sock = ::socket(node->ai_family, node->ai_socktype, node->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }
        const int timeout = static_cast<int>(http_timeout_ms > 0 ? http_timeout_ms : 500);
        ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        if (::connect(sock, node->ai_addr, static_cast<int>(node->ai_addrlen)) == 0) {
            connected = true;
            break;
        }
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    freeaddrinfo(results);
    if (!connected || sock == INVALID_SOCKET) {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
        details = "failed to connect to LOCATION endpoint";
        return false;
    }

    const std::string request = "GET " + path + " HTTP/1.1\r\n"
                                "Host: " + host + "\r\n"
                                "Connection: close\r\n"
                                "User-Agent: netsentinel11/0.1\r\n"
                                "\r\n";
    const int sent = ::send(sock, request.c_str(), static_cast<int>(request.size()), 0);
    if (sent != static_cast<int>(request.size())) {
        closesocket(sock);
        details = "failed to send description request";
        return false;
    }

    std::string response;
    response.reserve(1024);
    std::vector<char> recv_buffer(1024);
    while (true) {
        const int bytes = ::recv(sock, recv_buffer.data(), static_cast<int>(recv_buffer.size()), 0);
        if (bytes <= 0) {
            break;
        }
        response.append(recv_buffer.data(), static_cast<std::size_t>(bytes));
    }
    closesocket(sock);

    const auto marker = response.find("\r\n\r\n");
    const std::string body = (marker == std::string::npos) ? std::string{} : response.substr(marker + 4);
    if (body.empty()) {
        details = "device description response empty";
        return false;
    }

    bool parsed = false;
    std::string friendly;
    std::string manufacturer;
    std::string model_name;
    std::string device_type;
    std::string presentation_url;
    if (parse_xml_tag(body, "friendlyName", friendly)) {
        device.friendly_name = friendly;
        parsed = true;
    }
    if (parse_xml_tag(body, "manufacturer", manufacturer)) {
        device.manufacturer = manufacturer;
        parsed = true;
    }
    if (parse_xml_tag(body, "modelName", model_name)) {
        device.model_name = model_name;
        parsed = true;
    }
    if (parse_xml_tag(body, "deviceType", device_type)) {
        device.device_type = device_type;
        parsed = true;
    }
    if (parse_xml_tag(body, "presentationURL", presentation_url)) {
        device.presentation_url = presentation_url;
        parsed = true;
    }
    details = parsed ? "parsed SSDP device description" : "description returned no supported metadata";
    return parsed;
}

bool parse_ssdp_response(const std::vector<std::uint8_t>& packet, const std::string& sender_ip, ParsedSsdpResponse& out) {
    const std::string_view raw(reinterpret_cast<const char*>(packet.data()), packet.size());
    if (raw.find("HTTP/1.1 200") == std::string_view::npos) {
        return false;
    }
    out = {};
    out.target = sender_ip;
    std::size_t cursor = 0;
    while (cursor < raw.size()) {
        const auto newline = raw.find('\n', cursor);
        const auto line_end = (newline == std::string_view::npos) ? raw.size() : (newline + 1);
        const auto line = raw.substr(cursor, line_end - cursor);
        cursor = line_end;
        if (line.empty() || line == "\r\n") {
            break;
        }
        std::string value;
        if (parse_header(line, "USN:", value)) {
            out.usn = value;
        } else if (parse_header(line, "ST:", value)) {
            out.st = value;
        } else if (parse_header(line, "NT:", value)) {
            out.nt = value;
        } else if (parse_header(line, "LOCATION:", value)) {
            out.location = value;
        } else if (parse_header(line, "SERVER:", value)) {
            out.server = value;
        } else if (parse_header(line, "CACHE-CONTROL:", value)) {
            (void)parse_cache_control(value, out.ttl_ms);
        }
    }
    if (out.device_type_hint.empty()) {
        out.device_type_hint = out.st.empty() ? out.nt : out.st;
        if (!out.device_type_hint.empty()) {
            const auto open_paren = out.device_type_hint.find(':');
            if (open_paren != std::string::npos) {
                const auto fragment = out.device_type_hint.substr(0, open_paren);
                out.device_type_hint = fragment;
            }
        }
    }
    return !out.usn.empty() || !out.st.empty() || !out.nt.empty();
}

std::vector<netsentinel::engine::SsdpDevice> collect_mock(std::size_t max_devices) {
    std::vector<netsentinel::engine::SsdpDevice> devices;
    devices.reserve(std::min<std::size_t>(max_devices, 3));
    if (max_devices >= 1) {
        devices.push_back(
            netsentinel::engine::SsdpDevice{
                "192.168.1.12",
                "uuid:mock-tv-01::upnp:rootdevice",
                "urn:schemas-upnp-org:device:MediaRenderer:1",
                "urn:schemas-upnp-org:device:MediaRenderer:1",
                "http://192.168.1.12:1400/device.xml",
                "ACME Labs",
                "ModelStream 200",
                "urn:schemas-upnp-org:device:MediaRenderer:1",
                "LivingRoom TV",
                "http://192.168.1.12:1400",
                "mock-ssdp/0.1 UPnP/1.1",
                120 * 1000,
                "mock-ssdp",
                82,
                "deterministic mock ssdp response"
            }
        );
    }
    if (max_devices >= 2) {
        devices.push_back(
            netsentinel::engine::SsdpDevice{
                "192.168.1.25",
                "uuid:mock-printer-01::upnp:rootdevice",
                "urn:schemas-upnp-org:device:Printer:1",
                "urn:schemas-upnp-org:device:Printer:1",
                "http://192.168.1.25:8080/description.xml",
                "PrintPro",
                "InkModel X",
                "urn:schemas-upnp-org:device:Printer:1",
                "Office Printer",
                "",
                "mock-ssdp/0.1 UPnP/1.1",
                120 * 1000,
                "mock-ssdp",
                74,
                "deterministic mock ssdp response"
            }
        );
    }
    if (max_devices >= 3) {
        devices.push_back(
            netsentinel::engine::SsdpDevice{
                "192.168.1.30",
                "uuid:mock-router-01::upnp:rootdevice",
                "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                "http://192.168.1.30:5000/setup.xml",
                "SecureNet",
                "RouterModel Z",
                "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                "Home Router",
                "http://192.168.1.30",
                "mock-ssdp/0.1 UPnP/1.1",
                120 * 1000,
                "mock-ssdp",
                71,
                "deterministic mock ssdp response"
            }
        );
    }
    if (devices.size() > max_devices) {
        devices.resize(max_devices);
    }
    return devices;
}

bool open_ssdp_socket(SOCKET& socket_handle, long long timeout_ms) {
    socket_handle = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET) {
        return false;
    }
    const int on = 1;
    ::setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&on), sizeof(on));
    u_long non_blocking = 0;
    if (::ioctlsocket(socket_handle, FIONBIO, &non_blocking) != 0) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
        return false;
    }
    const int timeout = static_cast<int>(timeout_ms > 0 ? timeout_ms : 500);
    if (::setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
        return false;
    }
    if (::setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
        return false;
    }
    int ttl = 2;
    if (::setsockopt(socket_handle, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&ttl), sizeof(ttl)) != 0) {
        closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
        return false;
    }
    return true;
}

bool receive_response(
    SOCKET socket_handle,
    std::vector<std::uint8_t>& buffer,
    int timeout_ms,
    std::string& sender_ip
) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(socket_handle, &read_set);
    timeval tv{};
    tv.tv_sec = static_cast<long>(timeout_ms / 1000);
    tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
    if (select(0, &read_set, nullptr, nullptr, &tv) <= 0) {
        return false;
    }
    sockaddr_in sender{};
    int sender_len = static_cast<int>(sizeof(sender));
    const int bytes = ::recvfrom(
        socket_handle,
        reinterpret_cast<char*>(buffer.data()),
        static_cast<int>(buffer.size()),
        0,
        reinterpret_cast<sockaddr*>(&sender),
        &sender_len
    );
    if (bytes <= 0) {
        return false;
    }
    buffer.resize(static_cast<std::size_t>(bytes));
    char sender_text[INET_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET, &sender.sin_addr, sender_text, sizeof(sender_text)) == nullptr) {
        sender_ip.clear();
    } else {
        sender_ip.assign(sender_text);
    }
    return true;
}

} // namespace

namespace netsentinel::engine {

Result<std::vector<SsdpDevice>> discover_ssdp_devices(const SsdpDiscoveryConfig& config) {
    if (config.max_devices == 0) {
        return Result<std::vector<SsdpDevice>>::fail(
            ErrorCode::invalid_input,
            "invalid ssdp request",
            "max_devices must be greater than zero"
        );
    }
    if (config.query_timeout_ms <= 0 || config.response_wait_ms <= 0) {
        return Result<std::vector<SsdpDevice>>::fail(
            ErrorCode::invalid_input,
            "invalid ssdp timing",
            "query_timeout_ms and response_wait_ms must be positive"
        );
    }
    if (config.mock_mode) {
        return Result<std::vector<SsdpDevice>>::ok(collect_mock(config.max_devices));
    }

    Logger::instance().info("ssdp", "starting ssdp discovery");
    WSADATA data{};
    if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        const int ws_error = WSAGetLastError();
        return Result<std::vector<SsdpDevice>>::fail(
            ErrorCode::internal,
            "ssdp discovery failed",
            "WSAStartup failed: " + std::to_string(ws_error)
        );
    }

    SOCKET socket_handle = INVALID_SOCKET;
    if (!open_ssdp_socket(socket_handle, config.response_wait_ms)) {
        const int socket_error = WSAGetLastError();
        WSACleanup();
        return Result<std::vector<SsdpDevice>>::fail(
            ErrorCode::internal,
            "ssdp discovery socket failed",
            "unable to open UDP socket: " + std::to_string(socket_error)
        );
    }

    sockaddr_in multicast{};
    multicast.sin_family = AF_INET;
    multicast.sin_port = htons(k_ssdp_port);
    ::inet_pton(AF_INET, "239.255.255.250", &multicast.sin_addr);

    const std::string query = build_msearch_query();
    const int sent = ::sendto(
        socket_handle,
        query.c_str(),
        static_cast<int>(query.size()),
        0,
        reinterpret_cast<sockaddr*>(&multicast),
        static_cast<int>(sizeof(multicast))
    );
    if (sent != static_cast<int>(query.size())) {
        const int send_error = WSAGetLastError();
        closesocket(socket_handle);
        WSACleanup();
        return Result<std::vector<SsdpDevice>>::fail(
            ErrorCode::internal,
            "ssdp discovery failed",
            "failed to send m-search: " + std::to_string(send_error)
        );
    }

    std::unordered_map<std::string, SsdpDevice> discovered;
    std::vector<std::uint8_t> response(2048);
    const auto start_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    auto next_description = std::chrono::steady_clock::time_point{};

    while (std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count() < start_ms + static_cast<long long>(config.response_wait_ms)) {
        std::string sender_ip;
        if (!receive_response(socket_handle, response, static_cast<int>(config.query_timeout_ms), sender_ip)) {
            continue;
        }
        if (!is_private_ipv4(sender_ip)) {
            continue;
        }
        ParsedSsdpResponse parsed;
        if (!parse_ssdp_response(response, sender_ip, parsed)) {
            continue;
        }
        const std::string key = !parsed.usn.empty() ? parsed.usn : parsed.location;
        if (key.empty() || discovered.size() >= config.max_devices) {
            continue;
        }
        if (discovered.find(key) != discovered.end()) {
            continue;
        }
        SsdpDevice device{
            parsed.target,
            parsed.usn,
            parsed.st,
            parsed.nt,
            parsed.location,
            "",
            "",
            parsed.device_type_hint,
            parsed.location.empty() ? parsed.target : parsed.location,
            "",
            parsed.server,
            parsed.ttl_ms,
            "ssdp-udp",
            62,
            "ssdp response parsed"
        };
        if (config.parse_description && !parsed.location.empty() && std::chrono::steady_clock::now() >= next_description) {
            std::string detail;
            if (parse_http_description(parsed.location, config.http_timeout_ms, device, detail)) {
                if (!device.friendly_name.empty()) {
                    device.confidence = 84;
                }
            }
            if (device.friendly_name.empty()) {
                device.friendly_name = parsed.target;
            }
            if (device.details.empty()) {
                device.details = detail;
            }
            next_description = std::chrono::steady_clock::now() + std::chrono::milliseconds(k_rate_limit_ms);
        } else if (config.parse_description && device.details.empty()) {
            device.details = "description fetch deferred by rate limit";
        }
        if (device.device_type.empty()) {
            device.device_type = parsed.nt.empty() ? parsed.st : parsed.nt;
        }
        discovered.emplace(key, std::move(device));
    }

    std::vector<SsdpDevice> out;
    out.reserve(discovered.size());
    for (auto& entry : discovered) {
        out.push_back(std::move(entry.second));
    }
    closesocket(socket_handle);
    WSACleanup();
    return Result<std::vector<SsdpDevice>>::ok(std::move(out));
}

} // namespace netsentinel::engine
