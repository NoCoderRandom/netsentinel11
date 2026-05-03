#include "netsentinel/outage/outage_detector.h"

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string_view>
#include <vector>

#include <filesystem>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#endif

namespace netsentinel::outage {

namespace {

std::filesystem::path state_directory() {
    if (const char* override = std::getenv("NETSENTINEL_OUTAGE_STATE_DIR")) {
        if (*override != '\0') {
            return std::filesystem::path{override};
        }
    }
    const char* local = std::getenv("LOCALAPPDATA");
    if (local == nullptr || *local == '\0') {
        local = std::getenv("TEMP");
    }
    if (local == nullptr || *local == '\0') {
        local = ".";
    }
    return std::filesystem::path{local} / "NetSentinel11";
}

std::filesystem::path history_path() {
    return state_directory() / "outage-timeline.csv";
}

std::string now_utc_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto utc = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &utc);
#else
    gmtime_r(&utc, &tm);
#endif
    char out[32];
    std::strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string{out};
}

bool contains_token(std::string_view text, std::string_view token) {
    return text.find(token) != std::string_view::npos;
}

bool starts_with(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

bool is_authorized_local_probe_target(std::string_view target) {
    return target == "localhost" ||
        target == "127.0.0.1" ||
        starts_with(target, "127.") ||
        starts_with(target, "192.168.50.") ||
        starts_with(target, "192.168.1.");
}

OutageClass classify_mock_case(const OutageCheckConfig& config) {
    if (contains_token(config.gateway_ip, "0.0.0.0")) {
        return OutageClass::gateway_failure;
    }
    if (contains_token(config.dns_host, "bad") || contains_token(config.dns_host, "0.0.0.0")) {
        return OutageClass::dns_failure;
    }
    if (contains_token(config.external_url, "down") || contains_token(config.external_url, "offline")) {
        return OutageClass::isp_failure;
    }
    if (contains_token(config.host_ip, "0.0.0.0") || contains_token(config.host_ip, "offline")) {
        return OutageClass::host_failure;
    }
    return OutageClass::clear;
}

const char* class_to_text(OutageClass cls) {
    switch (cls) {
        case OutageClass::clear:
            return "clear";
        case OutageClass::gateway_failure:
            return "gateway_failure";
        case OutageClass::dns_failure:
            return "dns_failure";
        case OutageClass::isp_failure:
            return "isp_failure";
        case OutageClass::host_failure:
            return "host_failure";
        default:
            return "unknown";
    }
}

const char* class_to_message(OutageClass cls) {
    switch (cls) {
        case OutageClass::clear:
            return "No outage detected in mock mode.";
        case OutageClass::gateway_failure:
            return "Gateway ping check failed in mock mode.";
        case OutageClass::dns_failure:
            return "DNS query check failed in mock mode.";
        case OutageClass::isp_failure:
            return "External HTTPS HEAD check failed in mock mode.";
        case OutageClass::host_failure:
            return "Single-host reachability check failed in mock mode.";
        default:
            return "unknown classification";
    }
}

#ifdef _WIN32
bool ensure_winsock_started() {
    static const bool started = [] {
        WSADATA data{};
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return started;
}

DWORD timeout_to_dword(std::size_t timeout_ms) {
    constexpr std::size_t max_timeout = 60000;
    const auto clamped = std::min(timeout_ms == 0 ? std::size_t{1} : timeout_ms, max_timeout);
    return static_cast<DWORD>(clamped);
}

bool live_ping_ipv4(const std::string& ip, std::size_t timeout_ms) {
    if (!ensure_winsock_started()) {
        return false;
    }
    IN_ADDR address{};
    if (InetPtonA(AF_INET, ip.c_str(), &address) != 1) {
        return false;
    }

    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) {
        return false;
    }

    const char payload[] = "netsentinel-outage";
    const DWORD reply_size = static_cast<DWORD>(sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8);
    std::vector<unsigned char> reply(reply_size);
    const DWORD count = IcmpSendEcho(
        icmp,
        address.S_un.S_addr,
        const_cast<char*>(payload),
        static_cast<WORD>(sizeof(payload)),
        nullptr,
        reply.data(),
        reply_size,
        timeout_to_dword(timeout_ms)
    );
    IcmpCloseHandle(icmp);
    if (count == 0) {
        return false;
    }
    const auto* echo = reinterpret_cast<const ICMP_ECHO_REPLY*>(reply.data());
    return echo->Status == IP_SUCCESS;
}

bool live_dns_resolves(const std::string& host) {
    if (host.empty() || !ensure_winsock_started()) {
        return false;
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* info = nullptr;
    const int result = getaddrinfo(host.c_str(), nullptr, &hints, &info);
    if (info != nullptr) {
        freeaddrinfo(info);
    }
    return result == 0;
}

OutageCheckResult run_live_windows_local_check(const OutageCheckConfig& config) {
    OutageCheckResult result{};
    const bool gateway_ok = live_ping_ipv4(config.gateway_ip, config.timeout_ms);
    if (!gateway_ok) {
        result.classification = OutageClass::gateway_failure;
        result.outage_detected = true;
        result.message = "Gateway ICMP probe failed using safe local Windows outage check.";
        return result;
    }

    const bool dns_ok = live_dns_resolves(config.dns_host);
    if (!dns_ok) {
        result.classification = OutageClass::dns_failure;
        result.outage_detected = true;
        result.message = "DNS resolution probe failed using the Windows resolver.";
        return result;
    }

    const bool host_ok = live_ping_ipv4(config.host_ip, config.timeout_ms);
    if (!host_ok) {
        result.classification = OutageClass::host_failure;
        result.outage_detected = true;
        result.message = "Configured local host ICMP probe failed after gateway and DNS succeeded.";
        return result;
    }

    result.classification = OutageClass::clear;
    result.outage_detected = false;
    result.message = "Gateway, DNS, and configured local host probes succeeded using safe local Windows checks.";
    return result;
}
#endif

void append_history(const OutageCheckResult& result) {
    const auto path = history_path();
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out{path, std::ios::app};
    if (!out.is_open()) {
        return;
    }
    out << now_utc_iso8601() << ","
        << (result.outage_detected ? "outage" : "healthy") << ","
        << class_to_text(result.classification) << ","
        << result.message << "\n";
}

void prune_history(std::size_t max_entries) {
    const auto path = history_path();
    std::ifstream in{path};
    if (!in.is_open()) {
        return;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    if (lines.size() <= max_entries) {
        return;
    }
    const std::size_t keep_from = lines.size() - max_entries;
    std::ofstream out{path, std::ios::trunc};
    if (!out.is_open()) {
        return;
    }
    for (std::size_t i = keep_from; i < lines.size(); ++i) {
        out << lines[i] << "\n";
    }
}

} // namespace

const char* to_string(OutageClass cls) {
    return class_to_text(cls);
}

OutageCheckOperationResult run_outage_check(const OutageCheckConfig& config) {
    if (config.gateway_ip.empty() || config.dns_host.empty() || config.external_url.empty() || config.host_ip.empty()) {
        return {
            .success = false,
            .persisted = false,
            .result = {false, OutageClass::clear, "Missing one or more required endpoints."},
            .message = "missing-required-input"
        };
    }
    if (!config.mock_mode) {
#ifdef _WIN32
        if (!is_authorized_local_probe_target(config.gateway_ip) || !is_authorized_local_probe_target(config.host_ip)) {
            return {
                .success = false,
                .persisted = false,
                .result = {false, OutageClass::clear, "Live outage check blocked because gateway or host target is outside the authorized local ranges."},
                .message = "live-outage-target-not-authorized"
            };
        }
        const auto live_result = run_live_windows_local_check(config);
        append_history(live_result);
        prune_history(200);
        return {
            .success = true,
            .persisted = true,
            .result = live_result,
            .message = "live-local-outage-check"
        };
#else
        return {
            .success = false,
            .persisted = false,
            .result = {false, OutageClass::clear, "Non-mock checks are intentionally disabled in this stage; use --mock."},
            .message = "mock-only-mode"
        };
#endif
    }
    OutageCheckResult result;
    result.classification = classify_mock_case(config);
    result.outage_detected = (result.classification != OutageClass::clear);
    result.message = class_to_message(result.classification);

    append_history(result);
    prune_history(200);
    return {
        .success = true,
        .persisted = true,
        .result = result,
        .message = "mock-outage-check"
    };
}

std::vector<OutageTimelinePoint> read_outage_history(std::size_t max_entries) {
    std::vector<OutageTimelinePoint> out;
    const auto path = history_path();
    std::ifstream in{path};
    if (!in.is_open()) {
        return out;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    if (lines.size() > max_entries) {
        const auto start = lines.size() - max_entries;
        lines.erase(lines.begin(), lines.begin() + static_cast<std::ptrdiff_t>(start));
    }
    for (const auto& item : lines) {
        std::array<std::string, 4> cols{};
        std::size_t cursor = 0;
        std::size_t index = 0;
        while (index < cols.size()) {
            auto delim = item.find(',', cursor);
            if (delim == std::string::npos) {
                cols[index] = item.substr(cursor);
                break;
            }
            cols[index++] = item.substr(cursor, delim - cursor);
            cursor = delim + 1;
        }
        if (index < cols.size() - 1) {
            continue;
        }
        OutageTimelinePoint point;
        point.timestamp_utc = cols[0];
        point.classification = cols[2];
        point.outage_detected = (cols[1] == "outage");
        point.source = "mock";
        point.details = cols[3];
        out.push_back(point);
    }
    return out;
}

} // namespace netsentinel::outage
