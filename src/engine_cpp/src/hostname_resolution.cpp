#include "netsentinel/engine/hostname_resolution.h"
#include "netsentinel/engine/logger.h"

#include <chrono>
#include <cstring>
#include <future>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

namespace {

struct CachedHostnameResolution {
    netsentinel::engine::HostnameResolution value;
    std::chrono::steady_clock::time_point cached_at;
    long long ttl_ms = 0;
};

std::mutex g_cache_mutex;
std::unordered_map<std::string, CachedHostnameResolution> g_cache;

std::chrono::steady_clock::time_point now_now() {
    return std::chrono::steady_clock::now();
}

bool has_cache_data(const netsentinel::engine::HostnameResolutionConfig& config) {
    return config.cache_enabled && config.cache_ttl_ms > 0;
}

std::string sanitize_mock_hostname_token(const std::string& ip_address) {
    std::string out = ip_address;
    for (auto& ch : out) {
        if (ch == '.') {
            ch = '-';
        }
    }
    return out;
}

std::string mock_hostname_value(const std::string& ip_address) {
    return "host-" + sanitize_mock_hostname_token(ip_address) + ".local";
}

std::string trim(const std::string& input) {
    const auto start = input.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) {
        return {};
    }
    const auto end = input.find_last_not_of(" \t\n\r");
    return input.substr(start, end - start + 1);
}

netsentinel::engine::HostnameResolution cache_hit_if_valid(
    const std::string& ip_address,
    const netsentinel::engine::HostnameResolutionConfig& config
) {
    if (!has_cache_data(config)) {
        return {};
    }
    const auto now = now_now();
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    const auto it = g_cache.find(ip_address);
    if (it == g_cache.end()) {
        return {};
    }
    const auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.cached_at).count();
    if (age_ms > it->second.ttl_ms) {
        g_cache.erase(it);
        return {};
    }
    return it->second.value;
}

void cache_store(
    const std::string& ip_address,
    const netsentinel::engine::HostnameResolution& resolution,
    const netsentinel::engine::HostnameResolutionConfig& config
) {
    if (!has_cache_data(config)) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    g_cache[ip_address] = CachedHostnameResolution{
        .value = resolution,
        .cached_at = now_now(),
        .ttl_ms = config.cache_ttl_ms
    };
}

netsentinel::engine::HostnameResolution resolve_hostname_live(const std::string& ip_address, const long long timeout_ms) {
    netsentinel::engine::HostnameResolution out;
    out.source = "reverse-dns";
    out.confidence = 0;

    const std::string ip = trim(ip_address);
    if (ip.empty()) {
        out.details = "ip_address must not be empty";
        return out;
    }

    if (timeout_ms <= 0) {
        out.timed_out = true;
        out.details = "reverse DNS timeout was set to zero";
        return out;
    }

    std::string normalized = ip;
    auto result = std::async(std::launch::async, [normalized]() -> netsentinel::engine::HostnameResolution {
        netsentinel::engine::HostnameResolution internal;
        internal.source = "reverse-dns";
        internal.confidence = 0;
#if defined(_WIN32)
        WSADATA wsa_data{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            internal.details = "winsock initialization failed";
            return internal;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        const int converted = inet_pton(AF_INET, normalized.c_str(), &address.sin_addr);
        if (converted != 1) {
            internal.details = "invalid IPv4 literal";
            WSACleanup();
            return internal;
        }

        char hostname[NI_MAXHOST]{};
        const int dns_status = getnameinfo(
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address),
            hostname,
            sizeof(hostname),
            nullptr,
            0,
            NI_NAMEREQD
        );
        if (dns_status != 0) {
            internal.details = std::string("reverse DNS failed: ") + gai_strerrorA(dns_status);
            WSACleanup();
            return internal;
        }

        internal.resolved = true;
        internal.confidence = 78;
        internal.hostname = trim(hostname);
        internal.details = "reverse DNS lookup succeeded";
        WSACleanup();
        return internal;
#else
        (void)normalized;
        internal.details = "reverse DNS live lookup is unavailable in this build";
        return internal;
#endif
    });

    if (result.wait_for(std::chrono::milliseconds(timeout_ms)) != std::future_status::ready) {
        out.timed_out = true;
        out.details = "reverse DNS request timed out";
        return out;
    }

    try {
        out = result.get();
    } catch (const std::exception& ex) {
        out.details = std::string("reverse DNS lookup threw exception: ") + ex.what();
    }
    return out;
}

} // namespace

namespace netsentinel::engine {

Result<HostnameResolution> resolve_hostname_for_ip(const std::string& ip_address, const HostnameResolutionConfig& config) {
    const auto target = trim(ip_address);
    if (target.empty()) {
        return Result<HostnameResolution>::fail(
            ErrorCode::invalid_input,
            "invalid reverse DNS target",
            "ip_address must not be empty"
        );
    }

    if (config.mock_mode) {
        auto cached = cache_hit_if_valid(target, config);
        if (cached.source == "mock-reverse-dns") {
            return Result<HostnameResolution>::ok(std::move(cached));
        }
        const HostnameResolution mocked{
            .resolved = true,
            .timed_out = false,
            .hostname = mock_hostname_value(target),
            .source = "mock-reverse-dns",
            .confidence = 55,
            .details = "mock reverse DNS result"
        };
        cache_store(target, mocked, config);
        return Result<HostnameResolution>::ok(mocked);
    }

    if (const auto cached = cache_hit_if_valid(target, config); cached.source == "reverse-dns" || cached.source == "reverse-dns-timeout" || !cached.hostname.empty()) {
        return Result<HostnameResolution>::ok(cached);
    }

    auto resolved = resolve_hostname_live(target, config.timeout_ms);
    if (!resolved.hostname.empty() && !resolved.resolved) {
        resolved.source = resolved.source + "-timeout";
    } else if (resolved.timed_out) {
        resolved.source = "reverse-dns-timeout";
    }
    cache_store(target, resolved, config);
    if (resolved.timed_out) {
        Logger::instance().warning("hostname_resolution", "reverse DNS timed out for " + target);
    } else if (resolved.resolved) {
        Logger::instance().info("hostname_resolution", "reverse DNS resolved " + target + " -> " + resolved.hostname);
    } else {
        Logger::instance().warning("hostname_resolution", "reverse DNS miss for " + target);
    }
    return Result<HostnameResolution>::ok(resolved);
}

Result<std::size_t> clear_hostname_resolution_cache() {
    std::lock_guard<std::mutex> lock(g_cache_mutex);
    const auto removed = g_cache.size();
    g_cache.clear();
    return Result<std::size_t>::ok(removed);
}

} // namespace netsentinel::engine
