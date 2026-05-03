#include "netsentinel/diagnostics/diagnostic_tools.h"

#include <array>
#include <cstdlib>
#include <functional>
#include <fstream>
#include <algorithm>
#include <cmath>
#include <cctype>
#include <iomanip>
#include <limits>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <string_view>
#include <vector>
#include <filesystem>
#include <chrono>
#include <ctime>

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
#include <wlanapi.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#endif

namespace netsentinel::diagnostics {

namespace {

struct DhcpAdapterSource {
    std::string adapter_id;
    std::string interface_name;
    bool dhcp_enabled = false;
    std::string dhcp_server;
    std::string gateway;
    std::vector<std::string> dns_servers;
};

struct CameraInventoryRecord {
    std::string device_id;
    std::string hostname;
    std::vector<std::string> ip_addresses;
    std::string mac_address;
    std::string vendor_hint;
    std::string device_type;
    std::vector<std::string> user_labels;
    std::vector<int> open_tcp_ports;
    int importance = 0;
    bool hidden = false;
    std::string details;
};

std::filesystem::path state_directory() {
    if (const char* override = std::getenv("NETSENTINEL_DIAG_TOOLS_STATE_DIR")) {
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
    return state_directory() / "diagnostics-history.csv";
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

double deterministic_latency_ms(std::string_view text) {
    return static_cast<double>(std::hash<std::string_view>{}(text) % 1500) / 10.0 + 5.0;
}

double compute_consistency_score(const std::vector<double>& latencies) {
    if (latencies.empty()) {
        return 0.0;
    }
    if (latencies.size() == 1) {
        return 1.0;
    }
    double total = 0.0;
    for (double value : latencies) {
        total += value;
    }
    const double avg = total / static_cast<double>(latencies.size());
    if (avg <= 0.0) {
        return 0.0;
    }
    double variance_sum = 0.0;
    for (double value : latencies) {
        const double delta = value - avg;
        variance_sum += delta * delta;
    }
    const double variance = variance_sum / static_cast<double>(latencies.size());
    const double stdev = std::sqrt(variance);
    const double ratio = stdev / avg;
    return std::clamp(1.0 - ratio, 0.0, 1.0);
}

std::vector<DhcpAdapterSource> mock_dhcp_adapters() {
    return {
        DhcpAdapterSource{
            .adapter_id = "mock-ethernet-001",
            .interface_name = "Ethernet",
            .dhcp_enabled = true,
            .gateway = "192.168.1.1",
            .dns_servers = {"192.168.1.1", "1.1.1.1"}
        },
        DhcpAdapterSource{
            .adapter_id = "mock-wifi-001",
            .interface_name = "Wi-Fi",
            .dhcp_enabled = true,
            .gateway = "10.0.0.1",
            .dns_servers = {"10.0.0.1", "9.9.9.9"}
        },
        DhcpAdapterSource{
            .adapter_id = "mock-static-001",
            .interface_name = "StaticOnly",
            .dhcp_enabled = false,
            .gateway = "172.16.0.1",
            .dns_servers = {}
        }
    };
}

#ifdef _WIN32
std::string wide_to_utf8(const wchar_t* value) {
    if (value == nullptr || *value == L'\0') {
        return "";
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) {
        return "";
    }
    std::string out(static_cast<std::size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), size, nullptr, nullptr);
    return out;
}

std::string sockaddr_to_ip_string(const SOCKET_ADDRESS& address) {
    if (address.lpSockaddr == nullptr || address.iSockaddrLength <= 0) {
        return "";
    }
    char host[INET6_ADDRSTRLEN] = {};
    if (address.lpSockaddr->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address.lpSockaddr);
        if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&ipv4->sin_addr), host, static_cast<DWORD>(sizeof(host))) == nullptr) {
            return "";
        }
        return std::string{host};
    }
    if (address.lpSockaddr->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address.lpSockaddr);
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&ipv6->sin6_addr), host, static_cast<DWORD>(sizeof(host))) == nullptr) {
            return "";
        }
        return std::string{host};
    }
    return "";
}

void add_unique_ip(std::vector<std::string>& values, const std::string& value) {
    if (value.empty()) {
        return;
    }
    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

std::vector<DhcpAdapterSource> discover_live_windows_dhcp_adapters() {
    ULONG buffer_size = 15 * 1024;
    std::vector<unsigned char> buffer(buffer_size);
    ULONG result = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.resize(buffer_size);
        result = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
            &buffer_size
        );
    }
    if (result != NO_ERROR) {
        return {};
    }

    std::vector<DhcpAdapterSource> adapters;
    for (auto* adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
         adapter != nullptr;
         adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }

        DhcpAdapterSource source{};
        if (adapter->AdapterName != nullptr) {
            source.adapter_id = adapter->AdapterName;
        }
        source.interface_name = wide_to_utf8(adapter->FriendlyName);
        if (source.interface_name.empty()) {
            source.interface_name = wide_to_utf8(adapter->Description);
        }
        if (source.interface_name.empty()) {
            source.interface_name = source.adapter_id.empty() ? ("ifindex-" + std::to_string(adapter->IfIndex)) : source.adapter_id;
        }
        if (source.adapter_id.empty()) {
            source.adapter_id = "ifindex-" + std::to_string(adapter->IfIndex);
        }

        source.dhcp_enabled = adapter->Dhcpv4Enabled != 0;
        source.dhcp_server = sockaddr_to_ip_string(adapter->Dhcpv4Server);

        for (auto* gateway = adapter->FirstGatewayAddress; gateway != nullptr; gateway = gateway->Next) {
            const auto gateway_ip = sockaddr_to_ip_string(gateway->Address);
            if (!gateway_ip.empty()) {
                source.gateway = gateway_ip;
                break;
            }
        }

        for (auto* dns = adapter->FirstDnsServerAddress; dns != nullptr; dns = dns->Next) {
            add_unique_ip(source.dns_servers, sockaddr_to_ip_string(dns->Address));
        }

        adapters.push_back(std::move(source));
    }
    return adapters;
}
#endif

std::vector<DhcpAdapterSource> discover_adapters_for_dhcp(bool mock_mode) {
    if (mock_mode) {
        return mock_dhcp_adapters();
    }
#ifdef _WIN32
    return discover_live_windows_dhcp_adapters();
#else
    return {};
#endif
}

std::vector<WifiNetworkInfo> mock_wifi_networks() {
    return {
        WifiNetworkInfo{
            .ssid = "Home-Fi",
            .bssid = "A4:5D:36:11:22:33",
            .rssi_dbm = -42,
            .channel = 11,
            .band = "2.4GHz",
            .auth = "WPA2-PSK",
            .cipher = "CCMP",
            .signal_quality = 87,
            .connected = true,
            .hidden = false
        },
        WifiNetworkInfo{
            .ssid = "Office-Guest",
            .bssid = "D8:9F:8A:44:55:66",
            .rssi_dbm = -61,
            .channel = 44,
            .band = "5GHz",
            .auth = "WPA3-SAE",
            .cipher = "GCMP",
            .signal_quality = 64,
            .connected = false,
            .hidden = true
        },
        WifiNetworkInfo{
            .ssid = "Warehouse",
            .bssid = "11:22:33:44:55:66",
            .rssi_dbm = -72,
            .channel = 6,
            .band = "2.4GHz",
            .auth = "Open",
            .cipher = "None",
            .signal_quality = 39,
            .connected = false,
            .hidden = false
        },
        WifiNetworkInfo{
            .ssid = "Neighbor-Fi",
            .bssid = "7C:8B:CA:99:88:77",
            .rssi_dbm = -68,
            .channel = 10,
            .band = "2.4GHz",
            .auth = "WPA2-PSK",
            .cipher = "CCMP",
            .signal_quality = 48,
            .connected = false,
            .hidden = false
        }
    };
}

struct WifiScanCollection {
    bool success = false;
    std::vector<WifiNetworkInfo> networks{};
    std::string message{};
};

int channel_from_frequency_khz(unsigned long frequency_khz) {
    const unsigned long frequency_mhz = frequency_khz > 100000 ? frequency_khz / 1000 : frequency_khz;
    if (frequency_mhz == 2484) {
        return 14;
    }
    if (frequency_mhz >= 2412 && frequency_mhz <= 2472) {
        return static_cast<int>((frequency_mhz - 2407) / 5);
    }
    if (frequency_mhz >= 5000 && frequency_mhz <= 5895) {
        return static_cast<int>((frequency_mhz - 5000) / 5);
    }
    if (frequency_mhz >= 5955 && frequency_mhz <= 7115) {
        return static_cast<int>((frequency_mhz - 5950) / 5);
    }
    return 0;
}

std::string band_from_channel_and_frequency(int channel, unsigned long frequency_khz) {
    const unsigned long frequency_mhz = frequency_khz > 100000 ? frequency_khz / 1000 : frequency_khz;
    if ((frequency_mhz >= 2400 && frequency_mhz < 2500) || (channel >= 1 && channel <= 14)) {
        return "2.4GHz";
    }
    if ((frequency_mhz >= 4900 && frequency_mhz < 5925) || (channel >= 32 && channel <= 177)) {
        return "5GHz";
    }
    if (frequency_mhz >= 5925 && frequency_mhz <= 7125) {
        return "6GHz";
    }
    return "unknown";
}

std::string normalize_ssid_for_display(std::string value) {
    for (char& ch : value) {
        const auto uch = static_cast<unsigned char>(ch);
        if (uch < 32 || uch == 127) {
            ch = '?';
        }
    }
    return value;
}

#ifdef _WIN32
std::string ssid_to_string(const DOT11_SSID& ssid) {
    if (ssid.uSSIDLength == 0) {
        return {};
    }
    const auto length = std::min<std::size_t>(ssid.uSSIDLength, sizeof(ssid.ucSSID));
    return normalize_ssid_for_display(std::string{
        reinterpret_cast<const char*>(ssid.ucSSID),
        reinterpret_cast<const char*>(ssid.ucSSID) + length
    });
}

std::string bssid_to_string(const UCHAR* bssid) {
    std::ostringstream out;
    out << std::uppercase << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            out << ":";
        }
        out << std::setw(2) << static_cast<int>(bssid[i]);
    }
    return out.str();
}

std::string auth_algorithm_to_string(DOT11_AUTH_ALGORITHM auth) {
    switch (auth) {
        case DOT11_AUTH_ALGO_80211_OPEN:
            return "Open";
        case DOT11_AUTH_ALGO_80211_SHARED_KEY:
            return "WEP";
        case DOT11_AUTH_ALGO_WPA:
            return "WPA";
        case DOT11_AUTH_ALGO_WPA_PSK:
            return "WPA-PSK";
        case DOT11_AUTH_ALGO_WPA_NONE:
            return "WPA-None";
        case DOT11_AUTH_ALGO_RSNA:
            return "WPA2-Enterprise";
        case DOT11_AUTH_ALGO_RSNA_PSK:
            return "WPA2-PSK";
#ifdef DOT11_AUTH_ALGO_WPA3
        case DOT11_AUTH_ALGO_WPA3:
            return "WPA3";
#endif
#ifdef DOT11_AUTH_ALGO_WPA3_SAE
        case DOT11_AUTH_ALGO_WPA3_SAE:
            return "WPA3-SAE";
#endif
        default:
            return "Unknown";
    }
}

std::string cipher_algorithm_to_string(DOT11_CIPHER_ALGORITHM cipher) {
    switch (cipher) {
        case DOT11_CIPHER_ALGO_NONE:
            return "None";
        case DOT11_CIPHER_ALGO_WEP40:
            return "WEP40";
        case DOT11_CIPHER_ALGO_TKIP:
            return "TKIP";
        case DOT11_CIPHER_ALGO_CCMP:
            return "CCMP";
        case DOT11_CIPHER_ALGO_WEP104:
            return "WEP104";
        case DOT11_CIPHER_ALGO_WEP:
            return "WEP";
#ifdef DOT11_CIPHER_ALGO_GCMP
        case DOT11_CIPHER_ALGO_GCMP:
            return "GCMP";
#endif
        default:
            return "Unknown";
    }
}

WifiScanCollection collect_windows_wifi_scan_results() {
    WifiScanCollection collection{};
    DWORD negotiated_version = 0;
    HANDLE client = nullptr;
    const DWORD open_result = WlanOpenHandle(2, nullptr, &negotiated_version, &client);
    if (open_result != ERROR_SUCCESS || client == nullptr) {
        collection.message = "Windows WLAN API is unavailable or permission was denied. Error=" + std::to_string(open_result);
        return collection;
    }

    PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;
    const DWORD enum_result = WlanEnumInterfaces(client, nullptr, &interfaces);
    if (enum_result != ERROR_SUCCESS || interfaces == nullptr || interfaces->dwNumberOfItems == 0) {
        if (interfaces != nullptr) {
            WlanFreeMemory(interfaces);
        }
        WlanCloseHandle(client, nullptr);
        collection.message = "No active Windows WLAN interfaces were found. Error=" + std::to_string(enum_result);
        return collection;
    }

    std::unordered_map<std::string, WifiNetworkInfo> available_by_ssid;
    std::size_t interface_count = 0;
    for (DWORD i = 0; i < interfaces->dwNumberOfItems; ++i) {
        const auto& iface = interfaces->InterfaceInfo[i];
        ++interface_count;
        (void)WlanScan(client, &iface.InterfaceGuid, nullptr, nullptr, nullptr);

        PWLAN_AVAILABLE_NETWORK_LIST available = nullptr;
        const DWORD available_result = WlanGetAvailableNetworkList(
            client,
            &iface.InterfaceGuid,
            0,
            nullptr,
            &available
        );
        if (available_result == ERROR_SUCCESS && available != nullptr) {
            for (DWORD n = 0; n < available->dwNumberOfItems; ++n) {
                const auto& entry = available->Network[n];
                WifiNetworkInfo info{};
                info.ssid = ssid_to_string(entry.dot11Ssid);
                info.hidden = info.ssid.empty();
                info.signal_quality = static_cast<int>(entry.wlanSignalQuality);
                info.connected = (entry.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) != 0;
                info.auth = auth_algorithm_to_string(entry.dot11DefaultAuthAlgorithm);
                info.cipher = cipher_algorithm_to_string(entry.dot11DefaultCipherAlgorithm);
                if (!info.ssid.empty()) {
                    available_by_ssid[info.ssid] = info;
                }
            }
            WlanFreeMemory(available);
        }

        PWLAN_BSS_LIST bss_list = nullptr;
        const DWORD bss_result = WlanGetNetworkBssList(
            client,
            &iface.InterfaceGuid,
            nullptr,
            dot11_BSS_type_any,
            FALSE,
            nullptr,
            &bss_list
        );
        if (bss_result == ERROR_SUCCESS && bss_list != nullptr) {
            for (DWORD b = 0; b < bss_list->dwNumberOfItems; ++b) {
                const auto& entry = bss_list->wlanBssEntries[b];
                WifiNetworkInfo info{};
                info.ssid = ssid_to_string(entry.dot11Ssid);
                info.hidden = info.ssid.empty();
                info.bssid = bssid_to_string(entry.dot11Bssid);
                info.rssi_dbm = entry.lRssi;
                info.signal_quality = static_cast<int>(entry.uLinkQuality);
                info.channel = channel_from_frequency_khz(entry.ulChCenterFrequency);
                info.band = band_from_channel_and_frequency(info.channel, entry.ulChCenterFrequency);
                const auto available_it = available_by_ssid.find(info.ssid);
                if (available_it != available_by_ssid.end()) {
                    info.connected = available_it->second.connected;
                    info.auth = available_it->second.auth;
                    info.cipher = available_it->second.cipher;
                    if (info.signal_quality == 0) {
                        info.signal_quality = available_it->second.signal_quality;
                    }
                } else {
                    info.auth = "Unknown";
                    info.cipher = "Unknown";
                }
                collection.networks.push_back(std::move(info));
            }
            WlanFreeMemory(bss_list);
        }
    }

    if (interfaces != nullptr) {
        WlanFreeMemory(interfaces);
    }
    WlanCloseHandle(client, nullptr);

    if (collection.networks.empty() && !available_by_ssid.empty()) {
        for (const auto& item : available_by_ssid) {
            collection.networks.push_back(item.second);
        }
    }

    std::sort(collection.networks.begin(), collection.networks.end(), [](const WifiNetworkInfo& lhs, const WifiNetworkInfo& rhs) {
        if (lhs.connected != rhs.connected) {
            return lhs.connected && !rhs.connected;
        }
        if (lhs.signal_quality != rhs.signal_quality) {
            return lhs.signal_quality > rhs.signal_quality;
        }
        return lhs.ssid < rhs.ssid;
    });

    collection.success = true;
    collection.message = "Windows WLAN API scan completed; interfaces=" + std::to_string(interface_count) +
        ", networks=" + std::to_string(collection.networks.size()) +
        ". No client-device tracking, deauth, monitor mode, or disruptive traffic was used.";
    return collection;
}
#endif

WifiScanCollection collect_wifi_scan_results(bool mock_mode) {
    if (mock_mode) {
        return {
            .success = true,
            .networks = mock_wifi_networks(),
            .message = "mock-wifi-scan"
        };
    }
#ifdef _WIN32
    return collect_windows_wifi_scan_results();
#else
    return {
        .success = false,
        .networks = {},
        .message = "Native Wi-Fi environment scanning is currently implemented for Windows WLAN APIs only."
    };
#endif
}

void append_history(const std::string& command, const std::string& target, const std::string& status, const std::string& details) {
    const auto path = history_path();
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out{path, std::ios::app};
    if (!out.is_open()) {
        return;
    }
    out << now_utc_iso8601() << ","
        << command << ","
        << target << ","
        << status << ","
        << details << "\n";
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

bool is_invalid_resolver(std::string_view resolver) {
    return contains_token(resolver, "0.0.0.0") || contains_token(resolver, "bad");
}

PingResult mock_ping(const PingConfig& config) {
    PingResult result;
    if (contains_token(config.target, "down") || contains_token(config.target, "offline")) {
        result.reachable = false;
        result.timed_out = true;
        result.avg_latency_ms = -1.0;
        result.message = "mock ping timed out";
    } else {
        result.reachable = true;
        result.avg_latency_ms = static_cast<double>(std::hash<std::string_view>{}(config.target) % 200) / 10.0 + 5.0;
        result.message = "mock ping completed in safe stub mode";
    }
    return result;
}

PingOperationResult live_ping_operation(const PingConfig& config) {
#ifdef _WIN32
    WSADATA wsa_data{};
    const int wsa_started = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_started != 0) {
        return {
            .success = false,
            .persisted = false,
            .result = {false, false, 0.0, "winsock startup failed"},
            .message = "winsock-startup-failed"
        };
    }

    sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    if (InetPtonA(AF_INET, config.target.c_str(), &target_addr.sin_addr) != 1) {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* resolved = nullptr;
        const int resolve_result = getaddrinfo(config.target.c_str(), nullptr, &hints, &resolved);
        if (resolve_result != 0 || resolved == nullptr) {
            WSACleanup();
            return {
                .success = false,
                .persisted = false,
                .result = {false, false, 0.0, "target could not be resolved"},
                .message = "target-resolution-failed"
            };
        }
        target_addr = *reinterpret_cast<sockaddr_in*>(resolved->ai_addr);
        freeaddrinfo(resolved);
    }

    const HANDLE handle = IcmpCreateFile();
    if (handle == INVALID_HANDLE_VALUE) {
        WSACleanup();
        return {
            .success = false,
            .persisted = false,
            .result = {false, false, 0.0, "icmp handle could not be created"},
            .message = "icmp-handle-failed"
        };
    }

    const char payload[] = "netsentinel11";
    const DWORD reply_size = sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 64;
    std::vector<unsigned char> reply(reply_size);
    const DWORD timeout = static_cast<DWORD>(std::max<std::size_t>(1, config.timeout_ms));
    std::size_t replies = 0;
    double total_latency_ms = 0.0;
    bool any_timeout = false;
    std::string last_detail = "no reply";

    for (std::size_t i = 0; i < config.count; ++i) {
        std::fill(reply.begin(), reply.end(), static_cast<unsigned char>(0));
        const DWORD sent = IcmpSendEcho(
            handle,
            target_addr.sin_addr.S_un.S_addr,
            const_cast<char*>(payload),
            static_cast<WORD>(sizeof(payload)),
            nullptr,
            reply.data(),
            reply_size,
            timeout
        );
        if (sent > 0) {
            const auto* echo = reinterpret_cast<const ICMP_ECHO_REPLY*>(reply.data());
            if (echo->Status == IP_SUCCESS) {
                ++replies;
                total_latency_ms += static_cast<double>(echo->RoundTripTime);
                last_detail = "icmp reply received";
            } else if (echo->Status == IP_REQ_TIMED_OUT) {
                any_timeout = true;
                last_detail = "icmp request timed out";
            } else {
                last_detail = "icmp reply returned non-success status " + std::to_string(echo->Status);
            }
        } else {
            const DWORD error = GetLastError();
            any_timeout = any_timeout || error == IP_REQ_TIMED_OUT || error == ERROR_TIMEOUT;
            last_detail = "icmp send failed with error " + std::to_string(error);
        }
    }

    IcmpCloseHandle(handle);
    WSACleanup();

    PingResult result{};
    result.reachable = replies > 0;
    result.timed_out = !result.reachable && any_timeout;
    result.avg_latency_ms = replies > 0 ? total_latency_ms / static_cast<double>(replies) : -1.0;
    result.message = result.reachable
        ? "live ping completed: " + std::to_string(replies) + "/" + std::to_string(config.count) + " replies"
        : "live ping completed without reply: " + last_detail;
    append_history("ping", config.target, result.reachable ? "success" : "timeout", result.message);
    prune_history(128);
    return {
        .success = true,
        .persisted = true,
        .result = result,
        .message = "live-ping"
    };
#else
    (void)config;
    return {
        .success = false,
        .persisted = false,
        .result = {false, false, 0.0, "live ping unavailable on this platform"},
        .message = "live-ping-unavailable"
    };
#endif
}

TracerouteResult mock_traceroute(const TracerouteConfig& config) {
    TracerouteResult result;
    if (contains_token(config.destination, "down") || contains_token(config.destination, "offline")) {
        result.destination_reached = false;
        result.message = "mock traceroute destination unreachable";
        return result;
    }
    result.destination_reached = true;
    for (std::size_t hop = 1; hop <= 3 && hop <= config.max_hops; ++hop) {
        result.hops.push_back(TracerouteHop{
            .hop = hop,
            .address = std::string{"10.0.0."} + std::to_string(1 + hop),
            .latency_ms = 3.0 + static_cast<double>(hop)
        });
    }
    if (!result.hops.empty()) {
        result.hops.back().address = config.destination;
    }
    result.message = "mock traceroute completed in safe stub mode";
    return result;
}

TracerouteResult live_local_traceroute(const TracerouteConfig& config) {
    TracerouteResult result;
    PingConfig ping{};
    ping.mock_mode = false;
    ping.target = config.destination == "localhost" ? std::string{"127.0.0.1"} : config.destination;
    ping.count = 1;
    ping.timeout_ms = config.timeout_ms;

    const auto ping_result = run_ping(ping);
    if (!ping_result.success) {
        result.destination_reached = false;
        result.message = "live local traceroute could not run ping probe: " + ping_result.message;
        return result;
    }
    if (!ping_result.result.reachable) {
        result.destination_reached = false;
        result.message = "live local traceroute completed without an ICMP reply: " + ping_result.result.message;
        return result;
    }

    result.destination_reached = true;
    result.hops.push_back(TracerouteHop{
        .hop = 1,
        .address = ping.target,
        .latency_ms = ping_result.result.avg_latency_ms
    });
    result.message = "live local traceroute completed as a one-hop safe ICMP probe";
    return result;
}

DnsLookupResult mock_dns_lookup(const DnsLookupConfig& config) {
    DnsLookupResult result;
    if (is_invalid_resolver(config.resolver)) {
        result.resolved = false;
        result.message = "mock dns lookup rejected invalid resolver";
        return result;
    }
    if (config.reverse) {
        if (config.target == "127.0.0.1") {
            result.resolved = true;
            result.answers = {"localhost.localdomain"};
            result.message = "mock reverse lookup resolved localhost";
        } else if (contains_token(config.target, "8.8.8.8")) {
            result.resolved = true;
            result.answers = {"dns.google"};
            result.message = "mock reverse lookup resolved known DNS host";
        } else {
            result.resolved = false;
            result.message = "mock reverse lookup found no PTR record";
        }
        return result;
    }
    if (contains_token(config.target, "unknown") || contains_token(config.target, "down")) {
        result.resolved = false;
        result.message = "mock forward lookup failed";
        return result;
    }
    if (contains_token(config.target, "localhost")) {
        result.resolved = true;
        result.answers = {"127.0.0.1"};
        result.message = "mock forward lookup resolved localhost";
        return result;
    }
    result.resolved = true;
    result.answers = {config.target + ".mock"};
    result.message = "mock forward lookup resolved to synthetic address";
    return result;
}

DnsOperationResult live_dns_lookup_operation(const DnsLookupConfig& config) {
#ifdef _WIN32
    WSADATA wsa_data{};
    const int wsa_started = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_started != 0) {
        return {
            .success = false,
            .persisted = false,
            .result = {false, {}, "winsock startup failed"},
            .message = "winsock-startup-failed"
        };
    }

    DnsLookupResult result{};
    if (config.reverse) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        if (InetPtonA(AF_INET, config.target.c_str(), &address.sin_addr) != 1) {
            WSACleanup();
            return {
                .success = true,
                .persisted = true,
                .result = {false, {}, "reverse DNS target is not a valid IPv4 address"},
                .message = "live-dns-reverse-unresolved"
            };
        }

        char host[NI_MAXHOST]{};
        const int rc = getnameinfo(
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address),
            host,
            static_cast<DWORD>(sizeof(host)),
            nullptr,
            0,
            NI_NAMEREQD
        );
        result.resolved = rc == 0;
        if (result.resolved) {
            result.answers.push_back(host);
            result.message = "live reverse DNS resolved using Windows resolver";
        } else {
            result.message = "live reverse DNS returned no hostname";
        }
    } else {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* resolved = nullptr;
        const int rc = getaddrinfo(config.target.c_str(), nullptr, &hints, &resolved);
        if (rc == 0 && resolved != nullptr) {
            for (addrinfo* item = resolved; item != nullptr && result.answers.size() < config.max_records; item = item->ai_next) {
                char address_text[INET6_ADDRSTRLEN]{};
                void* raw_address = nullptr;
                if (item->ai_family == AF_INET) {
                    raw_address = &reinterpret_cast<sockaddr_in*>(item->ai_addr)->sin_addr;
                } else if (item->ai_family == AF_INET6) {
                    raw_address = &reinterpret_cast<sockaddr_in6*>(item->ai_addr)->sin6_addr;
                }
                if (raw_address != nullptr && InetNtopA(item->ai_family, raw_address, address_text, static_cast<DWORD>(sizeof(address_text))) != nullptr) {
                    const std::string answer = address_text;
                    if (std::find(result.answers.begin(), result.answers.end(), answer) == result.answers.end()) {
                        result.answers.push_back(answer);
                    }
                }
            }
            freeaddrinfo(resolved);
        }
        result.resolved = !result.answers.empty();
        result.message = result.resolved
            ? "live DNS resolved using Windows resolver"
            : "live DNS returned no addresses";
    }

    WSACleanup();
    const auto status = result.resolved ? "resolved" : "unresolved";
    append_history(config.reverse ? "dns-reverse" : "dns-forward", config.target, status, result.message);
    prune_history(128);
    return {
        .success = true,
        .persisted = true,
        .result = result,
        .message = config.reverse ? "live-dns-reverse" : "live-dns-forward"
    };
#else
    (void)config;
    return {
        .success = false,
        .persisted = false,
        .result = {false, {}, "live DNS unavailable on this platform"},
        .message = "live-dns-unavailable"
    };
#endif
}

DnsBenchmarkResult mock_dns_benchmark_resolver(
    const std::string& resolver,
    const std::vector<std::string>& queries,
    std::size_t samples
) {
    DnsBenchmarkResult result;
    result.resolver = resolver;
    if (samples == 0) {
        return result;
    }

    if (is_invalid_resolver(resolver)) {
        result.total_queries = queries.size() * samples;
        result.success_count = 0;
        result.failure_rate = 1.0;
        result.avg_latency_ms = -1.0;
        result.dnssec_available = false;
        result.recommendation = "avoid-this-resolver";
        return result;
    }

    std::size_t failures = 0;
    double latency_sum = 0.0;
    result.total_queries = queries.size() * samples;
    if (result.total_queries == 0) {
        result.total_queries = 1;
    }
    std::vector<double> latency_samples;
    for (std::size_t i = 0; i < queries.size(); ++i) {
        const auto& query = queries[i];
        const bool query_fail = contains_token(query, "offline") || contains_token(query, "bad");
        for (std::size_t sample = 0; sample < samples; ++sample) {
            if (query_fail) {
                ++failures;
            } else {
                ++result.success_count;
                const double latency = deterministic_latency_ms(resolver + "-" + query + "-" + std::to_string(sample));
                latency_sum += latency;
                latency_samples.push_back(latency);
            }
        }
    }
    result.failure_rate = static_cast<double>(failures) / static_cast<double>(result.total_queries);
    if (result.success_count == 0) {
        result.avg_latency_ms = -1.0;
    } else {
        result.avg_latency_ms = latency_sum / static_cast<double>(result.success_count);
    }
    result.dnssec_available = !contains_token(resolver, "nodnssec");
    if (result.failure_rate > 0.20) {
        result.recommendation = "avoid";
    } else if (result.avg_latency_ms < 70.0 && result.dnssec_available) {
        result.recommendation = "preferred";
    } else {
        result.recommendation = "acceptable";
    }
    result.consistency_score = compute_consistency_score(latency_samples);
    return result;
}

std::vector<std::string> dhcp_candidates_for_adapter(
    const DhcpAdapterSource& adapter
) {
    std::vector<std::string> candidates;
    const auto add_candidate = [&candidates](const std::string& value) {
        if (value.empty()) {
            return;
        }
        const auto it = std::find(candidates.begin(), candidates.end(), value);
        if (it == candidates.end()) {
            candidates.push_back(value);
        }
    };
    if (!adapter.gateway.empty()) {
        add_candidate(adapter.gateway);
    }
    if (!adapter.dhcp_server.empty()) {
        add_candidate(adapter.dhcp_server);
    }
    for (const auto& dns : adapter.dns_servers) {
        add_candidate(dns);
    }
    return candidates;
}

bool match_adapter_filter(
    const DhcpAdapterSource& adapter,
    std::string_view filter
) {
    if (filter.empty()) {
        return true;
    }
    if (adapter.adapter_id == filter) {
        return true;
    }
    if (adapter.interface_name == filter) {
        return true;
    }
    return false;
}

std::string wifi_connected_ssid(const std::vector<WifiNetworkInfo>& networks) {
    for (const auto& network : networks) {
        if (network.connected) {
            return network.ssid;
        }
    }
    return "";
}

bool is_weak_wifi_signal(const WifiNetworkInfo& network, int min_quality) {
    return network.signal_quality >= 0 && network.signal_quality < min_quality;
}

bool is_insecure_wifi_auth(const WifiNetworkInfo& network) {
    return contains_token(network.auth, "Open") || contains_token(network.auth, "WEP");
}

std::vector<int> sorted_channels_for_band(const std::vector<WifiNetworkInfo>& networks) {
    std::vector<int> channels;
    channels.reserve(networks.size());
    for (const auto& network : networks) {
        channels.push_back(network.channel);
    }
    std::sort(channels.begin(), channels.end());
    return channels;
}

std::size_t count_overlapping_channels(const std::vector<int>& channels) {
    std::size_t overlaps = 0;
    for (std::size_t i = 0; i < channels.size(); ++i) {
        for (std::size_t j = i + 1; j < channels.size(); ++j) {
            if (std::abs(channels[j] - channels[i]) <= 2) {
                ++overlaps;
                break;
            }
        }
    }
    return overlaps;
}

std::vector<int> select_port_profile(const std::string& preset, const std::vector<int>& custom_ports) {
    if (!custom_ports.empty()) {
        return custom_ports;
    }
    if (preset == "router") {
        return {53, 67, 68, 80, 443, 8080, 8443, 1900};
    }
    if (preset == "camera") {
        return {21, 22, 80, 554, 8080, 8443, 37777};
    }
    return {21, 22, 23, 25, 53, 80, 88, 443, 445, 554, 8080, 8443, 3389};
}

bool is_port_open_mock(const std::string& target, int port) {
    const auto hash = std::hash<std::string>{}(target + ":" + std::to_string(port));
    return (hash % 7) == 0 || (hash % 5) == 0;
}

std::string banner_for_port(int port) {
    switch (port) {
        case 21:
            return "FTP service ready";
        case 22:
            return "SSH-2.0";
        case 23:
            return "TELNET";
        case 53:
            return "DNS response";
        case 67:
        case 68:
            return "DHCP";
        case 80:
        case 443:
            return "HTTP service ready";
        case 554:
            return "RTSP/1.0";
        case 8080:
        case 8443:
            return "HTTP proxy";
        case 3389:
            return "RDP";
        case 445:
            return "SMB";
        default:
            return "TCP-OPEN";
    }
}

std::vector<int> router_profile_ports() {
    return {21, 22, 23, 53, 80, 443, 554, 1900, 5351, 7547, 8080, 8443};
}

std::string router_banner_for_port(int port) {
    switch (port) {
        case 21:
            return "FTP/1.1 Firmware v1.0.3";
        case 22:
            return "SSH-2.0";
        case 23:
            return "TELNET access";
        case 53:
            return "DNS/Router v1.0.3";
        case 80:
            return "HTTP/1.1 Admin Portal (Firmware v1.0.3)";
        case 443:
            return "HTTPS/1.1 TLSv1.0 Admin Portal Firmware v1.0.3";
        case 554:
            return "RTSP/1.0";
        case 1900:
            return "UPnP/1.0 Service (device discovery)";
        case 5351:
            return "NAT-PMP/1.0 UDP";
        case 7547:
            return "TR-069 CWMP firmware v1.0.3";
        case 8080:
            return "HTTP/1.1 legacy admin on 8080, TLSv1.1";
        case 8443:
            return "HTTPS/1.1 TLSv1.1 Admin API";
        default:
            return "TCP-OPEN";
    }
}

std::string service_for_port(int port);

std::string router_service_for_port(int port) {
    if (port == 1900) {
        return "upnp";
    }
    if (port == 5351) {
        return "nat-pmp";
    }
    if (port == 7547) {
        return "cwmp";
    }
    return service_for_port(port);
}

bool is_admin_service(const std::string& service, int port, const std::string& banner) {
    if (service == "http" || service == "https") {
        return true;
    }
    if (service == "upnp" || service == "nat-pmp" || service == "cwmp") {
        return true;
    }
    if (port == 80 || port == 443 || port == 8080 || port == 8443) {
        return true;
    }
    return contains_token(banner, "Admin");
}

bool is_weak_protocol_for_router(const std::string& service, const std::string& tls_version) {
    return service == "ftp" || service == "telnet" || service == "http" || (!tls_version.empty() && (tls_version == "TLSv1.0" || tls_version == "TLSv1.1"));
}

bool is_upnp_natpmp_service(const std::string& service) {
    return service == "upnp" || service == "nat-pmp" || service == "cwmp";
}

void append_management_guidance(std::vector<std::string>& guidance, const RouterPortExposure& mapping) {
    if (mapping.service == "upnp") {
        guidance.push_back(
            std::string{"Close UPnP exposure on UDP/"} +
            std::to_string(mapping.external_port) +
            " if auto-port forwarding is not required."
        );
        return;
    }
    if (mapping.service == "nat-pmp") {
        guidance.push_back(
            std::string{"Disable NAT-PMP control on UDP/"} +
            std::to_string(mapping.external_port) +
            " or limit it to trusted clients."
        );
        return;
    }
    if (mapping.service == "cwmp") {
        guidance.push_back(
            std::string{"Review TR-069 (CWMP) exposure on port "} +
            std::to_string(mapping.external_port) +
            " and disable remote management if unused."
        );
        return;
    }
    guidance.push_back(
        std::string{"Review mapping for service "} +
        mapping.service +
        " on external port " +
        std::to_string(mapping.external_port)
    );
}

std::string tls_from_banner(std::string_view banner) {
    if (contains_token(banner, "TLSv1.0")) {
        return "TLSv1.0";
    }
    if (contains_token(banner, "TLSv1.1")) {
        return "TLSv1.1";
    }
    if (contains_token(banner, "TLSv1.2")) {
        return "TLSv1.2";
    }
    if (contains_token(banner, "TLSv1.3")) {
        return "TLSv1.3";
    }
    if (contains_token(banner, "TLS")) {
        return "TLS";
    }
    return {};
}

bool is_outdated_tls(std::string_view tls) {
    return tls == "TLSv1.0" || tls == "TLSv1.1";
}

std::string firmware_from_banner(std::string_view banner) {
    const std::array<std::string_view, 3> known_firmware{
        "Firmware v1.0.3",
        "firmware v1.0.3",
        "v2.3.5"
    };
    for (const auto& value : known_firmware) {
        if (contains_token(banner, value)) {
            return std::string{value};
        }
    }
    return {};
}

void append_unique_finding(std::vector<RouterSecurityFinding>& findings, const RouterSecurityFinding& item) {
    const auto duplicate = std::find_if(
        findings.begin(),
        findings.end(),
        [&](const RouterSecurityFinding& existing) {
            return existing.title == item.title && existing.category == item.category;
        }
    );
    if (duplicate == findings.end()) {
        findings.push_back(item);
    }
}

std::vector<RouterCveCorrelation> cve_for_firmware(std::string_view firmware) {
    if (contains_token(firmware, "v1.0.3")) {
        return {
            {
                .component = "web-ui",
                .firmware = std::string{firmware},
                .cve = "CVE-2024-10001",
                .description = "Authentication bypass in legacy admin endpoint"
            },
            {
                .component = "tr069",
                .firmware = std::string{firmware},
                .cve = "CVE-2024-10002",
                .description = "Remote command execution in outdated CWMP implementation"
            }
        };
    }
    if (contains_token(firmware, "v2.3.5")) {
        return {
            {
                .component = "upnp",
                .firmware = std::string{firmware},
                .cve = "CVE-2023-33333",
                .description = "UPnP control endpoint allows unauthenticated access"
            }
        };
    }
    return {};
}

bool contains_port(const std::vector<int>& values, int port) {
    return std::find(values.begin(), values.end(), port) != values.end();
}

bool is_authorized_live_lan_target(std::string_view target) {
    return target.rfind("192.168.50.", 0) == 0 || target.rfind("192.168.1.", 0) == 0;
}

bool is_authorized_live_diagnostic_target(std::string_view target) {
    return target == "localhost" ||
        target == "127.0.0.1" ||
        target.rfind("127.", 0) == 0 ||
        is_authorized_live_lan_target(target);
}

bool tcp_connect_open(std::string_view target, int port, int timeout_ms) {
    if (target.empty() || port <= 0 || port > 65535 || timeout_ms <= 0) {
        return false;
    }
#ifdef _WIN32
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return false;
    }
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<u_short>(port));
    const auto target_text = std::string{target};
    if (inet_pton(AF_INET, target_text.c_str(), &address.sin_addr) != 1) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    u_long non_blocking = 1;
    ioctlsocket(sock, FIONBIO, &non_blocking);
    const int connect_result = connect(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (connect_result == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS && error != WSAEINVAL) {
            closesocket(sock);
            WSACleanup();
            return false;
        }
    }

    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);
    fd_set error_set;
    FD_ZERO(&error_set);
    FD_SET(sock, &error_set);
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    const int selected = select(0, nullptr, &write_set, &error_set, &timeout);
    bool open = false;
    if (selected > 0 && FD_ISSET(sock, &write_set)) {
        int socket_error = 0;
        int length = sizeof(socket_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error), &length) == 0) {
            open = socket_error == 0;
        }
    }
    closesocket(sock);
    WSACleanup();
    return open;
#else
    (void)target;
    (void)port;
    (void)timeout_ms;
    return false;
#endif
}

std::string service_for_port(int port) {
    if (port == 22 || port == 2222) {
        return "ssh";
    }
    if (port == 80 || port == 8080 || port == 8443 || port == 8888) {
        return "http";
    }
    if (port == 443 || port == 10443) {
        return "https";
    }
    if (port == 21 || port == 20 || port == 990) {
        return "ftp";
    }
    if (port == 23 || port == 2323) {
        return "telnet";
    }
    if (port == 53) {
        return "dns";
    }
    if (port == 3389) {
        return "rdp";
    }
    if (port == 445) {
        return "smb";
    }
    if (port == 554 || port == 37777) {
        return "rtsp";
    }
    if (port == 1883 || port == 8883) {
        return "mqtt";
    }
    if (port == 9100 || port == 515 || port == 631) {
        return "print";
    }
    return "unknown";
}

int confidence_from_port_and_banner(const std::string& service, const std::string& banner, bool has_banner) {
    if (service == "unknown") {
        return has_banner ? 55 : 30;
    }
    int confidence = 70;
    if (has_banner && !banner.empty()) {
        confidence = 85;
    }
    if (service == "http" && contains_token(banner, "HTTP")) {
        confidence = 98;
    }
    if (service == "https" && contains_token(banner, "HTTP")) {
        confidence = 95;
    }
    if (service == "ssh" && contains_token(banner, "SSH")) {
        confidence = 99;
    }
    if (service == "ftp" && contains_token(banner, "FTP")) {
        confidence = 95;
    }
    if (service == "rdp" && contains_token(banner, "RDP")) {
        confidence = 96;
    }
    if (service == "smb" && contains_token(banner, "SMB")) {
        confidence = 94;
    }
    if (service == "dns" && contains_token(banner, "DNS")) {
        confidence = 93;
    }
    if (service == "rtsp" && contains_token(banner, "RTSP")) {
        confidence = 95;
    }
    if (service == "mqtt" && contains_token(banner, "MQTT")) {
        confidence = 90;
    }
    return confidence;
}

std::string source_for_observation(bool has_banner, const std::string& service) {
    if (!has_banner) {
        return "port";
    }
    if (service == "unknown") {
        return "banner-heuristic";
    }
    return "banner";
}

std::string normalize_banner_for_output(std::string_view banner) {
    if (banner.empty()) {
        return "";
    }
    if (banner.size() > 80) {
        return std::string{banner.substr(0, 80)};
    }
    return std::string{banner};
}

void append_device_hint(std::vector<std::string>& hints, const std::string& hint) {
    if (hint.empty()) {
        return;
    }
    const auto it = std::find(hints.begin(), hints.end(), hint);
    if (it == hints.end()) {
        hints.push_back(hint);
    }
}

std::string to_lower_ascii(std::string_view text) {
    std::string out;
    out.resize(text.size());
    std::transform(text.begin(), text.end(), out.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return out;
}

bool contains_token_ci(std::string_view text, std::string_view token) {
    if (token.empty()) {
        return false;
    }
    return to_lower_ascii(text).find(to_lower_ascii(token)) != std::string::npos;
}

bool contains_any_token_ci(std::string_view text, std::initializer_list<std::string_view> tokens) {
    for (const auto token : tokens) {
        if (contains_token_ci(text, token)) {
            return true;
        }
    }
    return false;
}

std::string unescape_inventory_field(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        const char ch = value[i];
        if (ch != '\\' || i + 1 >= value.size()) {
            out.push_back(ch);
            continue;
        }
        const char next = value[++i];
        if (next == 'n') {
            out.push_back('\n');
        } else if (next == 'r') {
            out.push_back('\r');
        } else {
            out.push_back(next);
        }
    }
    return out;
}

std::vector<std::string> split_inventory_line(std::string_view line) {
    std::vector<std::string> fields;
    std::string current;
    bool escaped = false;
    for (const char ch : line) {
        if (escaped) {
            current.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '|') {
            fields.push_back(unescape_inventory_field(current));
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    fields.push_back(unescape_inventory_field(current));
    return fields;
}

std::vector<std::string> split_comma_list(std::string_view text) {
    std::vector<std::string> out;
    std::string token;
    for (const char ch : text) {
        if (ch == ',') {
            if (!token.empty()) {
                out.push_back(token);
            }
            token.clear();
            continue;
        }
        token.push_back(ch);
    }
    if (!token.empty()) {
        out.push_back(token);
    }
    return out;
}

bool parse_inventory_bool(std::string_view text) {
    return text == "1" || text == "true" || text == "yes";
}

int parse_inventory_int(std::string_view text, int fallback) {
    try {
        return std::stoi(std::string{text});
    } catch (...) {
        return fallback;
    }
}

std::vector<int> parse_camera_ports_from_details(std::string_view details) {
    std::vector<int> ports;
    const std::array<int, 8> camera_ports{554, 8554, 37777, 80, 443, 8080, 8443, 5000};
    for (const int port : camera_ports) {
        if (contains_token_ci(details, std::to_string(port))) {
            ports.push_back(port);
        }
    }
    return ports;
}

std::vector<CameraInventoryRecord> read_camera_inventory_records(
    const std::string& database_path,
    bool include_hidden
) {
    std::ifstream in{database_path};
    if (!in.is_open()) {
        return {};
    }

    std::vector<CameraInventoryRecord> records;
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("INV_DEVICE|", 0) != 0) {
            continue;
        }
        const auto fields = split_inventory_line(line);
        if (fields.size() != 13) {
            continue;
        }
        const bool hidden = parse_inventory_bool(fields[8]);
        if (hidden && !include_hidden) {
            continue;
        }
        records.push_back({
            .device_id = fields[1],
            .hostname = fields[2],
            .ip_addresses = split_comma_list(fields[3]),
            .mac_address = fields[4],
            .vendor_hint = fields[5],
            .device_type = fields[6],
            .user_labels = split_comma_list(fields[10]),
            .open_tcp_ports = parse_camera_ports_from_details(fields[11]),
            .importance = parse_inventory_int(fields[7], 0),
            .hidden = hidden,
            .details = fields[11]
        });
    }
    return records;
}

void add_camera_evidence(std::vector<std::string>& evidence, const std::string& reason, int& score, int delta) {
    if (!reason.empty()) {
        evidence.push_back(reason);
        score += delta;
    }
}

int collect_host_signals(
    const CameraInventoryRecord& record,
    std::vector<std::string>& evidence
) {
    int score = 0;
    if (contains_any_token_ci(record.vendor_hint, {"hikvision", "dahua", "axis", "foscam", "reolink", "ring", "arlo", "ezviz", "amcrest", "hik", "cisco", "tp-link", "tplink", "sony", "canon", "logi", "panasonic", "bosch"})) {
        add_camera_evidence(evidence, "vendor_hint suggests camera-focused hardware", score, 3);
    }
    if (contains_any_token_ci(record.device_type, {"camera", "ip-camera", "ipcam", "nvr", "dvr", "surveillance", "webcam", "doorbell", "cctv", "onvif"})) {
        add_camera_evidence(evidence, "device type indicates camera or video surveillance", score, 3);
    }
    if (contains_any_token_ci(record.hostname, {"cam", "camera", "ipcam", "stream", "nvr", "surveillance", "doorbell"})) {
        add_camera_evidence(evidence, "hostname contains camera indicator", score, 3);
    }
    for (const auto& label : record.user_labels) {
        if (contains_any_token_ci(label, {"camera", "cam", "nvr", "dvr", "ipcam", "doorbell", "doorbell-cam"})) {
            add_camera_evidence(evidence, "user label indicates camera role", score, 2);
            break;
        }
    }
    return score;
}

bool is_user_approved(const CameraInventoryRecord& record) {
    for (const auto& label : record.user_labels) {
        if (contains_token_ci(label, "approved") || contains_token_ci(label, "trusted") || contains_token_ci(label, "allow")) {
            return true;
        }
    }
    return false;
}

int collect_discovery_signals(
    const CameraInventoryRecord& record,
    bool include_mdns,
    bool include_ssdp,
    std::vector<std::string>& evidence
) {
    int score = 0;
    if (include_mdns && contains_any_token_ci(record.details, {"_rtsp", "_onvif", "_camera", "_media", "_ipcamera", "_webcam"})) {
        add_camera_evidence(evidence, "mDNS metadata contains camera-like service hints", score, 2);
    }
    if (include_ssdp && contains_any_token_ci(record.details, {"onvif", "ipcamera", "ip-camera", "nvr", "dvr", "webcam", "camera"})) {
        add_camera_evidence(evidence, "SSDP/UPnP metadata contains camera-like device hints", score, 3);
    }
    return score;
}

int collect_port_signals(
    const CameraInventoryRecord& record,
    std::vector<std::string>& evidence,
    std::vector<int>& exposed_ports
) {
    int score = 0;
    for (const auto port : record.open_tcp_ports) {
        if (port == 554 || port == 8554 || port == 37777) {
            exposed_ports.push_back(port);
            add_camera_evidence(evidence, "RTSP-like port detected", score, 4);
        }
        if (port == 80 || port == 443 || port == 8080 || port == 8443 || port == 5000) {
            exposed_ports.push_back(port);
            add_camera_evidence(evidence, "camera-management HTTP/HTTPS port detected", score, 1);
        }
    }
    if (contains_token_ci(record.details, "onvif")) {
        add_camera_evidence(evidence, "inventory metadata contains ONVIF marker", score, 3);
    }
    if (contains_token_ci(record.details, "rtsp")) {
        add_camera_evidence(evidence, "inventory metadata mentions RTSP stream control", score, 3);
    }
    std::sort(exposed_ports.begin(), exposed_ports.end());
    exposed_ports.erase(std::unique(exposed_ports.begin(), exposed_ports.end()), exposed_ports.end());
    return score;
}

std::string classify_camera_risk(int risk_score, bool approved) {
    if (approved) {
        return "known user-approved";
    }
    if (risk_score >= 7) {
        return "likely";
    }
    if (risk_score >= 3) {
        return "possible";
    }
    return "";
}

std::vector<std::string> sorted_unique_ips(const std::vector<std::string>& addresses) {
    auto out = addresses;
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<std::string> collect_inventory_scan_targets(
    const std::vector<CameraInventoryRecord>& records
) {
    std::vector<std::string> targets;
    for (const auto& record : records) {
        for (const auto& ip : record.ip_addresses) {
            if (!ip.empty()) {
                targets.push_back(ip);
            }
        }
    }
    return sorted_unique_ips(targets);
}

void append_unique_lines(std::vector<std::string>& out, const std::vector<std::string>& lines) {
    for (const auto& line : lines) {
        if (std::find(out.begin(), out.end(), line) == out.end()) {
            out.push_back(line);
        }
    }
}

void add_score_component(
    std::vector<SecurityScoreComponent>& components,
    std::string name,
    int penalty,
    int max_penalty,
    std::string status,
    std::string detail
) {
    components.push_back({
        .name = std::move(name),
        .penalty = std::clamp(penalty, 0, max_penalty),
        .max_penalty = max_penalty,
        .status = std::move(status),
        .detail = std::move(detail)
    });
}

bool has_approval_label(const CameraInventoryRecord& record) {
    for (const auto& label : record.user_labels) {
        if (contains_any_token_ci(label, {"approved", "trusted", "known", "family", "owned"})) {
            return true;
        }
    }
    return false;
}

std::string security_grade_for_score(int score) {
    if (score >= 90) {
        return "excellent";
    }
    if (score >= 75) {
        return "good";
    }
    if (score >= 60) {
        return "fair";
    }
    if (score >= 40) {
        return "poor";
    }
    return "critical";
}

std::size_t count_recent_history_command(std::string_view command_name, std::string_view bad_status) {
    std::size_t count = 0;
    for (const auto& item : read_diagnostics_history(128)) {
        if (item.command == command_name && (bad_status.empty() || contains_token_ci(item.status, bad_status))) {
            ++count;
        }
    }
    return count;
}


} // namespace

PingOperationResult run_ping(const PingConfig& config) {
    if (config.target.empty()) {
        return {
            .success = false,
            .persisted = false,
            .result = {false, false, 0.0, "missing target"},
            .message = "missing-target"
        };
    }
    if (config.count == 0 || config.timeout_ms == 0) {
        return {
            .success = false,
            .persisted = false,
            .result = {},
            .message = "invalid ping arguments"
        };
    }
    if (!config.mock_mode) {
        return live_ping_operation(config);
    }
    auto result = mock_ping(config);
    append_history("ping", config.target, result.reachable ? "success" : "timeout", result.message);
    prune_history(128);
    return {
        .success = true,
        .persisted = true,
        .result = result,
        .message = "mock-ping"
    };
}

TracerouteOperationResult run_traceroute(const TracerouteConfig& config) {
    if (config.destination.empty()) {
        return {
            .success = false,
            .persisted = false,
            .result = {},
            .message = "missing destination"
        };
    }
    if (config.max_hops == 0 || config.timeout_ms == 0) {
        return {
            .success = false,
            .persisted = false,
            .result = {},
            .message = "invalid traceroute arguments"
        };
    }
    if (!config.mock_mode && !is_authorized_live_diagnostic_target(config.destination)) {
        return {
            .success = false,
            .persisted = false,
            .result = {},
            .message = "live traceroute is limited to localhost, 192.168.50.*, and 192.168.1.* authorized targets"
        };
    }
    auto result = config.mock_mode ? mock_traceroute(config) : live_local_traceroute(config);
    append_history("traceroute", config.destination, result.destination_reached ? "reached" : "unreached", result.message);
    prune_history(128);
    return {
        .success = true,
        .persisted = true,
        .result = result,
        .message = config.mock_mode ? "mock-traceroute" : "live-local-traceroute"
    };
}

DnsOperationResult run_dns_lookup(const DnsLookupConfig& config) {
    if (config.target.empty()) {
        return {
            .success = false,
            .persisted = false,
            .result = {},
            .message = "missing target"
        };
    }
    if (config.max_records == 0) {
        return {
            .success = false,
            .persisted = false,
            .result = {},
            .message = "max-records must be greater than zero"
        };
    }
    if (!config.mock_mode) {
        return live_dns_lookup_operation(config);
    }
    auto result = mock_dns_lookup(config);
    const auto status = result.resolved ? "resolved" : "unresolved";
    append_history(config.reverse ? "dns-reverse" : "dns-forward", config.target, status, result.message);
    prune_history(128);
    return {
        .success = true,
        .persisted = true,
        .result = result,
        .message = config.reverse ? "mock-dns-reverse" : "mock-dns-forward"
    };
}

DnsBenchmarkOperationResult run_dns_benchmark(const DnsBenchmarkConfig& config) {
    if (config.resolvers.empty() && config.queries.empty()) {
        return {
            .success = false,
            .persisted = false,
            .results = {},
            .message = "missing resolvers and queries"
        };
    }
    if (!config.mock_mode) {
        return {
            .success = false,
            .persisted = false,
            .results = {},
            .message = "non-mock mode intentionally disabled in prompt 30; use --mock"
        };
    }
    if (config.samples == 0 || config.timeout_ms == 0) {
        return {
            .success = false,
            .persisted = false,
            .results = {},
            .message = "invalid benchmark arguments"
        };
    }

    std::vector<std::string> resolvers = config.resolvers;
    if (resolvers.empty()) {
        resolvers = {"8.8.8.8", "1.1.1.1"};
    }
    std::vector<std::string> queries = config.queries;
    if (queries.empty()) {
        queries = {"localhost", "example.com", "openai.com"};
    }

    std::vector<DnsBenchmarkResult> results;
    for (const auto& resolver : resolvers) {
        results.push_back(mock_dns_benchmark_resolver(resolver, queries, config.samples));
    }

    for (const auto& item : results) {
        append_history("dns-benchmark", item.resolver, item.recommendation, "avg_ms=" + std::to_string(item.avg_latency_ms));
    }
    prune_history(128);

    return {
        .success = true,
        .persisted = true,
        .results = results,
        .message = "mock-dns-benchmark"
    };
}

DhcpDiscoveryResult run_dhcp_discovery(const DhcpDiscoveryConfig& config) {
    DhcpDiscoveryResult out{
        .success = true,
        .persisted = true,
        .multiple_reply_detected = false,
        .adapters = {},
        .limitations = config.mock_mode
            ? "Mock mode: DHCP server inference from adapter gateway and DNS hints only."
            : "Live Windows adapter table only: no DHCP packets are sent, no leases are renewed, and no network configuration is changed.",
        .message = config.mock_mode ? "mock-dhcp-discovery" : "live-windows-dhcp-adapter-discovery"
    };

    const auto adapters = discover_adapters_for_dhcp(config.mock_mode);
    for (const auto& adapter : adapters) {
        if (!match_adapter_filter(adapter, config.adapter_filter)) {
            continue;
        }
        DhcpDiscoveryAdapterResult entry{
            .adapter_id = adapter.adapter_id,
            .interface_name = adapter.interface_name,
            .dhcp_enabled = adapter.dhcp_enabled
        };
        const auto candidates = dhcp_candidates_for_adapter(adapter);
        entry.observed_servers = candidates;
        if (!candidates.empty()) {
            entry.selected_server = candidates.front();
            entry.discovered_server = true;
            if (candidates.size() > 1 && config.allow_multiple_reply_check) {
                entry.multiple_responses_detected = true;
                out.multiple_reply_detected = true;
            }
        }
        if (!adapter.dhcp_enabled) {
            entry.message = "dhcp-disabled";
            append_history(
                "dhcp",
                adapter.adapter_id,
                "disabled",
                adapter.interface_name + " has DHCP disabled"
            );
        } else if (entry.discovered_server) {
            const auto status = entry.multiple_responses_detected ? "multiple" : "single";
            append_history("dhcp", adapter.adapter_id, status, "selected=" + entry.selected_server);
            if (entry.multiple_responses_detected) {
                entry.message = "multiple-responses-observed";
            } else {
                entry.message = "single-response";
            }
        } else {
            entry.message = "no-response-hint";
            append_history(
                "dhcp",
                adapter.adapter_id,
                "none",
                "no-dhcp-server-hint"
            );
        }
        out.adapters.push_back(std::move(entry));
    }

    prune_history(128);
    if (out.adapters.empty()) {
        out.message = "no-matching-adapters";
        return out;
    }
    return out;
}

WifiScanResult run_wifi_scan(const WifiScanConfig& config) {
    const auto collected = collect_wifi_scan_results(config.mock_mode);
    if (!collected.success) {
        return {
            .success = false,
            .persisted = false,
            .networks = {},
            .connected_ssid = "",
            .message = collected.message
        };
    }

    auto networks = collected.networks;
    if (!config.include_hidden) {
        networks.erase(
            std::remove_if(
                networks.begin(),
                networks.end(),
                [](const WifiNetworkInfo& item) {
                    return item.hidden;
                }
            ),
            networks.end()
        );
    }

    const auto connected = wifi_connected_ssid(networks);
    for (const auto& network : networks) {
        append_history("wifi-scan", network.ssid.empty() ? "<hidden>" : network.ssid, "seen", network.bssid + "-quality=" + std::to_string(network.signal_quality));
    }
    prune_history(128);

    return {
        .success = true,
        .persisted = true,
        .networks = std::move(networks),
        .connected_ssid = connected,
        .message = config.mock_mode
            ? (config.include_hidden ? "mock-wifi-scan-include-hidden" : "mock-wifi-scan")
            : collected.message
    };
}

WifiChannelAnalysisResult run_wifi_channel_analysis(const WifiScanConfig& config) {
    const auto scan = run_wifi_scan(config);
    if (!scan.success) {
        return {
            .success = false,
            .persisted = false,
            .total_networks = 0,
            .crowded_channels = 0,
            .weak_signal_count = 0,
            .insecure_network_count = 0,
            .band_summaries = {},
            .suggestions = {},
            .security_warnings = {},
            .history_snapshot = "",
            .message = scan.message
        };
    }

    if (scan.networks.empty()) {
        return {
            .success = true,
            .persisted = true,
            .total_networks = 0,
            .crowded_channels = 0,
            .weak_signal_count = 0,
            .insecure_network_count = 0,
            .band_summaries = {},
            .suggestions = {"No nearby Wi-Fi access points were observed by the selected scanner."},
            .security_warnings = {},
            .history_snapshot = "total=0,crowded=0,weak=0,insecure=0",
            .message = config.mock_mode ? "mock-wifi-analysis-empty" : "windows-wlan-analysis-empty"
        };
    }

    std::unordered_map<std::string, std::vector<WifiNetworkInfo>> by_band;
    for (const auto& network : scan.networks) {
        by_band[network.band].push_back(network);
    }

    std::size_t weak_signal_count = 0;
    std::size_t insecure_network_count = 0;
    std::size_t crowded_channels_total = 0;
    std::size_t band_24_count = 0;
    std::size_t modern_band_count = 0;
    std::vector<WifiChannelSummary> summaries;
    summaries.reserve(by_band.size());

    std::unordered_set<std::string> seen_warning;
    std::vector<WifiSecurityWarning> warnings;

    for (auto& entry : by_band) {
        auto& networks = entry.second;
        const auto& band = entry.first;
        WifiChannelSummary summary;
        summary.band = band;
        summary.network_count = networks.size();
        double signal_total = 0.0;
        for (const auto& network : networks) {
            signal_total += network.signal_quality;
            if (is_weak_wifi_signal(network, 50)) {
                ++weak_signal_count;
            }
            if (is_insecure_wifi_auth(network) || contains_token(network.cipher, "TKIP") || contains_token(network.cipher, "WEP")) {
                ++insecure_network_count;
                const auto key = network.ssid + "|" + network.bssid;
                if (seen_warning.insert(key).second) {
                    warnings.push_back({
                        .ssid = network.ssid.empty() ? "(hidden)" : network.ssid,
                        .bssid = network.bssid,
                        .reason = "Potentially weak security"
                    });
                }
            }
        }
        if (!networks.empty()) {
            summary.average_signal_quality = signal_total / static_cast<double>(networks.size());
        }
        const auto channels = sorted_channels_for_band(networks);
        summary.crowded_channels = count_overlapping_channels(channels);
        crowded_channels_total += summary.crowded_channels;
        if (contains_token(band, "2.4")) {
            band_24_count += networks.size();
        } else {
            modern_band_count += networks.size();
        }
        summaries.push_back(summary);
    }
    std::sort(summaries.begin(), summaries.end(), [](const auto& left, const auto& right){
        return left.band < right.band;
    });

    std::vector<std::string> suggestions;
    if (weak_signal_count > 0) {
        suggestions.push_back("Weak-signal APs detected; reduce obstacles or move closer for better link quality.");
    }
    if (crowded_channels_total > 0) {
        suggestions.push_back("Crowded channels detected; prefer less used channels where possible.");
    }
    if (modern_band_count >= band_24_count && modern_band_count > 0) {
        suggestions.push_back("Use 5/6GHz for higher throughput when compatible.");
    }
    if (band_24_count > modern_band_count) {
        suggestions.push_back("2.4GHz is dominant; consider 5/6GHz fallback when possible.");
    }
    if (insecure_network_count > 0) {
        suggestions.push_back("At least one AP uses weak authentication; avoid sensitive transfers on open/WEP networks.");
    }

    std::ostringstream snapshot;
    snapshot << "total=" << scan.networks.size() << ","
             << "crowded=" << crowded_channels_total << ","
             << "weak=" << weak_signal_count << ","
             << "insecure=" << insecure_network_count;
    for (const auto& summary : summaries) {
        snapshot << ","
                 << summary.band << ":count=" << summary.network_count
                 << ",avg_quality=" << summary.average_signal_quality
                 << ",overlap=" << summary.crowded_channels;
    }

    append_history("wifi-analysis", "scan", "ok", snapshot.str());
    prune_history(128);

    return {
        .success = true,
        .persisted = true,
        .total_networks = scan.networks.size(),
        .crowded_channels = crowded_channels_total,
        .weak_signal_count = weak_signal_count,
        .insecure_network_count = insecure_network_count,
        .band_summaries = std::move(summaries),
        .suggestions = std::move(suggestions),
        .security_warnings = std::move(warnings),
        .history_snapshot = snapshot.str(),
        .message = config.mock_mode ? "mock-wifi-analysis" : "windows-wlan-analysis"
    };
}

int wifi_channel_overlap_count(const WifiNetworkInfo& target, const std::vector<WifiNetworkInfo>& networks) {
    if (target.channel <= 0) {
        return 0;
    }
    int count = 0;
    for (const auto& other : networks) {
        if (&other == &target) {
            continue;
        }
        if (!target.bssid.empty() && target.bssid == other.bssid) {
            continue;
        }
        if (target.band != other.band || other.channel <= 0) {
            continue;
        }
        const int distance = std::abs(target.channel - other.channel);
        if (target.band == "2.4GHz") {
            if (distance <= 2) {
                ++count;
            }
        } else if (distance == 0) {
            ++count;
        }
    }
    return count;
}

std::string wifi_overlap_severity(int overlap_count) {
    if (overlap_count <= 0) {
        return "clear";
    }
    if (overlap_count == 1) {
        return "low";
    }
    if (overlap_count <= 3) {
        return "medium";
    }
    return "high";
}

int observed_overlap_for_candidate(const std::vector<WifiNetworkInfo>& networks, std::string_view band, int channel) {
    int count = 0;
    for (const auto& network : networks) {
        if (network.band != band || network.channel <= 0) {
            continue;
        }
        const int distance = std::abs(channel - network.channel);
        if (band == "2.4GHz") {
            if (distance <= 2) {
                ++count;
            }
        } else if (distance == 0) {
            ++count;
        }
    }
    return count;
}

WifiChannelRecommendation make_candidate_recommendation(
    const std::vector<WifiNetworkInfo>& networks,
    std::string_view band,
    const std::vector<int>& candidate_channels
) {
    WifiChannelRecommendation recommendation{};
    recommendation.band = std::string{band};
    recommendation.channel = candidate_channels.empty() ? 0 : candidate_channels.front();
    int best_count = std::numeric_limits<int>::max();
    for (const int channel : candidate_channels) {
        const int count = observed_overlap_for_candidate(networks, band, channel);
        if (count < best_count) {
            best_count = count;
            recommendation.channel = channel;
        }
    }
    recommendation.severity = best_count <= 1 ? "info" : (best_count <= 3 ? "warning" : "attention");
    recommendation.reason = std::string{"Recommended "} + recommendation.band +
        " channel " + std::to_string(recommendation.channel) +
        " has " + std::to_string(std::max(0, best_count)) +
        " observed overlapping or co-channel access point(s).";
    return recommendation;
}

WifiEnvironmentView run_wifi_environment_view(const WifiScanConfig& config) {
    WifiEnvironmentView view{};
    view.safety_notes = {
        "Shows nearby Wi-Fi access points exposed by the Windows WLAN API or deterministic mock data.",
        "Does not identify nearby client devices, deauthenticate clients, require monitor mode, spoof ARP, or disrupt traffic.",
        "Channel recommendations are advisory and based on visible SSIDs/BSSIDs, channel, band, signal, and overlap only."
    };
    view.scan_source = config.mock_mode ? "mock" : "windows-wlan-api";

    const auto scan = run_wifi_scan(config);
    if (!scan.success) {
        view.success = false;
        view.persisted = false;
        view.message = scan.message;
        append_history("wifi-environment", view.scan_source, "failed", scan.message);
        prune_history(128);
        return view;
    }

    const auto analysis = run_wifi_channel_analysis(config);
    view.band_summaries = analysis.band_summaries;
    view.connected_ssid = scan.connected_ssid;

    for (const auto& network : scan.networks) {
        WifiEnvironmentNetwork item{};
        item.ssid = network.ssid.empty() ? "(hidden)" : network.ssid;
        item.bssid = network.bssid;
        item.channel = network.channel;
        item.band = network.band;
        item.rssi_dbm = network.rssi_dbm;
        item.signal_quality = network.signal_quality;
        item.auth = network.auth;
        item.cipher = network.cipher;
        item.connected = network.connected;
        item.hidden = network.hidden;
        item.overlap_count = wifi_channel_overlap_count(network, scan.networks);
        item.overlap_severity = wifi_overlap_severity(item.overlap_count);

        if (is_insecure_wifi_auth(network)) {
            item.recommendation = "Avoid open/WEP networks for sensitive traffic; prefer WPA2 or WPA3.";
        } else if (is_weak_wifi_signal(network, 50)) {
            item.recommendation = "Weak signal: move closer to the access point or improve mesh/AP placement.";
        } else if (item.overlap_count > 0) {
            item.recommendation = "Channel overlap detected; review recommended channels before changing router settings.";
        } else {
            item.recommendation = "No immediate channel or signal issue detected.";
        }
        view.networks.push_back(std::move(item));
    }

    if (!scan.networks.empty()) {
        view.channel_recommendations.push_back(make_candidate_recommendation(scan.networks, "2.4GHz", {1, 6, 11}));
        const std::vector<int> five_ghz_candidates{36, 40, 44, 48, 149, 153, 157, 161};
        view.channel_recommendations.push_back(make_candidate_recommendation(scan.networks, "5GHz", five_ghz_candidates));
    }

    append_history(
        "wifi-environment",
        view.scan_source,
        "ok",
        "networks=" + std::to_string(view.networks.size()) + ",recommendations=" + std::to_string(view.channel_recommendations.size())
    );
    prune_history(128);

    view.success = true;
    view.persisted = true;
    view.message = config.mock_mode
        ? "Mock Wi-Fi environment view generated safely."
        : "Windows WLAN Wi-Fi environment view generated safely.";
    return view;
}

std::string wifi_environment_markdown(const WifiEnvironmentView& view) {
    std::ostringstream out;
    out << "# Nearby Wi-Fi Environment View\n\n";
    out << "- Status: " << (view.success ? "ok" : "error") << "\n";
    out << "- Source: " << view.scan_source << "\n";
    out << "- Networks: " << view.networks.size() << "\n";
    out << "- Connected SSID: " << (view.connected_ssid.empty() ? "(none)" : view.connected_ssid) << "\n";
    out << "- Message: " << view.message << "\n";
    out << "\n## Networks\n";
    for (const auto& network : view.networks) {
        out << "- ssid=" << network.ssid
            << " bssid=" << (network.bssid.empty() ? "(none)" : network.bssid)
            << " band=" << network.band
            << " channel=" << network.channel
            << " rssi_dbm=" << network.rssi_dbm
            << " quality=" << network.signal_quality
            << " auth=" << network.auth
            << " overlap=" << network.overlap_count
            << " severity=" << network.overlap_severity
            << " connected=" << (network.connected ? "yes" : "no")
            << "\n";
        out << "  recommendation: " << network.recommendation << "\n";
    }
    out << "\n## Band summaries\n";
    for (const auto& summary : view.band_summaries) {
        out << "- band=" << summary.band
            << " networks=" << summary.network_count
            << " crowded_channels=" << summary.crowded_channels
            << " average_quality=" << summary.average_signal_quality
            << "\n";
    }
    out << "\n## Channel recommendations\n";
    for (const auto& recommendation : view.channel_recommendations) {
        out << "- band=" << recommendation.band
            << " channel=" << recommendation.channel
            << " severity=" << recommendation.severity
            << " reason=" << recommendation.reason
            << "\n";
    }
    out << "\n## Safety notes\n";
    for (const auto& note : view.safety_notes) {
        out << "- " << note << "\n";
    }
    return out.str();
}

WifiSweetSpotReport run_wifi_sweet_spot_logger(const WifiSweetSpotConfig& config) {
    WifiSweetSpotReport report{};
    report.limitations = {
        "Laptop-friendly measurement workflow: the user manually enters the room/location label.",
        "This stage records Wi-Fi signal observations only; it does not scan devices or probe networks.",
        "Native WLAN polling uses the Windows WLAN API when available; --mock remains available for deterministic tests."
    };

    if (config.location_label.empty()) {
        report.success = false;
        report.message = "A manual --location label is required for Wi-Fi sweet-spot logging.";
        return report;
    }
    WifiScanConfig scan_config{};
    scan_config.mock_mode = config.mock_mode;
    scan_config.include_hidden = config.include_hidden;
    const auto scan = run_wifi_scan(scan_config);
    if (!scan.success) {
        report.success = false;
        report.message = scan.message;
        return report;
    }

    int weakest_rssi = 0;
    double quality_total = 0.0;
    for (const auto& network : scan.networks) {
        WifiSweetSpotSample sample{};
        sample.location_label = config.location_label;
        sample.ssid = network.ssid.empty() ? "(hidden)" : network.ssid;
        sample.bssid = network.bssid;
        sample.rssi_dbm = network.rssi_dbm;
        sample.link_quality = network.signal_quality;
        sample.channel = network.channel;
        sample.band = network.band;
        sample.timestamp_utc = config.timestamp_utc;
        if (report.samples.empty() || network.rssi_dbm < weakest_rssi) {
            weakest_rssi = network.rssi_dbm;
        }
        quality_total += static_cast<double>(network.signal_quality);
        report.samples.push_back(std::move(sample));
    }

    if (!report.samples.empty()) {
        const auto average = quality_total / static_cast<double>(report.samples.size());
        WifiSweetSpotLocationSummary summary{};
        summary.location_label = config.location_label;
        summary.sample_count = report.samples.size();
        summary.average_quality = average;
        summary.weakest_rssi_dbm = weakest_rssi;
        summary.weak_spot = average < 55.0 || weakest_rssi <= -70;
        summary.recommendation = summary.weak_spot
            ? "Weak spot candidate: move laptop closer to AP, reduce obstacles, or add mesh coverage."
            : "Signal looks usable in this location.";
        report.summaries.push_back(summary);

        std::ostringstream chart;
        chart << config.location_label << " quality=" << average << " ";
        const int bars = static_cast<int>(std::max(1.0, std::min(10.0, average / 10.0)));
        for (int i = 0; i < bars; ++i) {
            chart << "#";
        }
        report.chart_lines.push_back(chart.str());
    }

    append_history("wifi-sweetspot", config.location_label, "logged", "samples=" + std::to_string(report.samples.size()));
    prune_history(128);

    report.success = true;
    report.persisted = true;
    report.message = "Wi-Fi sweet-spot samples logged for manual location label.";
    return report;
}

std::string wifi_sweet_spot_csv(const WifiSweetSpotReport& report) {
    std::ostringstream out;
    out << "timestamp_utc,location,ssid,bssid,rssi_dbm,link_quality,channel,band\n";
    for (const auto& sample : report.samples) {
        out << sample.timestamp_utc << ","
            << sample.location_label << ","
            << sample.ssid << ","
            << sample.bssid << ","
            << sample.rssi_dbm << ","
            << sample.link_quality << ","
            << sample.channel << ","
            << sample.band << "\n";
    }
    return out.str();
}

std::string wifi_sweet_spot_markdown(const WifiSweetSpotReport& report) {
    std::ostringstream out;
    out << "# Wi-Fi Sweet Spot Logger\n\n";
    out << "- Status: " << (report.success ? "ok" : "error") << "\n";
    out << "- Samples: " << report.samples.size() << "\n";
    out << "- Locations: " << report.summaries.size() << "\n";
    out << "- Message: " << report.message << "\n";
    out << "\n## Location summaries\n";
    for (const auto& summary : report.summaries) {
        out << "- location=" << summary.location_label
            << " samples=" << summary.sample_count
            << " average_quality=" << summary.average_quality
            << " weakest_rssi_dbm=" << summary.weakest_rssi_dbm
            << " weak_spot=" << (summary.weak_spot ? "yes" : "no")
            << "\n";
        out << "  recommendation: " << summary.recommendation << "\n";
    }
    out << "\n## Chart\n";
    for (const auto& line : report.chart_lines) {
        out << "- " << line << "\n";
    }
    out << "\n## Samples\n";
    for (const auto& sample : report.samples) {
        out << "- " << sample.timestamp_utc
            << " location=" << sample.location_label
            << " ssid=" << sample.ssid
            << " bssid=" << sample.bssid
            << " rssi=" << sample.rssi_dbm
            << " quality=" << sample.link_quality
            << " channel=" << sample.channel
            << " band=" << sample.band
            << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : report.limitations) {
        out << "- " << limitation << "\n";
    }
    return out.str();
}

PortScanResult run_port_scan(const PortScanConfig& config, const std::string& preset, const std::vector<int>& custom_ports) {
    if (config.concurrency == 0) {
        return {
            .success = false,
            .persisted = false,
            .results = {},
            .open_port_count = 0,
            .preset = preset,
            .message = "Invalid concurrency: must be greater than zero."
        };
    }

    std::vector<std::string> targets = config.targets;
    if (targets.empty() && config.mock_mode) {
        targets = {"192.168.1.1", "192.168.1.10", "192.168.1.20"};
    } else if (targets.empty()) {
        return {
            .success = false,
            .persisted = false,
            .results = {},
            .open_port_count = 0,
            .preset = preset,
            .message = "Real port scanning requires explicit --target values."
        };
    }
    if (!config.mock_mode) {
        for (const auto& target : targets) {
            if (!is_authorized_live_lan_target(target)) {
                return {
                    .success = false,
                    .persisted = false,
                    .results = {},
                    .open_port_count = 0,
                    .preset = preset,
                    .message = "Real port scanning is limited to authorized LAN targets 192.168.50.* and 192.168.1.*."
                };
            }
        }
    }
    const auto resolved_preset = custom_ports.empty() ? preset : "custom";
    const auto profile_ports = select_port_profile(preset, custom_ports);
    if (profile_ports.empty()) {
        return {
            .success = false,
            .persisted = false,
            .results = {},
            .open_port_count = 0,
            .preset = resolved_preset,
            .message = "No ports configured for scan."
        };
    }
    const auto effective_concurrency = std::min<std::size_t>(config.concurrency, std::size_t{128});

    const auto ports = profile_ports;
    std::vector<PortScanTarget> results;
    results.reserve(targets.size());
    std::size_t open_port_count = 0;

    for (const auto& target : targets) {
        PortScanTarget result{};
        result.address = target;
        std::vector<int> open_ports;
        std::vector<std::string> banners;
        for (std::size_t batch = 0; batch < ports.size(); batch += effective_concurrency) {
            const std::size_t end = std::min(batch + effective_concurrency, ports.size());
            for (std::size_t i = batch; i < end; ++i) {
                const auto port = ports[i];
                if (port <= 0 || port > 65535) {
                    continue;
                }
                const bool open = config.mock_mode
                    ? is_port_open_mock(target, port)
                    : tcp_connect_open(target, port, 700);
                if (open) {
                    ++open_port_count;
                    open_ports.push_back(port);
                    if (config.banner && config.mock_mode) {
                        banners.push_back(banner_for_port(port));
                    }
                }
            }
        }
        result.open_ports = std::move(open_ports);
        result.banners = std::move(banners);
        results.push_back(std::move(result));
        append_history("port-scan", target, "ok", "open=" + std::to_string(result.open_ports.size()));
    }

    prune_history(128);

    return {
        .success = true,
        .persisted = true,
        .results = std::move(results),
        .open_port_count = open_port_count,
        .preset = resolved_preset,
        .message = config.mock_mode ? "mock-port-scan" : "live-authorized-lan-port-scan"
    };
}

std::vector<DiagnosticHistoryPoint> read_diagnostics_history(std::size_t max_entries) {
    std::vector<DiagnosticHistoryPoint> out;
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
        std::array<std::string, 5> cols{};
        std::size_t cursor = 0;
        std::size_t index = 0;
        while (index < cols.size() - 1) {
            auto delim = item.find(',', cursor);
            if (delim == std::string::npos) {
                cols[index] = item.substr(cursor);
                break;
            }
            cols[index++] = item.substr(cursor, delim - cursor);
            cursor = delim + 1;
        }
        cols[cols.size() - 1] = item.substr(cursor);
        if (cols[4].empty() && cursor == item.size()) {
            continue;
        }
        out.push_back({
            .timestamp_utc = cols[0],
            .command = cols[1],
            .target = cols[2],
            .status = cols[3],
            .details = cols[4]
        });
    }
    return out;
}

RouterSecurityResult run_router_security_check(const RouterSecurityConfig& config) {
    if (!config.mock_mode) {
        return {
            .success = false,
            .persisted = false,
            .gateway = config.gateway,
            .upnp_exposed = false,
            .natpmp_exposed = false,
            .exposed_mappings = {},
            .findings = {},
            .weak_protocols = {},
            .tls_protocols = {},
            .cve_correlations = {},
            .risk_score = 0,
            .firmware_version = "",
            .message = "Router security check is currently mock-only; use --mock."
        };
    }

    const auto gateway = config.gateway.empty() ? std::string{"192.168.1.1"} : config.gateway;

    netsentinel::diagnostics::PortScanConfig scan_config{};
    scan_config.mock_mode = true;
    scan_config.targets = {gateway};
    scan_config.concurrency = 8;
    scan_config.banner = true;
    const auto scan = run_port_scan(scan_config, "router", router_profile_ports());
    if (!scan.success) {
        return {
            .success = false,
            .persisted = false,
            .gateway = gateway,
            .upnp_exposed = false,
            .natpmp_exposed = false,
            .exposed_mappings = {},
            .findings = {},
            .weak_protocols = {},
            .tls_protocols = {},
            .cve_correlations = {},
            .risk_score = 0,
            .firmware_version = "",
            .message = scan.message
        };
    }
    if (scan.results.empty()) {
        return {
            .success = false,
            .persisted = false,
            .gateway = gateway,
            .upnp_exposed = false,
            .natpmp_exposed = false,
            .exposed_mappings = {},
            .findings = {},
            .weak_protocols = {},
            .tls_protocols = {},
            .cve_correlations = {},
            .risk_score = 0,
            .firmware_version = "",
            .message = "No scan result for gateway in mock router check."
        };
    }

    const auto& raw_target = scan.results.front();
    std::vector<int> ports = raw_target.open_ports;
    std::vector<std::string> banners = raw_target.banners;

    for (const int port : router_profile_ports()) {
        if (!contains_port(ports, port)) {
            ports.push_back(port);
            banners.push_back(router_banner_for_port(port));
        }
    }

    RouterSecurityResult out{};
    out.success = true;
    out.persisted = true;
    out.gateway = gateway;

    int score = 0;

    for (std::size_t i = 0; i < ports.size(); ++i) {
        const int port = ports[i];
        const std::string service = router_service_for_port(port);
        const std::string banner = (i < banners.size()) ? banners[i] : router_banner_for_port(port);
        const std::string detail = "protocol=" + service;
        const auto protocol = (port == 1900 || port == 5351) ? "udp" : "tcp";
        const int external_port = port;
        const int internal_port = port;

        out.exposed_mappings.push_back({
            .protocol = protocol,
            .external_port = external_port,
            .internal_port = internal_port,
            .service = service,
            .detail = detail
        });

        if (port == 1900) {
            out.upnp_exposed = true;
            append_unique_finding(out.findings, {
                .category = "upnp",
                .severity = "high",
                .title = "UPnP control endpoint reachable",
                .detail = "UDP/1900 is reachable from LAN; review external exposure controls.",
                .risk_score = 28
            });
        }
        if (port == 5351) {
            out.natpmp_exposed = true;
            append_unique_finding(out.findings, {
                .category = "natpmp",
                .severity = "high",
                .title = "NAT-PMP control endpoint reachable",
                .detail = "UDP/5351 is reachable from LAN; map creation endpoints may be exposed.",
                .risk_score = 26
            });
        }
        if (is_admin_service(service, port, banner)) {
            append_unique_finding(out.findings, {
                .category = "admin-interface",
                .severity = "high",
                .title = "Administrative interface exposure",
                .detail = std::string{"Router exposes "} + service + " on port " + std::to_string(port),
                .risk_score = 40
            });
        }
    }

    for (std::size_t i = 0; i < ports.size(); ++i) {
        const int port = ports[i];
        const std::string service = router_service_for_port(port);
        const std::string banner = (i < banners.size()) ? banners[i] : router_banner_for_port(port);
        const auto tls_version = tls_from_banner(banner);
        if (!tls_version.empty()) {
            if (std::find(out.tls_protocols.begin(), out.tls_protocols.end(), tls_version) == out.tls_protocols.end()) {
                out.tls_protocols.push_back(tls_version);
            }
            if (is_outdated_tls(tls_version)) {
                append_unique_finding(out.findings, {
                    .category = "tls",
                    .severity = "medium",
                    .title = "Outdated TLS detected",
                    .detail = std::string{"Port "} + std::to_string(port) + " reports " + tls_version,
                    .risk_score = 18
                });
            }
        }

        if (is_weak_protocol_for_router(service, tls_version)) {
            if (std::find(out.weak_protocols.begin(), out.weak_protocols.end(), service) == out.weak_protocols.end()) {
                out.weak_protocols.push_back(service);
            }
            append_unique_finding(out.findings, {
                .category = "protocol",
                .severity = "medium",
                .title = "Weak protocol likely exposed",
                .detail = service + " should be restricted on router interface",
                .risk_score = 12
            });
        }

        if (out.firmware_version.empty()) {
            out.firmware_version = firmware_from_banner(banner);
            const auto cves = cve_for_firmware(out.firmware_version);
            out.cve_correlations.insert(out.cve_correlations.end(), cves.begin(), cves.end());
        }
    }

    for (const auto& item : out.findings) {
        score += item.risk_score;
    }
    for (const auto& cve : out.cve_correlations) {
        (void)cve;
        score += 35;
    }
    out.risk_score = std::clamp(score, 0, 100);

    append_history("router-security", gateway, out.risk_score >= 75 ? "high-risk" : "ok", "risk=" + std::to_string(out.risk_score) + ",findings=" + std::to_string(out.findings.size()));
    prune_history(128);

    if (out.findings.empty()) {
        append_unique_finding(out.findings, {
            .category = "safe",
            .severity = "low",
            .title = "No obvious router exposures",
            .detail = "No direct router risk indicators detected in mock mode.",
            .risk_score = 0
        });
        out.message = "mock-router-security-safe";
    } else {
        out.message = "mock-router-security";
    }
    return out;
}

RouterUpnpNatpmpManagementResult run_router_upnp_natpmp_management(const RouterUpnpNatpmpManagementConfig& config) {
    const auto gateway = config.gateway.empty() ? std::string{"192.168.1.1"} : config.gateway;
    const bool apply_requested = !config.dry_run;

    if (!config.mock_mode) {
        return {
            .success = false,
            .persisted = false,
            .gateway = gateway,
            .dry_run = config.dry_run,
            .confirm_required = apply_requested,
            .safe_api_available = false,
            .discovered_mappings = {},
            .removable_mappings = {},
            .guidance = {
                "UPnP/NAT-PMP management actions are currently mock-safe-only until a validated protocol layer is integrated."
            },
            .applied_mappings = {},
            .message = "UPnP/NAT-PMP management is mock-only; use --mock."
        };
    }

    RouterSecurityConfig security_config{};
    security_config.mock_mode = true;
    security_config.gateway = gateway;
    const auto security_result = run_router_security_check(security_config);
    if (!security_result.success) {
        return {
            .success = false,
            .persisted = false,
            .gateway = gateway,
            .dry_run = config.dry_run,
            .confirm_required = apply_requested,
            .safe_api_available = false,
            .discovered_mappings = {},
            .removable_mappings = {},
            .guidance = {},
            .applied_mappings = {},
            .message = security_result.message
        };
    }

    RouterUpnpNatpmpManagementResult out{};
    out.success = true;
    out.persisted = true;
    out.gateway = gateway;
    out.dry_run = config.dry_run;
    out.confirm_required = false;
    out.safe_api_available = true;

    for (const auto& mapping : security_result.exposed_mappings) {
        if (!is_upnp_natpmp_service(mapping.service)) {
            continue;
        }
        out.discovered_mappings.push_back(mapping);
        if (config.target_ports.empty() || contains_port(config.target_ports, mapping.external_port)) {
            out.removable_mappings.push_back(mapping);
            append_management_guidance(out.guidance, mapping);
        }
    }

    if (out.discovered_mappings.empty()) {
        out.guidance.push_back("No UPnP/NAT-PMP mappings were discovered on the gateway in mock profile.");
        out.message = "No UPnP/NAT-PMP mappings discovered.";
        append_history("router-upnp-management", gateway, "ok", "targets=0");
        prune_history(128);
        return out;
    }

    if (out.removable_mappings.empty()) {
        out.guidance.push_back("No selected mappings match the requested port filters.");
        out.message = "No selected UPnP/NAT-PMP mappings selected for action.";
        append_history("router-upnp-management", gateway, config.dry_run ? "dry-run" : "blocked", "targets=0,selected=0");
        prune_history(128);
        return out;
    }

    if (apply_requested) {
        out.confirm_required = !config.confirm;
        if (!config.confirm) {
            out.success = false;
            out.message = "Apply requested, but confirmation is missing. Re-run with --confirm to apply safe changes.";
            out.dry_run = true;
            append_history("router-upnp-management", gateway, "blocked", "targets=" + std::to_string(out.removable_mappings.size()) + ",need-confirm");
            prune_history(128);
            return out;
        }
        if (!out.safe_api_available) {
            out.success = false;
            out.message = "Safe deletion API not available in this environment.";
            out.dry_run = true;
            append_history("router-upnp-management", gateway, "blocked", "targets=" + std::to_string(out.removable_mappings.size()) + ",api-unsupported");
            prune_history(128);
            return out;
        }
        out.dry_run = false;
        out.applied_mappings = out.removable_mappings;
        out.message = "Apply accepted in mock mode; requested cleanup actions prepared for execution path.";
        append_history("router-upnp-management", gateway, "applied", "targets=" + std::to_string(out.applied_mappings.size()));
        prune_history(128);
        return out;
    }

    out.dry_run = true;
    out.message = "Read-only management view prepared. Re-run with --apply and --confirm to request non-destructive cleanup actions.";
    append_history("router-upnp-management", gateway, "dry-run", "targets=" + std::to_string(out.removable_mappings.size()) + ",selected=" + std::to_string(out.removable_mappings.size()));
    prune_history(128);
    return out;
}

ServiceIdentificationResult run_service_identification(const PortScanConfig& config, const std::string& preset, const std::vector<int>& custom_ports) {
    auto port_result = run_port_scan(config, preset, custom_ports);
    if (!port_result.success) {
        return {
            .success = false,
            .persisted = false,
            .observations = {},
            .device_hints = {},
            .message = port_result.message
        };
    }

    std::vector<ServiceObservation> observations;
    std::vector<std::string> hints;

    for (const auto& target : port_result.results) {
        for (std::size_t i = 0; i < target.open_ports.size(); ++i) {
            const int port = target.open_ports[i];
            const std::string service = service_for_port(port);
            const std::string banner = (i < target.banners.size()) ? target.banners[i] : "";
            const bool has_banner = !banner.empty();
            const int confidence = confidence_from_port_and_banner(service, banner, has_banner);
            observations.push_back({
                .target = target.address,
                .port = port,
                .protocol = "tcp",
                .service = service,
                .confidence_percent = confidence,
                .source = source_for_observation(has_banner, service),
                .detail = normalize_banner_for_output(banner),
                .observed_at_utc = now_utc_iso8601()
            });

            if (service == "http" || service == "https") {
                append_device_hint(hints, "web-capable");
            }
            if (service == "ssh") {
                append_device_hint(hints, "admin-interface");
            }
            if (service == "rdp") {
                append_device_hint(hints, "remote-desktop");
            }
            if (service == "print") {
                append_device_hint(hints, "printer");
            }
            if (service == "rtsp") {
                append_device_hint(hints, "camera");
            }
        }
    }

    append_history("service-id", "port-scan", "ok", "observations=" + std::to_string(observations.size()));
    prune_history(128);

    return {
        .success = true,
        .persisted = true,
        .observations = std::move(observations),
        .device_hints = std::move(hints),
        .message = config.mock_mode ? "mock-service-identification" : "live-authorized-lan-service-identification"
    };
}

std::string camera_privacy_join_evidence(const std::vector<std::string>& values) {
    std::ostringstream oss;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            oss << " ";
        }
        oss << values[index];
    }
    return oss.str();
}

bool camera_privacy_has_port(const HiddenCameraFinding& finding, int port) {
    return std::find(finding.exposed_ports.begin(), finding.exposed_ports.end(), port) != finding.exposed_ports.end();
}

bool camera_record_is_unknown_iot(const CameraInventoryRecord& record) {
    const std::string identity = record.hostname + " " + record.vendor_hint + " " + record.device_type + " " + record.details;
    if (contains_any_token_ci(identity, {"camera", "cam", "webcam", "ip-camera", "onvif", "rtsp", "nvr", "dvr", "doorbell"})) {
        return false;
    }
    if (contains_any_token_ci(identity, {"laptop", "desktop", "pc", "nas", "storage", "printer", "scanner", "phone", "iphone", "ipad", "tablet", "vehicle", "tesla", "router", "gateway", "dns"})) {
        return false;
    }
    if (contains_any_token_ci(identity, {"iot", "tuya", "espressif", "shelly", "smart", "sensor", "plug", "bulb", "switch", "esp", "matter", "zigbee"})) {
        return true;
    }
    return contains_any_token_ci(
        record.hostname + " " + record.device_type,
        {"unknown"}
    );
}

std::string camera_checklist_category(const std::string& classification) {
    if (classification == "likely") {
        return "likely cameras";
    }
    if (classification == "possible") {
        return "possible cameras";
    }
    if (classification == "unknown IoT") {
        return "unknown IoT";
    }
    if (classification == "known user-approved") {
        return "known/approved cameras";
    }
    return "manual review";
}

int camera_confidence_percent(int risk_score, const std::string& classification, bool approved) {
    if (approved) {
        return 95;
    }
    if (classification == "unknown IoT") {
        return 35;
    }
    int confidence = 20 + (risk_score * 8);
    if (classification == "likely" && confidence < 75) {
        confidence = 75;
    }
    if (classification == "possible" && confidence < 45) {
        confidence = 45;
    }
    if (confidence > 95) {
        confidence = 95;
    }
    if (confidence < 0) {
        confidence = 0;
    }
    return confidence;
}

std::vector<std::string> camera_false_positive_warnings(const HiddenCameraFinding& finding) {
    std::vector<std::string> warnings;
    const std::string identity = finding.hostname + " " + finding.vendor_hint + " " + finding.device_type;
    const std::string evidence_text = camera_privacy_join_evidence(finding.evidence);
    const bool has_rtsp_or_onvif = camera_privacy_has_port(finding, 554) ||
        camera_privacy_has_port(finding, 8554) ||
        contains_any_token_ci(evidence_text, {"rtsp", "onvif"});
    const bool has_http_only = (camera_privacy_has_port(finding, 80) ||
        camera_privacy_has_port(finding, 443) ||
        camera_privacy_has_port(finding, 8080) ||
        camera_privacy_has_port(finding, 8443) ||
        camera_privacy_has_port(finding, 5000)) && !has_rtsp_or_onvif;

    if (contains_any_token_ci(identity, {"printer", "scanner", "officejet", "laserjet"})) {
        warnings.push_back("Printer/scanner devices can expose web management ports that look camera-like.");
    }
    if (contains_any_token_ci(identity, {"nas", "storage", "synology", "qnap"})) {
        warnings.push_back("NAS/storage devices may run media or surveillance services without being hidden cameras.");
    }
    if (contains_any_token_ci(identity, {"router", "gateway", "ap", "access point", "asus"})) {
        warnings.push_back("Routers and access points often expose HTTP/HTTPS management interfaces.");
    }
    if (contains_any_token_ci(identity, {"tv", "chromecast", "roku", "media", "speaker"})) {
        warnings.push_back("Media devices can advertise streaming-related services that are not cameras.");
    }
    if (contains_any_token_ci(identity, {"phone", "iphone", "ipad", "tablet", "android"})) {
        warnings.push_back("Phones and tablets may use randomized names or media services; confirm physically before flagging.");
    }
    if (has_http_only) {
        warnings.push_back("Only HTTP/HTTPS management ports were seen; no RTSP or ONVIF evidence was found.");
    }
    if (finding.risk_score < 7 && finding.classification != "unknown IoT") {
        warnings.push_back("Evidence score is moderate; treat this as a prompt for manual review, not proof.");
    }
    return warnings;
}

std::vector<std::string> camera_recommended_checks(const std::string& classification, bool rental_mode, bool approved) {
    std::vector<std::string> checks;
    checks.push_back("Do not connect to private streams or try default credentials.");
    checks.push_back("Physically identify the device owner, location, and visible purpose before escalating.");
    checks.push_back("Label known devices in the inventory so future scans reduce false positives.");
    if (rental_mode) {
        checks.push_back("Rental workflow: inspect private spaces, ask the host/property owner for device purpose, and document findings.");
    }
    if (classification == "likely") {
        checks.push_back("Likely camera: confirm whether the device is expected and whether it is allowed in this location.");
    } else if (classification == "possible") {
        checks.push_back("Possible camera: verify vendor/model and check whether the open services match a non-camera device.");
    } else if (classification == "unknown IoT") {
        checks.push_back("Unknown IoT: identify the device before assuming it is safe or unsafe.");
    }
    if (approved) {
        checks.push_back("User-approved device: keep the approval note current and revisit if the device moves location.");
    }
    return checks;
}

std::vector<std::string> build_camera_checklist_report(const HiddenCameraDetectorResult& result) {
    std::vector<std::string> lines;
    lines.push_back("Privacy mode: metadata-only checklist. No streams, credentials, or default-password checks are used.");
    lines.push_back("Likely cameras: " + std::to_string(result.likely_camera_count));
    lines.push_back("Possible cameras: " + std::to_string(result.possible_camera_count));
    lines.push_back("Unknown IoT: " + std::to_string(result.unknown_iot_count));
    lines.push_back("False-positive warnings: " + std::to_string(result.false_positive_warning_count));
    for (const auto& finding : result.findings) {
        lines.push_back(
            finding.checklist_category + ": " + finding.device_id + " (" + finding.classification +
            ", confidence " + std::to_string(finding.confidence_percent) + "%)"
        );
        for (const auto& warning : finding.false_positive_warnings) {
            lines.push_back("warning: " + finding.device_id + ": " + warning);
        }
    }
    return lines;
}
HiddenCameraDetectorResult run_hidden_camera_detector(const HiddenCameraDetectorConfig& config) {
    HiddenCameraDetectorResult result;
    const bool explicit_storage_path = !config.storage_db_path.empty();

    if (!config.mock_mode && !explicit_storage_path) {
        result.success = false;
        result.persisted = false;
        result.storage_db_path = config.storage_db_path;
        result.message = "Hidden camera privacy detector needs an authorized inventory database path for non-mock mode.";
        result.limitations.push_back("Non-mock mode is metadata-only and requires --db from an authorized local scan; no live probing is started automatically.");
        result.limitations.push_back("Privacy mode blocks stream access, credential attempts, exploit payloads, and default-password checks.");
        return result;
    }

    const std::string storage_db_path = explicit_storage_path ? config.storage_db_path : std::string{"netsentinel11_storage.db"};
    result.storage_db_path = storage_db_path;

    const auto records = read_camera_inventory_records(storage_db_path, false);
    if (records.empty()) {
        result.success = true;
        result.persisted = true;
        result.message = config.mock_mode ? "mock-hidden-camera-no-inventory" : "inventory-hidden-camera-no-records";
        result.limitations.push_back("No visible inventory records were available for hidden-camera checklist scoring.");
        result.limitations.push_back("Privacy mode is metadata-only; no streams, credentials, brute force, or exploit payloads are used.");
        result.checklist_report = build_camera_checklist_report(result);
        append_history("hidden-camera", storage_db_path, "none", "count=0");
        prune_history(128);
        return result;
    }

    for (const auto& record : records) {
        std::vector<std::string> evidence;
        std::vector<int> exposed_ports;
        int risk_score = collect_host_signals(record, evidence);
        risk_score += collect_discovery_signals(record, config.include_mdns, config.include_ssdp, evidence);
        if (config.include_port_hints) {
            risk_score += collect_port_signals(record, evidence, exposed_ports);
        }

        const bool approved = is_user_approved(record);
        std::string classification = classify_camera_risk(risk_score, approved);
        if (classification.empty() && config.include_unknown_iot && camera_record_is_unknown_iot(record)) {
            classification = "unknown IoT";
            if (risk_score < 2) {
                risk_score = 2;
            }
            add_camera_evidence(evidence, "unknown IoT identity requires owner confirmation", risk_score, 0);
        }
        if (classification.empty()) {
            continue;
        }

        std::sort(evidence.begin(), evidence.end());
        evidence.erase(std::unique(evidence.begin(), evidence.end()), evidence.end());
        std::sort(exposed_ports.begin(), exposed_ports.end());
        exposed_ports.erase(std::unique(exposed_ports.begin(), exposed_ports.end()), exposed_ports.end());

        HiddenCameraFinding finding;
        finding.device_id = record.device_id;
        finding.hostname = record.hostname;
        finding.ip_address = record.ip_addresses.empty() ? std::string{} : record.ip_addresses.front();
        finding.vendor_hint = record.vendor_hint;
        finding.device_type = record.device_type;
        finding.classification = classification;
        finding.risk_score = risk_score;
        finding.user_approved = approved;
        finding.checklist_category = camera_checklist_category(classification);
        finding.confidence_percent = camera_confidence_percent(risk_score, classification, approved);
        finding.exposed_ports = std::move(exposed_ports);
        finding.evidence = std::move(evidence);
        finding.false_positive_warnings = camera_false_positive_warnings(finding);
        finding.recommended_checks = camera_recommended_checks(classification, config.rental_mode, approved);

        if (classification == "likely") {
            ++result.likely_camera_count;
        } else if (classification == "possible") {
            ++result.possible_camera_count;
        } else if (classification == "unknown IoT") {
            ++result.unknown_iot_count;
        }
        result.false_positive_warning_count += finding.false_positive_warnings.size();
        result.findings.push_back(std::move(finding));
    }

    result.success = true;
    result.persisted = true;
    result.message = config.mock_mode ? "mock-hidden-camera-privacy-checklist" : "inventory-hidden-camera-privacy-checklist";
    result.limitations.push_back("Privacy mode: metadata-only; no stream connection, credential attempt, default-password check, brute force, or exploit payload is performed.");
    result.limitations.push_back("Rental workflow is checklist guidance and cannot prove a hidden camera is present.");
    if (!config.include_mdns) {
        result.limitations.push_back("mDNS hints were disabled by configuration.");
    }
    if (!config.include_ssdp) {
        result.limitations.push_back("SSDP hints were disabled by configuration.");
    }
    if (!config.include_port_hints) {
        result.limitations.push_back("Port hints were disabled by configuration.");
    }
    if (result.findings.empty()) {
        result.limitations.push_back("No likely cameras, possible cameras, or unknown IoT devices were identified from available metadata.");
    }

    result.checklist_report = build_camera_checklist_report(result);
    append_history("hidden-camera", storage_db_path, result.findings.empty() ? "none" : "found", "count=" + std::to_string(result.findings.size()));
    prune_history(128);
    return result;
}

std::string hidden_camera_detector_markdown(const HiddenCameraDetectorResult& result) {
    std::ostringstream oss;
    oss << "# Hidden Camera Privacy Checklist\n\n";
    oss << "Privacy mode: metadata-only. Do not connect to private streams or try default credentials.\n\n";
    oss << "- Success: " << (result.success ? "yes" : "no") << "\n";
    oss << "- Storage DB: " << result.storage_db_path << "\n";
    oss << "- Likely cameras: " << result.likely_camera_count << "\n";
    oss << "- Possible cameras: " << result.possible_camera_count << "\n";
    oss << "- Unknown IoT: " << result.unknown_iot_count << "\n";
    oss << "- False-positive warnings: " << result.false_positive_warning_count << "\n";
    oss << "- Message: " << result.message << "\n\n";

    oss << "## Checklist Summary\n\n";
    if (result.checklist_report.empty()) {
        oss << "- No checklist findings were generated.\n";
    } else {
        for (const auto& line : result.checklist_report) {
            oss << "- " << line << "\n";
        }
    }

    oss << "\n## Findings\n\n";
    if (result.findings.empty()) {
        oss << "No likely cameras, possible cameras, or unknown IoT devices were identified from available metadata.\n";
    }
    for (const auto& finding : result.findings) {
        oss << "### " << finding.device_id << "\n\n";
        oss << "- Category: " << finding.checklist_category << "\n";
        oss << "- Classification: " << finding.classification << "\n";
        oss << "- Confidence: " << finding.confidence_percent << "%\n";
        oss << "- Risk score: " << finding.risk_score << "\n";
        oss << "- User approved: " << (finding.user_approved ? "yes" : "no") << "\n";
        oss << "- Host: " << finding.hostname << "\n";
        oss << "- IP: " << finding.ip_address << "\n";
        oss << "- Vendor: " << finding.vendor_hint << "\n";
        oss << "- Type: " << finding.device_type << "\n";
        if (!finding.exposed_ports.empty()) {
            oss << "- Ports:";
            for (const int port : finding.exposed_ports) {
                oss << " " << port;
            }
            oss << "\n";
        }
        if (!finding.evidence.empty()) {
            oss << "- Evidence:\n";
            for (const auto& item : finding.evidence) {
                oss << "  - " << item << "\n";
            }
        }
        if (!finding.false_positive_warnings.empty()) {
            oss << "- False-positive warnings:\n";
            for (const auto& warning : finding.false_positive_warnings) {
                oss << "  - " << warning << "\n";
            }
        }
        if (!finding.recommended_checks.empty()) {
            oss << "- Recommended checks:\n";
            for (const auto& check : finding.recommended_checks) {
                oss << "  - " << check << "\n";
            }
        }
        oss << "\n";
    }

    if (!result.limitations.empty()) {
        oss << "## Limitations\n\n";
        for (const auto& limitation : result.limitations) {
            oss << "- " << limitation << "\n";
        }
    }
    return oss.str();
}

struct DeviceLifecycleCatalogEntry {
    std::string vendor;
    std::string device_type;
    std::string model;
    std::vector<std::string> model_tokens;
    std::string status;
    std::string source;
    std::string notes;
    int confidence_percent = 0;
    int first_seen_year = 0;
    int eol_year = 0;
};

std::string lifecycle_json_string(const std::string& object, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    const auto key_pos = object.find(needle);
    if (key_pos == std::string::npos) {
        return {};
    }
    const auto colon = object.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return {};
    }
    const auto start = object.find('"', colon + 1);
    if (start == std::string::npos) {
        return {};
    }
    std::string out;
    bool escaped = false;
    for (std::size_t i = start + 1; i < object.size(); ++i) {
        const char ch = object[i];
        if (escaped) {
            out.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            break;
        }
        out.push_back(ch);
    }
    return out;
}

int lifecycle_json_int(const std::string& object, const std::string& key, int fallback = 0) {
    const std::string needle = "\"" + key + "\"";
    const auto key_pos = object.find(needle);
    if (key_pos == std::string::npos) {
        return fallback;
    }
    const auto colon = object.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return fallback;
    }
    auto pos = colon + 1;
    while (pos < object.size() && std::isspace(static_cast<unsigned char>(object[pos]))) {
        ++pos;
    }
    bool negative = false;
    if (pos < object.size() && object[pos] == '-') {
        negative = true;
        ++pos;
    }
    int value = 0;
    bool saw_digit = false;
    while (pos < object.size() && std::isdigit(static_cast<unsigned char>(object[pos]))) {
        saw_digit = true;
        value = (value * 10) + (object[pos] - '0');
        ++pos;
    }
    if (!saw_digit) {
        return fallback;
    }
    return negative ? -value : value;
}

std::vector<std::string> lifecycle_json_string_array(const std::string& object, const std::string& key) {
    std::vector<std::string> values;
    const std::string needle = "\"" + key + "\"";
    const auto key_pos = object.find(needle);
    if (key_pos == std::string::npos) {
        return values;
    }
    const auto open = object.find('[', key_pos + needle.size());
    const auto close = object.find(']', open == std::string::npos ? key_pos : open);
    if (open == std::string::npos || close == std::string::npos || close <= open) {
        return values;
    }
    std::size_t pos = open + 1;
    while (pos < close) {
        const auto start = object.find('"', pos);
        if (start == std::string::npos || start >= close) {
            break;
        }
        const auto end = object.find('"', start + 1);
        if (end == std::string::npos || end > close) {
            break;
        }
        values.push_back(object.substr(start + 1, end - start - 1));
        pos = end + 1;
    }
    return values;
}

std::vector<std::string> lifecycle_extract_json_objects(const std::string& json) {
    std::vector<std::string> objects;
    std::vector<std::size_t> starts;
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (std::size_t i = 0; i < json.size(); ++i) {
        const char ch = json[i];
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }
        if (ch == '"') {
            in_string = true;
            continue;
        }
        if (ch == '{') {
            starts.push_back(i);
            ++depth;
        } else if (ch == '}') {
            if (starts.empty()) {
                continue;
            }
            const std::size_t start = starts.back();
            starts.pop_back();
            --depth;
            objects.push_back(json.substr(start, i - start + 1));
        }
    }
    return objects;
}

std::vector<DeviceLifecycleCatalogEntry> lifecycle_builtin_catalog() {
    return {
        {
            .vendor = "ASUS",
            .device_type = "router",
            .model = "RT-AC68U family",
            .model_tokens = {"rt-ac68u", "rt-ac66u", "asuswrt"},
            .status = "likely_eol",
            .source = "manual-curated: vendor support pages should be checked by the user",
            .notes = "Older router families often need firmware review or replacement planning.",
            .confidence_percent = 70,
            .first_seen_year = 2013,
            .eol_year = 2024
        },
        {
            .vendor = "Hikvision",
            .device_type = "camera",
            .model = "DS-2CD legacy camera family",
            .model_tokens = {"ds-2cd", "hikvision", "ip-camera"},
            .status = "outdated",
            .source = "manual-curated: common legacy IP-camera family pattern",
            .notes = "Camera firmware age should be verified against the exact model support page.",
            .confidence_percent = 65,
            .first_seen_year = 2016,
            .eol_year = 2023
        },
        {
            .vendor = "Apple",
            .device_type = "tablet",
            .model = "generic tablet lifecycle",
            .model_tokens = {"ipad"},
            .status = "monitor",
            .source = "manual-curated: generic device-age guidance",
            .notes = "Exact OS support depends on model generation; verify in device settings.",
            .confidence_percent = 45,
            .first_seen_year = 2019,
            .eol_year = 0
        },
        {
            .vendor = "Raspberry Pi",
            .device_type = "dns",
            .model = "Pi-hole host",
            .model_tokens = {"pihole", "pi-hole", "raspberry"},
            .status = "monitor",
            .source = "manual-curated: software host lifecycle depends on OS package maintenance",
            .notes = "Keep the host OS and Pi-hole packages updated.",
            .confidence_percent = 55,
            .first_seen_year = 2018,
            .eol_year = 0
        }
    };
}

std::vector<DeviceLifecycleCatalogEntry> lifecycle_load_catalog(const std::string& catalog_path, std::vector<std::string>& limitations) {
    if (catalog_path.empty()) {
        limitations.push_back("No lifecycle catalog path was provided; built-in minimal catalog was used.");
        return lifecycle_builtin_catalog();
    }
    std::ifstream input{catalog_path, std::ios::binary};
    if (!input.is_open()) {
        limitations.push_back("Lifecycle catalog could not be opened: " + catalog_path + ". Built-in minimal catalog was used.");
        return lifecycle_builtin_catalog();
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string json = buffer.str();
    std::vector<DeviceLifecycleCatalogEntry> entries;
    for (const auto& object : lifecycle_extract_json_objects(json)) {
        if (object.find("\"devices\"") != std::string::npos) {
            continue;
        }
        if (object.find("\"vendor\"") == std::string::npos || object.find("\"status\"") == std::string::npos) {
            continue;
        }
        DeviceLifecycleCatalogEntry entry;
        entry.vendor = lifecycle_json_string(object, "vendor");
        entry.device_type = lifecycle_json_string(object, "device_type");
        entry.model = lifecycle_json_string(object, "model");
        entry.model_tokens = lifecycle_json_string_array(object, "model_tokens");
        entry.status = lifecycle_json_string(object, "status");
        entry.source = lifecycle_json_string(object, "source");
        entry.notes = lifecycle_json_string(object, "notes");
        entry.confidence_percent = lifecycle_json_int(object, "confidence_percent", 50);
        entry.first_seen_year = lifecycle_json_int(object, "first_seen_year", 0);
        entry.eol_year = lifecycle_json_int(object, "eol_year", 0);
        if (!entry.vendor.empty() || !entry.device_type.empty() || !entry.model_tokens.empty()) {
            entries.push_back(std::move(entry));
        }
    }
    if (entries.empty()) {
        limitations.push_back("Lifecycle catalog parsed 0 usable entries; built-in minimal catalog was used.");
        return lifecycle_builtin_catalog();
    }
    return entries;
}

int lifecycle_reference_year(const std::string& reference_date_utc) {
    if (reference_date_utc.size() >= 4 &&
        std::isdigit(static_cast<unsigned char>(reference_date_utc[0])) &&
        std::isdigit(static_cast<unsigned char>(reference_date_utc[1])) &&
        std::isdigit(static_cast<unsigned char>(reference_date_utc[2])) &&
        std::isdigit(static_cast<unsigned char>(reference_date_utc[3]))) {
        return std::stoi(reference_date_utc.substr(0, 4));
    }
    const std::string now = now_utc_iso8601();
    return std::stoi(now.substr(0, 4));
}

std::vector<CameraInventoryRecord> lifecycle_mock_inventory() {
    CameraInventoryRecord router;
    router.device_id = "old-router";
    router.hostname = "RT-AC68U";
    router.ip_addresses = {"192.168.1.1"};
    router.vendor_hint = "ASUS";
    router.device_type = "router";
    router.details = "model=RT-AC68U;firmware=legacy";

    CameraInventoryRecord camera;
    camera.device_id = "legacy-camera";
    camera.hostname = "front-door-ds-2cd";
    camera.ip_addresses = {"192.168.1.50"};
    camera.vendor_hint = "Hikvision";
    camera.device_type = "ip-camera";
    camera.details = "model=DS-2CD;ports=554,80";

    CameraInventoryRecord tablet;
    tablet.device_id = "family-ipad";
    tablet.hostname = "iPad";
    tablet.ip_addresses = {"192.168.1.130"};
    tablet.vendor_hint = "Apple";
    tablet.device_type = "tablet";
    tablet.details = "router-client-list";

    CameraInventoryRecord unknown;
    unknown.device_id = "mystery-plug";
    unknown.hostname = "unknown-smart-plug";
    unknown.ip_addresses = {"192.168.1.77"};
    unknown.vendor_hint = "Tuya";
    unknown.device_type = "iot";
    unknown.details = "no lifecycle catalog match";

    return {router, camera, tablet, unknown};
}

int lifecycle_match_score(const CameraInventoryRecord& record, const DeviceLifecycleCatalogEntry& entry, std::vector<std::string>& evidence) {
    int score = 0;
    const std::string identity = record.hostname + " " + record.vendor_hint + " " + record.device_type + " " + record.details;
    if (!entry.vendor.empty() && contains_token_ci(record.vendor_hint, entry.vendor)) {
        score += 35;
        evidence.push_back("vendor matched catalog entry: " + entry.vendor);
    }
    if (!entry.device_type.empty() && contains_token_ci(record.device_type, entry.device_type)) {
        score += 25;
        evidence.push_back("device type matched catalog entry: " + entry.device_type);
    }
    for (const auto& token : entry.model_tokens) {
        if (!token.empty() && contains_token_ci(identity, token)) {
            score += 35;
            evidence.push_back("model token matched: " + token);
            break;
        }
    }
    return score;
}

std::string lifecycle_effective_status(const DeviceLifecycleCatalogEntry& entry, int reference_year, int estimated_age_years) {
    if (entry.eol_year > 0 && entry.eol_year <= reference_year) {
        return "likely_eol";
    }
    if (!entry.status.empty()) {
        return entry.status;
    }
    if (estimated_age_years >= 8) {
        return "outdated";
    }
    return "monitor";
}

std::string lifecycle_severity(const std::string& status) {
    if (status == "likely_eol") {
        return "high";
    }
    if (status == "outdated") {
        return "medium";
    }
    if (status == "unknown") {
        return "info";
    }
    return "low";
}

std::vector<std::string> lifecycle_recommendations(const std::string& status) {
    if (status == "likely_eol") {
        return {
            "Verify the exact model on the vendor support page before making replacement decisions.",
            "Plan firmware update, replacement, or network segmentation if the device is no longer supported.",
            "Do not infer CVEs from lifecycle status alone; use a separate CVE/CPE check when available."
        };
    }
    if (status == "outdated") {
        return {
            "Check for firmware or OS updates from the vendor.",
            "Confirm the exact model and support status before escalating.",
            "Prefer replacement planning for devices that no longer receive security fixes."
        };
    }
    if (status == "unknown") {
        return {
            "Add a community catalog entry with model, source, confidence, and support dates when known.",
            "Confirm the device model locally before treating it as outdated or supported."
        };
    }
    return {
        "Monitor lifecycle annually and keep firmware updated.",
        "Improve confidence by adding exact model and source data to the local catalog."
    };
}

DeviceLifecycleFinding lifecycle_unknown_finding(const CameraInventoryRecord& record) {
    DeviceLifecycleFinding finding;
    finding.device_id = record.device_id;
    finding.hostname = record.hostname;
    finding.ip_address = record.ip_addresses.empty() ? std::string{} : record.ip_addresses.front();
    finding.vendor_hint = record.vendor_hint;
    finding.device_type = record.device_type;
    finding.lifecycle_status = "unknown";
    finding.severity = "info";
    finding.source = "local inventory only";
    finding.notes = "No local lifecycle catalog entry matched this device.";
    finding.confidence_percent = 20;
    finding.evidence = {"no local lifecycle catalog match"};
    finding.recommendations = lifecycle_recommendations(finding.lifecycle_status);
    return finding;
}

DeviceLifecycleResult run_device_lifecycle_intelligence(const DeviceLifecycleConfig& config) {
    DeviceLifecycleResult result;
    const bool explicit_storage_path = !config.storage_db_path.empty();
    result.storage_db_path = explicit_storage_path ? config.storage_db_path : std::string{"netsentinel11_storage.db"};
    result.catalog_path = config.catalog_path;
    result.reference_date_utc = config.reference_date_utc.empty() ? now_utc_iso8601().substr(0, 10) : config.reference_date_utc;

    if (!config.mock_mode && !explicit_storage_path) {
        result.success = false;
        result.message = "Device lifecycle intelligence needs an authorized inventory database path for non-mock mode.";
        result.limitations.push_back("Non-mock mode is offline inventory analysis only; provide --db from an authorized local scan.");
        return result;
    }

    std::vector<std::string> limitations;
    const auto catalog = lifecycle_load_catalog(config.catalog_path, limitations);
    auto records = read_camera_inventory_records(result.storage_db_path, false);
    if (records.empty() && config.mock_mode) {
        records = lifecycle_mock_inventory();
        limitations.push_back("Mock lifecycle inventory was used because no inventory records were available.");
    }
    result.device_count = records.size();

    const int reference_year = lifecycle_reference_year(result.reference_date_utc);
    for (const auto& record : records) {
        const DeviceLifecycleCatalogEntry* best = nullptr;
        std::vector<std::string> best_evidence;
        int best_score = 0;
        for (const auto& entry : catalog) {
            std::vector<std::string> evidence;
            const int score = lifecycle_match_score(record, entry, evidence);
            if (score > best_score) {
                best_score = score;
                best = &entry;
                best_evidence = std::move(evidence);
            }
        }

        if (best == nullptr || best_score < 50) {
            if (config.include_unknown) {
                result.findings.push_back(lifecycle_unknown_finding(record));
                ++result.unknown_count;
            }
            continue;
        }

        DeviceLifecycleFinding finding;
        finding.device_id = record.device_id;
        finding.hostname = record.hostname;
        finding.ip_address = record.ip_addresses.empty() ? std::string{} : record.ip_addresses.front();
        finding.vendor_hint = record.vendor_hint;
        finding.device_type = record.device_type;
        finding.matched_vendor = best->vendor;
        finding.matched_model = best->model;
        finding.first_seen_year = best->first_seen_year;
        finding.eol_year = best->eol_year;
        finding.estimated_age_years = best->first_seen_year > 0 ? std::max(0, reference_year - best->first_seen_year) : 0;
        finding.lifecycle_status = lifecycle_effective_status(*best, reference_year, finding.estimated_age_years);
        finding.severity = lifecycle_severity(finding.lifecycle_status);
        finding.source = best->source;
        finding.notes = best->notes;
        finding.confidence_percent = std::max(0, std::min(95, best->confidence_percent + (best_score >= 70 ? 10 : 0)));
        finding.evidence = std::move(best_evidence);
        finding.recommendations = lifecycle_recommendations(finding.lifecycle_status);

        if (finding.lifecycle_status == "likely_eol") {
            ++result.likely_eol_count;
        } else if (finding.lifecycle_status == "outdated") {
            ++result.outdated_count;
        } else {
            ++result.monitor_count;
        }
        result.findings.push_back(std::move(finding));
    }

    result.finding_count = result.findings.size();
    result.limitations = std::move(limitations);
    result.limitations.push_back("Lifecycle intelligence is offline and approximate; it does not make unsupported CVE or exploitability claims.");
    result.limitations.push_back("Confidence and source fields must be reviewed before release or replacement decisions.");
    result.success = true;
    result.persisted = true;
    result.message = "device-lifecycle-intelligence-complete";
    append_history("device-lifecycle", result.storage_db_path, result.findings.empty() ? "none" : "found", "count=" + std::to_string(result.findings.size()));
    prune_history(128);
    return result;
}

std::string device_lifecycle_markdown(const DeviceLifecycleResult& result) {
    std::ostringstream oss;
    oss << "# Device Lifecycle Intelligence Report\n\n";
    oss << "- Success: " << (result.success ? "yes" : "no") << "\n";
    oss << "- Storage DB: " << result.storage_db_path << "\n";
    oss << "- Catalog: " << result.catalog_path << "\n";
    oss << "- Reference date: " << result.reference_date_utc << "\n";
    oss << "- Devices analyzed: " << result.device_count << "\n";
    oss << "- Findings: " << result.finding_count << "\n";
    oss << "- Likely EOL: " << result.likely_eol_count << "\n";
    oss << "- Outdated: " << result.outdated_count << "\n";
    oss << "- Monitor: " << result.monitor_count << "\n";
    oss << "- Unknown: " << result.unknown_count << "\n";
    oss << "- Message: " << result.message << "\n\n";
    oss << "## Findings\n\n";
    if (result.findings.empty()) {
        oss << "No lifecycle findings were generated from the available inventory.\n";
    }
    for (const auto& finding : result.findings) {
        oss << "### " << finding.device_id << "\n\n";
        oss << "- Host: " << finding.hostname << "\n";
        oss << "- IP: " << finding.ip_address << "\n";
        oss << "- Vendor hint: " << finding.vendor_hint << "\n";
        oss << "- Type: " << finding.device_type << "\n";
        oss << "- Lifecycle status: " << finding.lifecycle_status << "\n";
        oss << "- Severity: " << finding.severity << "\n";
        oss << "- Confidence: " << finding.confidence_percent << "%\n";
        oss << "- Matched vendor: " << finding.matched_vendor << "\n";
        oss << "- Matched model: " << finding.matched_model << "\n";
        oss << "- First seen year: " << finding.first_seen_year << "\n";
        oss << "- EOL year: " << finding.eol_year << "\n";
        oss << "- Estimated age years: " << finding.estimated_age_years << "\n";
        oss << "- Source: " << finding.source << "\n";
        oss << "- Notes: " << finding.notes << "\n";
        if (!finding.evidence.empty()) {
            oss << "- Evidence:\n";
            for (const auto& item : finding.evidence) {
                oss << "  - " << item << "\n";
            }
        }
        if (!finding.recommendations.empty()) {
            oss << "- Recommendations:\n";
            for (const auto& item : finding.recommendations) {
                oss << "  - " << item << "\n";
            }
        }
        oss << "\n";
    }
    if (!result.limitations.empty()) {
        oss << "## Limitations\n\n";
        for (const auto& limitation : result.limitations) {
            oss << "- " << limitation << "\n";
        }
    }
    return oss.str();
}

struct CveCpeCatalogEntry {
    std::string cpe;
    std::string vendor;
    std::string product;
    std::vector<std::string> model_tokens;
    std::vector<std::string> version_tokens;
    std::string cve;
    std::string severity;
    std::string cvss;
    std::string source;
    std::string summary;
};

std::vector<CveCpeCatalogEntry> cve_cpe_builtin_catalog() {
    return {
        {
            .cpe = "cpe:2.3:o:fixture:router_firmware:1.0.3:*:*:*:*:*:*:*",
            .vendor = "ASUS",
            .product = "router",
            .model_tokens = {"rt-ac68u", "router"},
            .version_tokens = {"v1.0.3", "firmware=1.0.3"},
            .cve = "CVE-2024-10001",
            .severity = "high",
            .cvss = "8.1",
            .source = "local fixture: replace with licensed NVD/public data before release claims",
            .summary = "Fixture CVE correlation for deterministic tests; not a vulnerability claim for a real product."
        },
        {
            .cpe = "cpe:2.3:o:fixture:ip_camera_firmware:5.4:*:*:*:*:*:*:*",
            .vendor = "Hikvision",
            .product = "camera",
            .model_tokens = {"ds-2cd", "hikvision", "ip-camera"},
            .version_tokens = {"v5.4", "firmware=5.4"},
            .cve = "CVE-2023-33333",
            .severity = "medium",
            .cvss = "6.5",
            .source = "local fixture: replace with licensed NVD/public data before release claims",
            .summary = "Fixture camera firmware correlation; possible unless exact version evidence is present."
        }
    };
}

std::vector<CveCpeCatalogEntry> cve_cpe_load_catalog(const std::string& catalog_path, std::vector<std::string>& limitations) {
    if (catalog_path.empty()) {
        limitations.push_back("No CPE/CVE catalog path was provided; built-in fixture catalog was used.");
        return cve_cpe_builtin_catalog();
    }
    std::ifstream input{catalog_path, std::ios::binary};
    if (!input.is_open()) {
        limitations.push_back("CPE/CVE catalog could not be opened: " + catalog_path + ". Built-in fixture catalog was used.");
        return cve_cpe_builtin_catalog();
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string json = buffer.str();
    std::vector<CveCpeCatalogEntry> entries;
    for (const auto& object : lifecycle_extract_json_objects(json)) {
        if (object.find("\"cves\"") != std::string::npos) {
            continue;
        }
        if (object.find("\"cve\"") == std::string::npos || object.find("\"cpe\"") == std::string::npos) {
            continue;
        }
        CveCpeCatalogEntry entry;
        entry.cpe = lifecycle_json_string(object, "cpe");
        entry.vendor = lifecycle_json_string(object, "vendor");
        entry.product = lifecycle_json_string(object, "product");
        entry.model_tokens = lifecycle_json_string_array(object, "model_tokens");
        entry.version_tokens = lifecycle_json_string_array(object, "version_tokens");
        entry.cve = lifecycle_json_string(object, "cve");
        entry.severity = lifecycle_json_string(object, "severity");
        entry.cvss = lifecycle_json_string(object, "cvss");
        entry.source = lifecycle_json_string(object, "source");
        entry.summary = lifecycle_json_string(object, "summary");
        if (!entry.cve.empty() && !entry.cpe.empty()) {
            entries.push_back(std::move(entry));
        }
    }
    if (entries.empty()) {
        limitations.push_back("CPE/CVE catalog parsed 0 usable entries; built-in fixture catalog was used.");
        return cve_cpe_builtin_catalog();
    }
    return entries;
}

std::vector<CameraInventoryRecord> cve_cpe_mock_inventory() {
    CameraInventoryRecord router;
    router.device_id = "old-router";
    router.hostname = "RT-AC68U";
    router.ip_addresses = {"192.168.1.1"};
    router.vendor_hint = "ASUS";
    router.device_type = "router";
    router.details = "model=RT-AC68U;firmware=v1.0.3";

    CameraInventoryRecord camera;
    camera.device_id = "legacy-camera";
    camera.hostname = "front-door-ds-2cd";
    camera.ip_addresses = {"192.168.1.50"};
    camera.vendor_hint = "Hikvision";
    camera.device_type = "ip-camera";
    camera.details = "model=DS-2CD;service=rtsp";

    CameraInventoryRecord pihole;
    pihole.device_id = "pihole";
    pihole.hostname = "PiHole";
    pihole.ip_addresses = {"192.168.1.2"};
    pihole.vendor_hint = "Raspberry Pi";
    pihole.device_type = "dns";
    pihole.details = "no cpe match";

    return {router, camera, pihole};
}

int cve_cpe_match_score(
    const CameraInventoryRecord& record,
    const CveCpeCatalogEntry& entry,
    std::vector<std::string>& evidence,
    bool& version_evidence
) {
    int score = 0;
    version_evidence = false;
    const std::string identity = record.hostname + " " + record.vendor_hint + " " + record.device_type + " " + record.details;
    if (!entry.vendor.empty() && contains_token_ci(record.vendor_hint, entry.vendor)) {
        score += 25;
        evidence.push_back("vendor matched CPE catalog entry: " + entry.vendor);
    }
    if (!entry.product.empty() && contains_token_ci(record.device_type, entry.product)) {
        score += 20;
        evidence.push_back("device type matched CPE product: " + entry.product);
    }
    for (const auto& token : entry.model_tokens) {
        if (!token.empty() && contains_token_ci(identity, token)) {
            score += 30;
            evidence.push_back("model token matched: " + token);
            break;
        }
    }
    for (const auto& token : entry.version_tokens) {
        if (!token.empty() && contains_token_ci(identity, token)) {
            score += 35;
            version_evidence = true;
            evidence.push_back("version token matched: " + token);
            break;
        }
    }
    return score;
}

std::vector<std::string> cve_cpe_recommendations(const std::string& match_label) {
    std::vector<std::string> recommendations = {
        "Do not run exploit scripts, proof-of-concept payloads, credential attacks, or intrusive verification.",
        "Confirm exact vendor, model, firmware, and CPE before treating this as a real vulnerability.",
        "Use vendor advisories or licensed NVD/public data to validate the correlation."
    };
    if (match_label == "strong version match") {
        recommendations.push_back("Because version evidence matched, prioritize vendor advisory review and patch planning.");
    } else {
        recommendations.push_back("This is a possible match only; improve inventory version data before escalation.");
    }
    return recommendations;
}

CveCpeCorrelationResult run_cve_cpe_correlation(const CveCpeCorrelationConfig& config) {
    CveCpeCorrelationResult result;
    const bool explicit_storage_path = !config.storage_db_path.empty();
    result.storage_db_path = explicit_storage_path ? config.storage_db_path : std::string{"netsentinel11_storage.db"};
    result.catalog_path = config.catalog_path;

    if (!config.mock_mode && !explicit_storage_path) {
        result.success = false;
        result.message = "CPE/CVE correlation needs an authorized inventory database path for non-mock mode.";
        result.limitations.push_back("Non-mock mode is offline correlation only; provide --db from an authorized local scan.");
        return result;
    }

    std::vector<std::string> limitations;
    const auto catalog = cve_cpe_load_catalog(config.catalog_path, limitations);
    auto records = read_camera_inventory_records(result.storage_db_path, false);
    if (records.empty() && config.mock_mode) {
        records = cve_cpe_mock_inventory();
        limitations.push_back("Mock CPE/CVE inventory was used because no inventory records were available.");
    }
    result.device_count = records.size();

    for (const auto& record : records) {
        for (const auto& entry : catalog) {
            std::vector<std::string> evidence;
            bool version_evidence = false;
            const int score = cve_cpe_match_score(record, entry, evidence, version_evidence);
            const bool strong_version_match = version_evidence && score >= 80;
            const bool possible_match = score >= 55;
            if (!strong_version_match && (!possible_match || !config.include_possible_matches)) {
                continue;
            }

            CveCpeMatch match;
            match.device_id = record.device_id;
            match.hostname = record.hostname;
            match.ip_address = record.ip_addresses.empty() ? std::string{} : record.ip_addresses.front();
            match.vendor_hint = record.vendor_hint;
            match.device_type = record.device_type;
            match.cpe = entry.cpe;
            match.cve = entry.cve;
            match.severity = entry.severity;
            match.cvss = entry.cvss;
            match.match_label = strong_version_match ? "strong version match" : "possible match";
            match.source = entry.source;
            match.summary = entry.summary;
            match.confidence_percent = std::max(0, std::min(95, score));
            match.version_evidence = version_evidence;
            match.evidence = std::move(evidence);
            match.recommendations = cve_cpe_recommendations(match.match_label);
            if (strong_version_match) {
                ++result.strong_version_match_count;
            } else {
                ++result.possible_match_count;
            }
            result.matches.push_back(std::move(match));
        }
    }

    result.match_count = result.matches.size();
    result.limitations = std::move(limitations);
    result.limitations.push_back("Correlation is offline and non-invasive; no exploit checks, proof-of-concept payloads, credential attempts, or intrusive probes are run.");
    result.limitations.push_back("Matches are labeled possible unless strong version evidence is present; correlation is not proof of vulnerability.");
    result.success = true;
    result.persisted = true;
    result.message = "cve-cpe-correlation-complete";
    append_history("cve-cpe", result.storage_db_path, result.matches.empty() ? "none" : "found", "count=" + std::to_string(result.matches.size()));
    prune_history(128);
    return result;
}

std::string cve_cpe_correlation_markdown(const CveCpeCorrelationResult& result) {
    std::ostringstream oss;
    oss << "# CPE/CVE Correlation Report\n\n";
    oss << "No exploit scripts, proof-of-concept payloads, credential attacks, or intrusive verification are performed.\n\n";
    oss << "- Success: " << (result.success ? "yes" : "no") << "\n";
    oss << "- Storage DB: " << result.storage_db_path << "\n";
    oss << "- Catalog: " << result.catalog_path << "\n";
    oss << "- Devices analyzed: " << result.device_count << "\n";
    oss << "- Matches: " << result.match_count << "\n";
    oss << "- Possible matches: " << result.possible_match_count << "\n";
    oss << "- Strong version matches: " << result.strong_version_match_count << "\n";
    oss << "- Message: " << result.message << "\n\n";
    oss << "## Matches\n\n";
    if (result.matches.empty()) {
        oss << "No CPE/CVE correlations were found in the local catalog.\n";
    }
    for (const auto& match : result.matches) {
        oss << "### " << match.device_id << " - " << match.cve << "\n\n";
        oss << "- Host: " << match.hostname << "\n";
        oss << "- IP: " << match.ip_address << "\n";
        oss << "- Vendor hint: " << match.vendor_hint << "\n";
        oss << "- Type: " << match.device_type << "\n";
        oss << "- CPE: " << match.cpe << "\n";
        oss << "- Match label: " << match.match_label << "\n";
        oss << "- Version evidence: " << (match.version_evidence ? "yes" : "no") << "\n";
        oss << "- Confidence: " << match.confidence_percent << "%\n";
        oss << "- Severity: " << match.severity << "\n";
        oss << "- CVSS: " << match.cvss << "\n";
        oss << "- Source: " << match.source << "\n";
        oss << "- Summary: " << match.summary << "\n";
        if (!match.evidence.empty()) {
            oss << "- Evidence:\n";
            for (const auto& item : match.evidence) {
                oss << "  - " << item << "\n";
            }
        }
        if (!match.recommendations.empty()) {
            oss << "- Recommendations:\n";
            for (const auto& item : match.recommendations) {
                oss << "  - " << item << "\n";
            }
        }
        oss << "\n";
    }
    if (!result.limitations.empty()) {
        oss << "## Limitations\n\n";
        for (const auto& limitation : result.limitations) {
            oss << "- " << limitation << "\n";
        }
    }
    return oss.str();
}

struct LocalRecognitionRule {
    std::string device_id;
    std::string hostname_token;
    std::string vendor_token;
    std::string device_type;
    std::vector<std::string> labels;
    int confidence_percent = 80;
    std::string source;
    std::string updated_utc;
};

std::vector<std::string> recognition_split(const std::string& text, char delimiter) {
    std::vector<std::string> parts;
    std::string current;
    for (const char ch : text) {
        if (ch == delimiter) {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    parts.push_back(current);
    return parts;
}

std::string recognition_join(const std::vector<std::string>& values, char delimiter) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            oss << delimiter;
        }
        oss << values[i];
    }
    return oss.str();
}

int recognition_parse_int(const std::string& text, int fallback) {
    try {
        std::size_t consumed = 0;
        const int value = std::stoi(text, &consumed);
        return consumed == text.size() ? value : fallback;
    } catch (...) {
        return fallback;
    }
}

LocalRecognitionRule recognition_rule_from_line(const std::string& line, bool& ok) {
    ok = false;
    LocalRecognitionRule rule;
    const auto fields = recognition_split(line, '|');
    if (fields.size() < 8 || fields[0] != "LRULE") {
        return rule;
    }
    rule.device_id = fields[1];
    rule.hostname_token = fields[2];
    rule.vendor_token = fields[3];
    rule.device_type = fields[4];
    rule.labels = recognition_split(fields[5], ',');
    rule.confidence_percent = recognition_parse_int(fields[6], 80);
    rule.source = fields[7];
    if (fields.size() > 8) {
        rule.updated_utc = fields[8];
    }
    ok = !rule.device_type.empty() || !rule.labels.empty();
    return rule;
}

std::vector<LocalRecognitionRule> recognition_read_rules(const std::string& path, std::vector<std::string>& limitations) {
    std::vector<LocalRecognitionRule> rules;
    if (path.empty()) {
        limitations.push_back("No recognition database path was provided.");
        return rules;
    }
    std::ifstream input{path};
    if (!input.is_open()) {
        limitations.push_back("Recognition database not found yet; a local file will be created when a correction is learned.");
        return rules;
    }
    std::string line;
    while (std::getline(input, line)) {
        bool ok = false;
        auto rule = recognition_rule_from_line(line, ok);
        if (ok) {
            rules.push_back(std::move(rule));
        }
    }
    return rules;
}

bool recognition_write_rules(const std::string& path, const std::vector<LocalRecognitionRule>& rules) {
    if (path.empty()) {
        return false;
    }
    const auto parent = std::filesystem::path{path}.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }
    std::ofstream output{path, std::ios::trunc};
    if (!output.is_open()) {
        return false;
    }
    output << "# NetSentinel11 local recognition rules. Sanitized: no IP or MAC addresses.\n";
    for (const auto& rule : rules) {
        output << "LRULE|"
               << rule.device_id << "|"
               << rule.hostname_token << "|"
               << rule.vendor_token << "|"
               << rule.device_type << "|"
               << recognition_join(rule.labels, ',') << "|"
               << rule.confidence_percent << "|"
               << rule.source << "|"
               << (rule.updated_utc.empty() ? now_utc_iso8601() : rule.updated_utc) << "\n";
    }
    return true;
}

LocalRecognitionRule recognition_rule_from_learning_config(const LocalRecognitionLearningConfig& config) {
    LocalRecognitionRule rule;
    rule.device_id = config.learn_device_id;
    rule.hostname_token = config.learn_hostname;
    rule.vendor_token = config.learn_vendor_hint;
    rule.device_type = config.learn_device_type;
    rule.labels = config.learn_labels;
    rule.confidence_percent = 95;
    rule.source = "local-user-correction";
    rule.updated_utc = now_utc_iso8601();
    return rule;
}

int recognition_rule_match_score(const CameraInventoryRecord& record, const LocalRecognitionRule& rule, std::vector<std::string>& evidence) {
    int score = 0;
    if (!rule.device_id.empty() && record.device_id == rule.device_id) {
        score += 55;
        evidence.push_back("device_id matched local correction");
    }
    if (!rule.hostname_token.empty() && contains_token_ci(record.hostname, rule.hostname_token)) {
        score += 30;
        evidence.push_back("hostname token matched local correction: " + rule.hostname_token);
    }
    if (!rule.vendor_token.empty() && contains_token_ci(record.vendor_hint, rule.vendor_token)) {
        score += 20;
        evidence.push_back("vendor token matched local correction: " + rule.vendor_token);
    }
    return score;
}

LocalRecognitionSuggestion recognition_suggestion_for_rule(
    const CameraInventoryRecord& record,
    const LocalRecognitionRule& rule,
    int score,
    std::vector<std::string> evidence
) {
    LocalRecognitionSuggestion suggestion;
    suggestion.device_id = record.device_id;
    suggestion.hostname = record.hostname;
    suggestion.vendor_hint = record.vendor_hint;
    suggestion.current_device_type = record.device_type;
    suggestion.suggested_device_type = rule.device_type;
    suggestion.suggested_labels = rule.labels;
    suggestion.confidence_percent = std::max(0, std::min(100, rule.confidence_percent + (score >= 75 ? 5 : 0)));
    suggestion.source = rule.source;
    suggestion.evidence = std::move(evidence);
    return suggestion;
}

LocalRecognitionLearningResult run_local_recognition_learning(const LocalRecognitionLearningConfig& config) {
    LocalRecognitionLearningResult result;
    result.inventory_db_path = config.inventory_db_path.empty() ? std::string{"netsentinel11_storage.db"} : config.inventory_db_path;
    result.recognition_db_path = config.recognition_db_path;

    if (!config.mock_mode && config.inventory_db_path.empty() && config.learn_device_id.empty()) {
        result.success = false;
        result.message = "Local recognition learning needs an authorized inventory DB or an explicit local correction.";
        result.limitations.push_back("No cloud service is used; provide --db for non-mock inventory evaluation.");
        return result;
    }

    std::vector<std::string> limitations;
    auto rules = recognition_read_rules(config.recognition_db_path, limitations);
    result.rules_loaded = rules.size();

    if (!config.import_path.empty()) {
        auto imported = recognition_read_rules(config.import_path, limitations);
        result.rules_imported = imported.size();
        rules.insert(rules.end(), imported.begin(), imported.end());
    }

    if (!config.learn_device_id.empty() || !config.learn_hostname.empty() || !config.learn_device_type.empty() || !config.learn_labels.empty()) {
        auto learned = recognition_rule_from_learning_config(config);
        if (learned.device_type.empty() && learned.labels.empty()) {
            limitations.push_back("Learning request ignored because no device type or labels were provided.");
        } else {
            rules.push_back(std::move(learned));
        }
    }

    bool wrote_db = false;
    if (!rules.empty()) {
        wrote_db = recognition_write_rules(config.recognition_db_path, rules);
        result.rules_written = wrote_db ? rules.size() : 0;
        if (!wrote_db) {
            limitations.push_back("Could not write local recognition database: " + config.recognition_db_path);
        }
    }

    if (!config.export_path.empty()) {
        if (!recognition_write_rules(config.export_path, rules)) {
            limitations.push_back("Could not export sanitized recognition rules: " + config.export_path);
        }
    }

    auto records = read_camera_inventory_records(result.inventory_db_path, false);
    if (records.empty() && config.mock_mode) {
        records = lifecycle_mock_inventory();
        limitations.push_back("Mock inventory was used because no inventory records were available.");
    }

    for (const auto& record : records) {
        const LocalRecognitionRule* best = nullptr;
        std::vector<std::string> best_evidence;
        int best_score = 0;
        for (const auto& rule : rules) {
            std::vector<std::string> evidence;
            const int score = recognition_rule_match_score(record, rule, evidence);
            if (score > best_score) {
                best_score = score;
                best = &rule;
                best_evidence = std::move(evidence);
            }
        }
        if (best == nullptr || best_score < 45) {
            continue;
        }
        result.suggestions.push_back(recognition_suggestion_for_rule(record, *best, best_score, std::move(best_evidence)));
    }

    result.suggestions_count = result.suggestions.size();
    result.limitations = std::move(limitations);
    result.limitations.push_back("Recognition learning is local-first; user inventory is never uploaded to a cloud service by default.");
    result.limitations.push_back("Exports contain sanitized rules only and must not include IP or MAC addresses.");
    result.success = true;
    result.persisted = wrote_db || !rules.empty();
    result.message = "local-recognition-learning-complete";
    append_history("local-recognition", result.recognition_db_path, result.suggestions.empty() ? "none" : "suggested", "count=" + std::to_string(result.suggestions.size()));
    prune_history(128);
    return result;
}

std::string local_recognition_learning_markdown(const LocalRecognitionLearningResult& result) {
    std::ostringstream oss;
    oss << "# Local Device Recognition Learning Report\n\n";
    oss << "- Success: " << (result.success ? "yes" : "no") << "\n";
    oss << "- Inventory DB: " << result.inventory_db_path << "\n";
    oss << "- Recognition DB: " << result.recognition_db_path << "\n";
    oss << "- Rules loaded: " << result.rules_loaded << "\n";
    oss << "- Rules imported: " << result.rules_imported << "\n";
    oss << "- Rules written: " << result.rules_written << "\n";
    oss << "- Suggestions: " << result.suggestions_count << "\n";
    oss << "- Message: " << result.message << "\n\n";
    oss << "## Suggestions\n\n";
    if (result.suggestions.empty()) {
        oss << "No local recognition suggestions were produced.\n";
    }
    for (const auto& suggestion : result.suggestions) {
        oss << "### " << suggestion.device_id << "\n\n";
        oss << "- Host: " << suggestion.hostname << "\n";
        oss << "- Vendor: " << suggestion.vendor_hint << "\n";
        oss << "- Current type: " << suggestion.current_device_type << "\n";
        oss << "- Suggested type: " << suggestion.suggested_device_type << "\n";
        oss << "- Confidence: " << suggestion.confidence_percent << "%\n";
        oss << "- Source: " << suggestion.source << "\n";
        if (!suggestion.suggested_labels.empty()) {
            oss << "- Suggested labels: " << recognition_join(suggestion.suggested_labels, ',') << "\n";
        }
        if (!suggestion.evidence.empty()) {
            oss << "- Evidence:\n";
            for (const auto& item : suggestion.evidence) {
                oss << "  - " << item << "\n";
            }
        }
        oss << "\n";
    }
    if (!result.limitations.empty()) {
        oss << "## Limitations\n\n";
        for (const auto& limitation : result.limitations) {
            oss << "- " << limitation << "\n";
        }
    }
    return oss.str();
}

std::string importer_lower_key(std::string value) {
    std::string out;
    for (const char ch : value) {
        if (std::isalnum(static_cast<unsigned char>(ch))) {
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        }
    }
    return out;
}

std::vector<std::string> importer_parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string current;
    bool in_quotes = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '"') {
            if (in_quotes && i + 1 < line.size() && line[i + 1] == '"') {
                current.push_back('"');
                ++i;
            } else {
                in_quotes = !in_quotes;
            }
            continue;
        }
        if (ch == ',' && !in_quotes) {
            fields.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    fields.push_back(current);
    return fields;
}

std::string importer_field(const std::vector<std::string>& row, const std::map<std::string, std::size_t>& columns, std::initializer_list<const char*> names) {
    for (const char* name : names) {
        const auto it = columns.find(importer_lower_key(name));
        if (it != columns.end() && it->second < row.size()) {
            return row[it->second];
        }
    }
    return {};
}

std::string importer_safe_token(std::string value) {
    for (char& ch : value) {
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '-' && ch != '_') {
            ch = '-';
        }
    }
    while (value.find("--") != std::string::npos) {
        value.replace(value.find("--"), 2, "-");
    }
    if (value.empty()) {
        value = "imported-device";
    }
    return value;
}

std::string importer_db_field(std::string value) {
    for (char& ch : value) {
        if (ch == '|') {
            ch = ' ';
        }
    }
    return value;
}

std::vector<GenericImportedDevice> importer_parse_csv(const std::string& text, std::vector<std::string>& warnings, std::size_t& rows_read) {
    std::istringstream input{text};
    std::string line;
    if (!std::getline(input, line)) {
        warnings.push_back("CSV import file is empty.");
        return {};
    }
    const auto header = importer_parse_csv_line(line);
    std::map<std::string, std::size_t> columns;
    for (std::size_t i = 0; i < header.size(); ++i) {
        columns[importer_lower_key(header[i])] = i;
    }
    std::vector<GenericImportedDevice> devices;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        ++rows_read;
        const auto row = importer_parse_csv_line(line);
        GenericImportedDevice device;
        device.ip_address = importer_field(row, columns, {"ip", "ip address", "ip_address", "client ip address"});
        device.mac_address = importer_field(row, columns, {"mac", "mac address", "mac_address", "client mac address", "clients mac address"});
        device.hostname = importer_field(row, columns, {"hostname", "host", "name", "client name", "clients name", "device name"});
        device.vendor_hint = importer_field(row, columns, {"vendor", "vendor hint", "manufacturer"});
        device.device_type = importer_field(row, columns, {"type", "device type", "device_type", "category"});
        const auto labels = importer_field(row, columns, {"label", "labels", "tag", "tags"});
        if (!labels.empty()) {
            device.labels = recognition_split(labels, ',');
        }
        device.first_seen_utc = importer_field(row, columns, {"first seen", "first_seen", "first seen utc"});
        device.last_seen_utc = importer_field(row, columns, {"last seen", "last_seen", "last seen utc"});
        device.device_id = importer_safe_token(!device.hostname.empty() ? device.hostname : (!device.mac_address.empty() ? device.mac_address : device.ip_address));
        device.mapping_notes.push_back("generic CSV column mapping preview");
        if (device.ip_address.empty() && device.mac_address.empty() && device.hostname.empty()) {
            warnings.push_back("Skipped row without IP, MAC, or hostname.");
            continue;
        }
        devices.push_back(std::move(device));
    }
    return devices;
}

std::vector<GenericImportedDevice> importer_parse_json(const std::string& text, std::vector<std::string>& warnings, std::size_t& rows_read) {
    std::vector<GenericImportedDevice> devices;
    for (const auto& object : lifecycle_extract_json_objects(text)) {
        if (object.find("\"devices\"") != std::string::npos) {
            continue;
        }
        GenericImportedDevice device;
        device.ip_address = lifecycle_json_string(object, "ip");
        if (device.ip_address.empty()) {
            device.ip_address = lifecycle_json_string(object, "ip_address");
        }
        device.mac_address = lifecycle_json_string(object, "mac");
        if (device.mac_address.empty()) {
            device.mac_address = lifecycle_json_string(object, "mac_address");
        }
        device.hostname = lifecycle_json_string(object, "hostname");
        if (device.hostname.empty()) {
            device.hostname = lifecycle_json_string(object, "name");
        }
        device.vendor_hint = lifecycle_json_string(object, "vendor");
        device.device_type = lifecycle_json_string(object, "type");
        if (device.device_type.empty()) {
            device.device_type = lifecycle_json_string(object, "device_type");
        }
        const auto label = lifecycle_json_string(object, "label");
        if (!label.empty()) {
            device.labels = recognition_split(label, ',');
        }
        device.first_seen_utc = lifecycle_json_string(object, "first_seen");
        device.last_seen_utc = lifecycle_json_string(object, "last_seen");
        if (device.ip_address.empty() && device.mac_address.empty() && device.hostname.empty()) {
            continue;
        }
        ++rows_read;
        device.device_id = importer_safe_token(!device.hostname.empty() ? device.hostname : (!device.mac_address.empty() ? device.mac_address : device.ip_address));
        device.mapping_notes.push_back("generic JSON key mapping preview");
        devices.push_back(std::move(device));
    }
    if (devices.empty()) {
        warnings.push_back("JSON importer found no generic device objects.");
    }
    return devices;
}

bool importer_write_inventory_db(const std::string& path, const std::vector<GenericImportedDevice>& devices) {
    if (path.empty()) {
        return false;
    }
    const auto parent = std::filesystem::path{path}.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }
    std::ofstream output{path, std::ios::trunc};
    if (!output.is_open()) {
        return false;
    }
    output << "SCHEMA_VERSION=2\n";
    output << "INV_DEVICE|\n";
    for (const auto& device : devices) {
        output << "INV_DEVICE|"
               << importer_db_field(device.device_id) << "|"
               << importer_db_field(device.hostname) << "|"
               << importer_db_field(device.ip_address) << "|"
               << importer_db_field(device.mac_address) << "|"
               << importer_db_field(device.vendor_hint) << "|"
               << importer_db_field(device.device_type.empty() ? std::string{"unknown"} : device.device_type) << "|"
               << "50|0|0|"
               << importer_db_field(recognition_join(device.labels, ',')) << "|"
               << "imported-generic;first_seen=" << importer_db_field(device.first_seen_utc)
               << ";last_seen=" << importer_db_field(device.last_seen_utc) << "|"
               << (device.last_seen_utc.empty() ? now_utc_iso8601() : importer_db_field(device.last_seen_utc)) << "\n";
    }
    return true;
}

GenericInventoryImportResult run_generic_inventory_import(const GenericInventoryImportConfig& config) {
    GenericInventoryImportResult result;
    result.input_path = config.input_path;
    result.output_db_path = config.output_db_path;
    result.format = config.format.empty() ? "auto" : config.format;
    result.preview_only = !config.apply;

    if (config.input_path.empty()) {
        result.success = false;
        result.message = "Generic importer requires --input.";
        return result;
    }
    std::ifstream input{config.input_path, std::ios::binary};
    if (!input.is_open()) {
        result.success = false;
        result.message = "Failed to open generic import input: " + config.input_path;
        return result;
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string text = buffer.str();

    std::string format = result.format;
    if (format == "auto") {
        format = config.input_path.size() >= 5 && config.input_path.substr(config.input_path.size() - 5) == ".json" ? "json" : "csv";
    }
    if (format == "csv") {
        result.devices = importer_parse_csv(text, result.warnings, result.rows_read);
    } else if (format == "json") {
        result.devices = importer_parse_json(text, result.warnings, result.rows_read);
    } else {
        result.success = false;
        result.message = "Unsupported generic import format. Use csv, json, or auto.";
        return result;
    }

    result.format = format;
    result.rows_importable = result.devices.size();
    if (config.apply) {
        if (config.output_db_path.empty()) {
            result.success = false;
            result.message = "--apply requires --output-db.";
            return result;
        }
        result.persisted = importer_write_inventory_db(config.output_db_path, result.devices);
        result.rows_written = result.persisted ? result.devices.size() : 0;
        if (!result.persisted) {
            result.success = false;
            result.message = "Failed to write generic imported inventory DB.";
            return result;
        }
    }
    result.limitations.push_back("Importer uses generic user-provided CSV/JSON mappings only and does not depend on proprietary formats.");
    result.limitations.push_back("Preview mode is the default; use --apply to write an inventory DB.");
    result.success = true;
    result.message = config.apply ? "generic-inventory-import-applied" : "generic-inventory-import-preview";
    append_history("generic-import", config.input_path, config.apply ? "applied" : "preview", "rows=" + std::to_string(result.rows_importable));
    prune_history(128);
    return result;
}

std::string generic_inventory_import_markdown(const GenericInventoryImportResult& result) {
    std::ostringstream oss;
    oss << "# Generic Inventory Import Report\n\n";
    oss << "- Success: " << (result.success ? "yes" : "no") << "\n";
    oss << "- Input: " << result.input_path << "\n";
    oss << "- Output DB: " << result.output_db_path << "\n";
    oss << "- Format: " << result.format << "\n";
    oss << "- Preview only: " << (result.preview_only ? "yes" : "no") << "\n";
    oss << "- Rows read: " << result.rows_read << "\n";
    oss << "- Rows importable: " << result.rows_importable << "\n";
    oss << "- Rows written: " << result.rows_written << "\n";
    oss << "- Message: " << result.message << "\n\n";
    oss << "## Preview\n\n";
    for (const auto& device : result.devices) {
        oss << "- " << device.device_id << ": host=" << device.hostname
            << ", ip=" << device.ip_address
            << ", mac=" << device.mac_address
            << ", vendor=" << device.vendor_hint
            << ", type=" << device.device_type << "\n";
    }
    if (!result.warnings.empty()) {
        oss << "\n## Warnings\n\n";
        for (const auto& warning : result.warnings) {
            oss << "- " << warning << "\n";
        }
    }
    if (!result.limitations.empty()) {
        oss << "\n## Limitations\n\n";
        for (const auto& limitation : result.limitations) {
            oss << "- " << limitation << "\n";
        }
    }
    return oss.str();
}

SecurityHealthCheckResult run_security_health_check(const SecurityHealthCheckConfig& config) {
    if (!config.mock_mode) {
        return {
            .success = false,
            .persisted = false,
            .score = 0,
            .grade = "unknown",
            .components = {},
            .recommendations = {
                "Security health check is mock-safe-only in this stage; rerun with --mock."
            },
            .message = "Security health check is currently mock-only; use --mock."
        };
    }

    const std::string storage_db_path = config.storage_db_path.empty()
        ? std::string{"netsentinel11_storage.db"}
        : config.storage_db_path;
    const auto records = read_camera_inventory_records(storage_db_path, false);

    std::size_t unknown_devices = 0;
    std::size_t risky_port_count = 0;
    std::size_t outdated_fingerprints = 0;
    std::size_t important_offline = 0;
    for (const auto& record : records) {
        const bool approved = has_approval_label(record);
        if (!approved && (record.device_type.empty() || contains_any_token_ci(record.device_type, {"unknown", "generic"}))) {
            ++unknown_devices;
        }
        for (const auto port : record.open_tcp_ports) {
            if (port == 21 || port == 23 || port == 3389 || port == 554 || port == 8554 || port == 37777) {
                ++risky_port_count;
            }
        }
        if (contains_any_token_ci(record.details, {"outdated", "cve", "eol", "unsupported", "firmware v1.0"})) {
            ++outdated_fingerprints;
        }
        if (record.importance >= 70 && contains_any_token_ci(record.details, {"offline", "down", "stale", "unreachable"})) {
            ++important_offline;
        }
    }

    std::vector<SecurityScoreComponent> components;
    std::vector<std::string> recommendations;

    add_score_component(
        components,
        "unknown-devices",
        static_cast<int>(std::min<std::size_t>(unknown_devices * 6, 18)),
        18,
        unknown_devices == 0 ? "ok" : "review",
        std::to_string(unknown_devices) + " visible device(s) lack approval or a specific type."
    );
    if (unknown_devices > 0) {
        recommendations.push_back("Review unknown devices and add labels once ownership is confirmed.");
    }

    add_score_component(
        components,
        "risky-ports",
        static_cast<int>(std::min<std::size_t>(risky_port_count * 4, 16)),
        16,
        risky_port_count == 0 ? "ok" : "review",
        std::to_string(risky_port_count) + " risky service hint(s) found in inventory metadata."
    );
    if (risky_port_count > 0) {
        recommendations.push_back("Close or restrict unused risky services such as Telnet, FTP, RDP, RTSP, or camera vendor ports.");
    }

    RouterSecurityConfig router_config{};
    router_config.mock_mode = true;
    router_config.gateway = config.gateway.empty() ? std::string{"192.168.1.1"} : config.gateway;
    const auto router = run_router_security_check(router_config);
    const int router_penalty = router.success ? std::clamp(router.risk_score / 4, 0, 25) : 10;
    add_score_component(
        components,
        "router-exposure",
        router_penalty,
        25,
        router_penalty == 0 ? "ok" : "risk",
        router.success
            ? "Router exposure score " + std::to_string(router.risk_score) + " from " + std::to_string(router.findings.size()) + " finding(s)."
            : "Router exposure check did not complete: " + router.message
    );
    if (router_penalty > 0) {
        recommendations.push_back("Review router admin, UPnP/NAT-PMP, weak protocol, and firmware exposure findings.");
    }

    DnsBenchmarkConfig dns_config{};
    dns_config.mock_mode = true;
    dns_config.resolvers = {"8.8.8.8", "1.1.1.1"};
    dns_config.queries = {"localhost", "example.com"};
    dns_config.samples = 2;
    const auto dns = run_dns_benchmark(dns_config);
    double worst_failure_rate = 0.0;
    for (const auto& result : dns.results) {
        worst_failure_rate = std::max(worst_failure_rate, result.failure_rate);
    }
    const int dns_penalty = static_cast<int>(std::clamp(worst_failure_rate * 12.0, 0.0, 12.0));
    add_score_component(
        components,
        "dns-reliability",
        dns.success ? dns_penalty : 8,
        12,
        dns_penalty == 0 ? "ok" : "degraded",
        dns.success
            ? "Worst resolver failure rate is " + std::to_string(worst_failure_rate) + "."
            : "DNS benchmark did not complete: " + dns.message
    );

    const auto outage_count = count_recent_history_command("outage-check", "outage");
    add_score_component(
        components,
        "outage-frequency",
        static_cast<int>(std::min<std::size_t>(outage_count * 5, 15)),
        15,
        outage_count == 0 ? "ok" : "unstable",
        std::to_string(outage_count) + " recent outage-like diagnostic event(s) in local history."
    );

    WifiScanConfig wifi_config{};
    wifi_config.mock_mode = true;
    wifi_config.include_hidden = true;
    const auto wifi = run_wifi_channel_analysis(wifi_config);
    const int wifi_penalty = wifi.success
        ? static_cast<int>(std::min<std::size_t>(wifi.insecure_network_count * 6 + wifi.weak_signal_count * 2, 14))
        : 6;
    add_score_component(
        components,
        "wifi-security",
        wifi_penalty,
        14,
        wifi_penalty == 0 ? "ok" : "review",
        wifi.success
            ? std::to_string(wifi.insecure_network_count) + " insecure and " + std::to_string(wifi.weak_signal_count) + " weak-signal Wi-Fi network(s)."
            : "Wi-Fi analysis did not complete: " + wifi.message
    );
    if (wifi_penalty > 0) {
        recommendations.push_back("Prefer WPA2/WPA3 networks and address weak Wi-Fi signal areas.");
    }

    add_score_component(
        components,
        "outdated-fingerprints",
        static_cast<int>(std::min<std::size_t>(outdated_fingerprints * 8, 16)),
        16,
        outdated_fingerprints == 0 ? "ok" : "review",
        std::to_string(outdated_fingerprints) + " device(s) mention outdated, EOL, CVE, or unsupported firmware metadata."
    );
    if (outdated_fingerprints > 0) {
        recommendations.push_back("Update or replace devices with outdated firmware or lifecycle warnings.");
    }

    add_score_component(
        components,
        "important-devices-offline",
        static_cast<int>(std::min<std::size_t>(important_offline * 7, 14)),
        14,
        important_offline == 0 ? "ok" : "attention",
        std::to_string(important_offline) + " important device(s) appear offline or stale."
    );
    if (important_offline > 0) {
        recommendations.push_back("Check important offline devices before relying on the network health score.");
    }

    HiddenCameraDetectorConfig camera_config{};
    camera_config.mock_mode = true;
    camera_config.storage_db_path = storage_db_path;
    const auto camera = run_hidden_camera_detector(camera_config);
    const int camera_penalty = camera.success
        ? static_cast<int>(std::min<std::size_t>(camera.findings.size() * 4, 12))
        : 4;
    add_score_component(
        components,
        "camera-risk",
        camera_penalty,
        12,
        camera_penalty == 0 ? "ok" : "review",
        camera.success
            ? std::to_string(camera.findings.size()) + " possible, likely, or approved camera-like device(s) identified."
            : "Hidden camera detector did not complete: " + camera.message
    );

    int total_penalty = 0;
    for (const auto& component : components) {
        total_penalty += component.penalty;
    }
    const int score = std::clamp(100 - total_penalty, 0, 100);
    if (recommendations.empty()) {
        recommendations.push_back("No urgent actions from mock health inputs; keep inventory labels current.");
    }

    append_history("security-health", storage_db_path, score >= 75 ? "ok" : "review", "score=" + std::to_string(score));
    prune_history(128);

    return {
        .success = true,
        .persisted = true,
        .score = score,
        .grade = security_grade_for_score(score),
        .components = std::move(components),
        .recommendations = std::move(recommendations),
        .message = "mock-security-health"
    };
}

std::string control_lower_copy(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char ch : text) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

bool control_contains_any_ci(std::string_view text, const std::vector<std::string_view>& tokens) {
    const auto lower = control_lower_copy(text);
    for (const auto token : tokens) {
        if (lower.find(token) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string normalize_control_backend(std::string_view backend) {
    const auto lower = control_lower_copy(backend);
    if (lower.empty() || lower == "advice" || lower == "advisory") {
        return "advisory";
    }
    if (lower == "windows-firewall" || lower == "windows-firewall-local" || lower == "firewall" || lower == "local-firewall") {
        return "windows-firewall-local";
    }
    if (lower == "router" || lower == "router-plugin" || lower == "router-stub") {
        return "router-plugin";
    }
    return lower;
}

std::string normalize_control_action(std::string_view action) {
    const auto lower = control_lower_copy(action);
    if (lower.empty()) {
        return "block";
    }
    if (lower == "deny") {
        return "block";
    }
    if (lower == "rate-limit" || lower == "throttle") {
        return "limit";
    }
    if (lower == "allow") {
        return "unblock";
    }
    return lower;
}

std::vector<std::string> default_control_safety_guards() {
    return {
        "No ARP spoofing, deauthentication, MITM, traffic interception, or packet injection is implemented or permitted.",
        "Actions are dry-run unless an apply path is explicitly requested and confirmed.",
        "The Windows Firewall backend only affects traffic on this PC; it cannot disconnect other devices from the LAN.",
        "Router-control support is a credential-gated plugin stub in this stage and does not change router settings."
    };
}

std::string control_target_label(const InternetControlConfig& config) {
    if (!config.target_ip.empty()) {
        return config.target_ip;
    }
    if (!config.device_id.empty()) {
        return config.device_id;
    }
    if (!config.target_label.empty()) {
        return config.target_label;
    }
    return {};
}

std::string control_limit_detail(const InternetControlConfig& config) {
    if (config.download_limit_kbps <= 0 && config.upload_limit_kbps <= 0) {
        return "no bandwidth limit values were requested";
    }
    std::vector<std::string> parts;
    if (config.download_limit_kbps > 0) {
        parts.push_back("download=" + std::to_string(config.download_limit_kbps) + "kbps");
    }
    if (config.upload_limit_kbps > 0) {
        parts.push_back("upload=" + std::to_string(config.upload_limit_kbps) + "kbps");
    }
    std::ostringstream out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            out << ", ";
        }
        out << parts[i];
    }
    return out.str();
}

InternetControlResult make_control_failure(
    const std::string& backend,
    const std::string& action,
    bool dry_run,
    bool confirm_required,
    std::vector<std::string> safety_guards,
    std::vector<std::string> limitations,
    const std::string& target,
    const std::string& status,
    const std::string& message
) {
    append_history("internet-control", target.empty() ? "(none)" : target, status, "backend=" + backend + ",action=" + action);
    prune_history(128);
    return {
        .success = false,
        .persisted = true,
        .backend = backend,
        .action = action,
        .dry_run = dry_run,
        .confirm_required = confirm_required,
        .applied = false,
        .safe_backend = false,
        .steps = {},
        .safety_guards = std::move(safety_guards),
        .limitations = std::move(limitations),
        .message = message
    };
}

InternetControlResult run_internet_control(const InternetControlConfig& config) {
    const std::string backend = normalize_control_backend(config.backend);
    const std::string action = normalize_control_action(config.action);
    const std::string target = control_target_label(config);
    std::vector<std::string> safety_guards = default_control_safety_guards();
    std::vector<std::string> limitations;

    if (control_contains_any_ci(
            config.requested_method + " " + config.backend + " " + config.action,
            {"arp-spoof", "arp spoof", "spoofing", "deauth", "deauthentication", "mitm", "man-in-the-middle", "evil twin", "packet injection"}
        )) {
        limitations.push_back("Unsafe network disruption methods are outside the project safety contract.");
        return make_control_failure(
            backend,
            action,
            true,
            false,
            std::move(safety_guards),
            std::move(limitations),
            target,
            "forbidden",
            "Requested control method is forbidden by the safety contract."
        );
    }

    if (backend != "advisory" && backend != "windows-firewall-local" && backend != "router-plugin") {
        limitations.push_back("Supported backends are advisory, windows-firewall-local, and router-plugin.");
        return make_control_failure(
            backend,
            action,
            true,
            false,
            std::move(safety_guards),
            std::move(limitations),
            target,
            "blocked",
            "Unsupported internet control backend."
        );
    }

    if (action != "block" && action != "unblock" && action != "limit") {
        limitations.push_back("Supported actions are block, unblock, and limit.");
        return make_control_failure(
            backend,
            action,
            true,
            false,
            std::move(safety_guards),
            std::move(limitations),
            target,
            "blocked",
            "Unsupported internet control action."
        );
    }

    if (target.empty()) {
        limitations.push_back("A target IP, device id, or label is required before a control plan can be produced.");
        return make_control_failure(
            backend,
            action,
            true,
            false,
            std::move(safety_guards),
            std::move(limitations),
            target,
            "blocked",
            "Missing control target."
        );
    }

    if (action == "limit" && config.download_limit_kbps <= 0 && config.upload_limit_kbps <= 0) {
        limitations.push_back("Internet limit actions require --download-kbps and/or --upload-kbps.");
        return make_control_failure(
            backend,
            action,
            true,
            false,
            std::move(safety_guards),
            std::move(limitations),
            target,
            "blocked",
            "Missing bandwidth limit values."
        );
    }

    InternetControlResult out{};
    out.success = true;
    out.persisted = true;
    out.backend = backend;
    out.action = action;
    out.dry_run = true;
    out.confirm_required = false;
    out.applied = false;
    out.safe_backend = true;
    out.safety_guards = safety_guards;

    if (backend == "advisory") {
        out.limitations.push_back("Advisory backend never changes firewall, router, Wi-Fi, ARP, or endpoint state.");
        if (action == "limit") {
            out.steps.push_back({
                .backend = backend,
                .action = action,
                .target = target,
                .status = "advisory",
                .detail = "Document requested internet limit (" + control_limit_detail(config) + ") for a router plugin, parent-control workflow, or human-reviewed router UI change."
            });
        } else {
            out.steps.push_back({
                .backend = backend,
                .action = action,
                .target = target,
                .status = "advisory",
                .detail = "Create a human-readable control recommendation only; no traffic is modified."
            });
        }
        out.message = "Advisory control plan generated without changing network state.";
        append_history("internet-control", target, "advisory", "backend=advisory,action=" + action);
        prune_history(128);
        return out;
    }

    if (backend == "windows-firewall-local") {
        if (config.target_ip.empty()) {
            out.success = false;
            out.safe_backend = true;
            out.limitations.push_back("Windows Firewall rules require a concrete remote IP address for this safe backend.");
            out.message = "Windows Firewall backend requires --target-ip.";
            append_history("internet-control", target, "blocked", "backend=windows-firewall-local,missing-ip");
            prune_history(128);
            return out;
        }
        if (action == "limit") {
            out.success = false;
            out.safe_backend = true;
            out.limitations.push_back("Windows Firewall can block or unblock remote addresses for this PC, but it cannot provide per-device bandwidth limits.");
            out.steps.push_back({
                .backend = backend,
                .action = action,
                .target = target,
                .status = "unsupported",
                .detail = "Use advisory mode or a future credentialed router plugin for bandwidth limits."
            });
            out.message = "Windows Firewall backend does not support bandwidth limits.";
            append_history("internet-control", target, "blocked", "backend=windows-firewall-local,limit-unsupported");
            prune_history(128);
            return out;
        }

        out.steps.push_back({
            .backend = backend,
            .action = action,
            .target = target,
            .status = "planned",
            .detail = std::string{"Plan outbound Windows Firewall "} + (action == "block" ? "block" : "unblock") + " rule for remote address " + config.target_ip + "."
        });
        out.steps.push_back({
            .backend = backend,
            .action = action,
            .target = target,
            .status = "planned",
            .detail = "Plan inbound companion rule review so only this PC's local traffic policy changes."
        });

        if (!config.dry_run && !config.confirm) {
            out.success = false;
            out.confirm_required = true;
            out.dry_run = true;
            out.message = "Apply requested, but confirmation is missing. Re-run with --confirm to acknowledge the local firewall change.";
            append_history("internet-control", target, "blocked", "backend=windows-firewall-local,need-confirm");
            prune_history(128);
            return out;
        }

        if (!config.dry_run && config.confirm && config.mock_mode) {
            out.dry_run = false;
            out.applied = true;
            out.steps.push_back({
                .backend = backend,
                .action = action,
                .target = target,
                .status = "mock-applied",
                .detail = "Mock mode accepted the Windows Firewall request; no firewall rules were changed."
            });
            out.message = "Mock Windows Firewall control action accepted safely.";
            append_history("internet-control", target, "mock-applied", "backend=windows-firewall-local,action=" + action);
            prune_history(128);
            return out;
        }

        if (!config.dry_run && config.confirm && !config.mock_mode) {
            out.success = false;
            out.dry_run = true;
            out.applied = false;
            out.limitations.push_back("Non-mock Windows Firewall apply requires an elevated service path that is intentionally not invoked by this prompt-stage CLI.");
            out.message = "Windows Firewall apply is not enabled from this CLI yet; dry-run planning is available.";
            append_history("internet-control", target, "blocked", "backend=windows-firewall-local,apply-not-enabled");
            prune_history(128);
            return out;
        }

        out.dry_run = true;
        out.message = "Windows Firewall dry-run plan generated for this PC only.";
        append_history("internet-control", target, "dry-run", "backend=windows-firewall-local,action=" + action);
        prune_history(128);
        return out;
    }

    if (backend == "router-plugin") {
        if (config.router_username.empty() || config.router_password.empty()) {
            out.success = false;
            out.safe_backend = true;
            out.confirm_required = false;
            out.limitations.push_back("Router plugin controls require explicit operator-supplied credentials; no default credentials are attempted.");
            out.message = "Router plugin backend requires --router-user and --router-password.";
            append_history("internet-control", target, "blocked", "backend=router-plugin,missing-credentials");
            prune_history(128);
            return out;
        }

        out.limitations.push_back("Router plugin backend is a stub in this stage and does not log in to or modify routers.");
        out.steps.push_back({
            .backend = backend,
            .action = action,
            .target = target,
            .status = "stub-planned",
            .detail = std::string{"Credential-gated router plugin plan prepared using plugin '"} + (config.router_plugin.empty() ? "generic-router" : config.router_plugin) + "'."
        });
        if (action == "limit") {
            out.steps.push_back({
                .backend = backend,
                .action = action,
                .target = target,
                .status = "stub-planned",
                .detail = "Requested internet limit: " + control_limit_detail(config) + "."
            });
        }

        if (!config.dry_run) {
            out.success = false;
            out.dry_run = true;
            out.applied = false;
            out.confirm_required = !config.confirm;
            out.message = config.confirm
                ? "Router plugin apply is not implemented in this safe stage; dry-run stub only."
                : "Router plugin apply requested, but --confirm is missing and apply is stubbed in this stage.";
            append_history("internet-control", target, "blocked", "backend=router-plugin,apply-stub");
            prune_history(128);
            return out;
        }

        out.dry_run = true;
        out.message = "Router plugin dry-run stub generated with explicit credentials present.";
        append_history("internet-control", target, "dry-run", "backend=router-plugin,action=" + action);
        prune_history(128);
        return out;
    }

    limitations.push_back("Internal control dispatch reached an unsupported backend.");
    return make_control_failure(
        backend,
        action,
        true,
        false,
        std::move(safety_guards),
        std::move(limitations),
        target,
        "blocked",
        "Internal internet control dispatch error."
    );
}

bool parse_time_of_day_minutes(std::string_view text, int& minutes_out) {
    if (text.size() < 4) {
        return false;
    }
    const auto colon = text.find(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 >= text.size()) {
        return false;
    }
    try {
        const int hours = std::stoi(std::string{text.substr(0, colon)});
        const int minutes = std::stoi(std::string{text.substr(colon + 1, 2)});
        if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) {
            return false;
        }
        minutes_out = hours * 60 + minutes;
        return true;
    } catch (...) {
        return false;
    }
}

std::string extract_time_token(std::string_view now_local) {
    if (now_local.empty()) {
        const auto now = std::chrono::system_clock::now();
        const auto local = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &local);
#else
        localtime_r(&local, &tm);
#endif
        char out[8];
        std::strftime(out, sizeof(out), "%H:%M", &tm);
        return std::string{out};
    }
    const auto t_pos = now_local.find('T');
    if (t_pos != std::string_view::npos &&
        t_pos > 0 &&
        t_pos + 5 < now_local.size() &&
        std::isdigit(static_cast<unsigned char>(now_local[t_pos + 1])) &&
        std::isdigit(static_cast<unsigned char>(now_local[t_pos + 2]))) {
        return std::string{now_local.substr(t_pos + 1, 5)};
    }
    const auto space_pos = now_local.rfind(' ');
    if (space_pos != std::string_view::npos && space_pos + 1 < now_local.size()) {
        return std::string{now_local.substr(space_pos + 1, 5)};
    }
    return std::string{now_local.substr(0, std::min<std::size_t>(now_local.size(), 5))};
}

std::string extract_day_token(std::string_view now_local) {
    const auto space_pos = now_local.find(' ');
    if (space_pos == std::string_view::npos) {
        return {};
    }
    return control_lower_copy(now_local.substr(0, space_pos));
}

bool downtime_days_match(std::string_view days, std::string_view now_local) {
    const auto lower_days = control_lower_copy(days);
    if (lower_days.empty() || lower_days == "all" || lower_days == "everyday" || lower_days == "*") {
        return true;
    }
    const auto day = extract_day_token(now_local);
    if (day.empty()) {
        return true;
    }
    return lower_days.find(day) != std::string::npos;
}

bool downtime_window_active(const ParentalDowntimeWindow& window, std::string_view now_local, std::string& detail) {
    if (!window.enabled) {
        detail = "window disabled";
        return false;
    }
    if (!downtime_days_match(window.days, now_local)) {
        detail = "day not selected";
        return false;
    }

    int start_minutes = 0;
    int end_minutes = 0;
    int now_minutes = 0;
    const auto now_token = extract_time_token(now_local);
    if (!parse_time_of_day_minutes(window.start_local, start_minutes) ||
        !parse_time_of_day_minutes(window.end_local, end_minutes) ||
        !parse_time_of_day_minutes(now_token, now_minutes)) {
        detail = "invalid time format; expected HH:MM";
        return false;
    }

    if (start_minutes == end_minutes) {
        detail = "zero-length downtime window";
        return false;
    }

    const bool active = start_minutes < end_minutes
        ? (now_minutes >= start_minutes && now_minutes < end_minutes)
        : (now_minutes >= start_minutes || now_minutes < end_minutes);
    detail = active
        ? "current local time is inside downtime window"
        : "current local time is outside downtime window";
    return active;
}

std::string downtime_assignment_target(const ParentalDowntimeAssignment& assignment) {
    if (!assignment.target_ip.empty()) {
        return assignment.target_ip;
    }
    if (!assignment.device_id.empty()) {
        return assignment.device_id;
    }
    if (!assignment.label.empty()) {
        return assignment.label;
    }
    if (!assignment.user.empty()) {
        return "user:" + assignment.user;
    }
    if (!assignment.group.empty()) {
        return "group:" + assignment.group;
    }
    return "(unassigned)";
}

ParentalDowntimeAuditEvent make_downtime_audit_event(
    const std::string& schedule_id,
    const std::string& event,
    const std::string& detail
) {
    return {
        .timestamp_utc = now_utc_iso8601(),
        .schedule_id = schedule_id,
        .event = event,
        .detail = detail
    };
}

ParentalDowntimeResult run_parental_downtime_schedule(const ParentalDowntimeConfig& config) {
    ParentalDowntimeResult out{};
    out.success = false;
    out.persisted = false;
    out.schedule_id = config.schedule_id.empty() ? std::string{"default"} : config.schedule_id;
    out.emergency_disabled = config.emergency_disable;
    out.advisory_only = true;

    if (!config.mock_mode) {
        out.limitations.push_back("Parental downtime scheduling is mock/dry-run only in this stage; use --mock for deterministic verification.");
        out.message = "Parental downtime scheduling is currently mock-only; use --mock.";
        append_history("parental-downtime", out.schedule_id, "blocked", "mock-required");
        prune_history(128);
        return out;
    }

    if (config.windows.empty()) {
        out.limitations.push_back("At least one downtime window is required.");
        out.message = "No downtime windows were configured.";
        append_history("parental-downtime", out.schedule_id, "blocked", "windows=0");
        prune_history(128);
        return out;
    }

    if (config.assignments.empty()) {
        out.limitations.push_back("At least one user, group, device, or target IP assignment is required.");
        out.message = "No downtime assignments were configured.";
        append_history("parental-downtime", out.schedule_id, "blocked", "assignments=0");
        prune_history(128);
        return out;
    }

    std::vector<std::string> window_details;
    bool any_window_active = false;
    for (const auto& window : config.windows) {
        std::string detail;
        const bool active = downtime_window_active(window, config.now_local, detail);
        window_details.push_back(window.start_local + "-" + window.end_local + ": " + detail);
        any_window_active = any_window_active || active;
    }

    out.downtime_active = any_window_active && !config.emergency_disable;
    out.audit_events.push_back(make_downtime_audit_event(
        out.schedule_id,
        "schedule-evaluated",
        std::string{"windows="} + std::to_string(config.windows.size()) +
            ", assignments=" + std::to_string(config.assignments.size()) +
            ", active=" + (out.downtime_active ? "true" : "false")
    ));

    if (config.emergency_disable) {
        out.audit_events.push_back(make_downtime_audit_event(
            out.schedule_id,
            "emergency-disable",
            "Emergency disable is active; downtime blocks are suppressed and unblock is requested where safe."
        ));
        out.limitations.push_back("Emergency disable is active; no block action will be requested.");
    }

    for (const auto& detail : window_details) {
        out.audit_events.push_back(make_downtime_audit_event(out.schedule_id, "window-check", detail));
    }

    for (const auto& assignment : config.assignments) {
        ParentalDowntimeDecision decision{};
        decision.assignment = assignment;
        decision.downtime_active = out.downtime_active;
        decision.advisory_only = true;
        decision.requested_action = out.downtime_active ? "block" : "unblock";
        decision.detail = config.emergency_disable
            ? "Emergency disable requested safe unblock/advisory state."
            : (out.downtime_active ? "Downtime window active; safe backend block requested." : "Downtime inactive; safe backend unblock/advisory state requested.");

        InternetControlConfig control{};
        control.mock_mode = config.mock_mode;
        control.backend = config.backend.empty() ? std::string{"advisory"} : config.backend;
        control.action = decision.requested_action;
        control.target_ip = assignment.target_ip;
        control.device_id = assignment.device_id;
        control.target_label = downtime_assignment_target(assignment);
        control.requested_method = "parental-downtime-safe-control";
        control.dry_run = config.dry_run;
        control.confirm = config.confirm;
        decision.control = run_internet_control(control);

        if (decision.control.success) {
            decision.advisory_only = decision.control.backend == "advisory" || !decision.control.applied;
            out.advisory_only = out.advisory_only && decision.advisory_only;
        } else {
            decision.advisory_only = true;
            out.limitations.push_back("Safe backend unavailable for " + downtime_assignment_target(assignment) + ": " + decision.control.message);
        }

        out.audit_events.push_back(make_downtime_audit_event(
            out.schedule_id,
            "assignment-decision",
            downtime_assignment_target(assignment) + " action=" + decision.requested_action +
                ", advisory=" + (decision.advisory_only ? "true" : "false")
        ));
        out.decisions.push_back(std::move(decision));
    }

    append_history(
        "parental-downtime",
        out.schedule_id,
        out.downtime_active ? "active" : (config.emergency_disable ? "emergency-disabled" : "inactive"),
        "decisions=" + std::to_string(out.decisions.size()) + ",advisory=" + (out.advisory_only ? "true" : "false")
    );
    prune_history(128);

    out.success = true;
    out.persisted = true;
    out.message = config.emergency_disable
        ? "Emergency disable evaluated; safe unblock/advisory decisions generated."
        : "Parental downtime schedule evaluated with safe control backends.";
    return out;
}

std::uint64_t mib_bytes(std::uint64_t value) {
    return value * 1024ULL * 1024ULL;
}

std::uint64_t gib_bytes(std::uint64_t value) {
    return value * 1024ULL * 1024ULL * 1024ULL;
}

std::string normalize_usage_profile(std::string_view profile) {
    const auto lower = control_lower_copy(profile);
    if (lower.empty()) {
        return "family";
    }
    if (lower == "kid" || lower == "kids" || lower == "child" || lower == "children") {
        return "family";
    }
    if (lower == "guests") {
        return "guest";
    }
    if (lower == "office" || lower == "work-device" || lower == "work-devices") {
        return "work";
    }
    return lower;
}

std::uint64_t default_quota_for_profile(std::string_view profile) {
    const auto normalized = normalize_usage_profile(profile);
    if (normalized == "guest") {
        return gib_bytes(1);
    }
    if (normalized == "work") {
        return gib_bytes(10);
    }
    return gib_bytes(3);
}

std::uint64_t default_warning_for_quota(std::uint64_t quota_bytes) {
    if (quota_bytes == 0) {
        return 0;
    }
    return (quota_bytes * 4ULL) / 5ULL;
}

std::vector<UsagePolicyRule> default_usage_policy_rules() {
    return {
        UsagePolicyRule{
            .rule_id = "family-daily",
            .profile = "family",
            .group = "family",
            .schedule_days = "all",
            .schedule_window = "00:00-23:59",
            .quota_bytes = gib_bytes(3),
            .warning_threshold_bytes = mib_bytes(2400),
            .enabled = true
        },
        UsagePolicyRule{
            .rule_id = "guest-daily",
            .profile = "guest",
            .group = "guest",
            .schedule_days = "all",
            .schedule_window = "00:00-23:59",
            .quota_bytes = gib_bytes(1),
            .warning_threshold_bytes = mib_bytes(800),
            .enabled = true
        },
        UsagePolicyRule{
            .rule_id = "work-hours",
            .profile = "work",
            .group = "work",
            .schedule_days = "mon,tue,wed,thu,fri",
            .schedule_window = "08:00-18:00",
            .quota_bytes = gib_bytes(10),
            .warning_threshold_bytes = gib_bytes(8),
            .enabled = true
        }
    };
}

std::vector<UsagePolicyObservation> default_usage_policy_observations() {
    return {
        UsagePolicyObservation{
            .device_id = "family-tablet",
            .group = "family",
            .target_ip = "192.168.50.130",
            .used_bytes = mib_bytes(2600),
            .source = "mock-bandwidth-rollup"
        },
        UsagePolicyObservation{
            .device_id = "guest-phone",
            .group = "guest",
            .target_ip = "192.168.50.223",
            .used_bytes = mib_bytes(1250),
            .source = "mock-bandwidth-rollup"
        },
        UsagePolicyObservation{
            .device_id = "work-laptop",
            .group = "work",
            .target_ip = "192.168.50.30",
            .used_bytes = gib_bytes(3),
            .source = "mock-bandwidth-rollup"
        }
    };
}

bool parse_usage_window(std::string_view text, ParentalDowntimeWindow& window) {
    const auto dash = text.find('-');
    if (dash == std::string_view::npos || dash == 0 || dash + 1 >= text.size()) {
        return false;
    }
    window.start_local = std::string{text.substr(0, dash)};
    window.end_local = std::string{text.substr(dash + 1)};
    return !window.start_local.empty() && !window.end_local.empty();
}

bool usage_rule_active(const UsagePolicyRule& rule, std::string_view now_local, std::string& detail) {
    if (!rule.enabled) {
        detail = "rule disabled";
        return false;
    }
    ParentalDowntimeWindow window{};
    window.days = rule.schedule_days.empty() ? std::string{"all"} : rule.schedule_days;
    window.enabled = true;
    if (!parse_usage_window(rule.schedule_window.empty() ? std::string_view{"00:00-23:59"} : std::string_view{rule.schedule_window}, window)) {
        detail = "invalid policy window; expected HH:MM-HH:MM";
        return false;
    }
    return downtime_window_active(window, now_local, detail);
}

bool usage_observation_matches_rule(const UsagePolicyRule& rule, const UsagePolicyObservation& observation) {
    bool has_selector = false;
    if (!rule.device_id.empty()) {
        has_selector = true;
        if (rule.device_id != observation.device_id) {
            return false;
        }
    }
    if (!rule.group.empty()) {
        has_selector = true;
        if (rule.group != observation.group) {
            return false;
        }
    }
    if (!rule.target_ip.empty()) {
        has_selector = true;
        if (rule.target_ip != observation.target_ip) {
            return false;
        }
    }
    if (!has_selector) {
        return normalize_usage_profile(rule.profile) == normalize_usage_profile(observation.group);
    }
    return true;
}

std::string usage_subject_for_observation(const UsagePolicyRule& rule, const UsagePolicyObservation& observation) {
    if (!observation.target_ip.empty()) {
        return observation.target_ip;
    }
    if (!observation.device_id.empty()) {
        return observation.device_id;
    }
    if (!observation.group.empty()) {
        return "group:" + observation.group;
    }
    if (!rule.target_ip.empty()) {
        return rule.target_ip;
    }
    if (!rule.device_id.empty()) {
        return rule.device_id;
    }
    if (!rule.group.empty()) {
        return "group:" + rule.group;
    }
    return "profile:" + normalize_usage_profile(rule.profile);
}

UsagePolicyDecision make_usage_policy_decision(
    const UsagePolicyRule& raw_rule,
    const UsagePolicyObservation& observation,
    bool active,
    const std::string& active_detail
) {
    UsagePolicyRule rule = raw_rule;
    rule.profile = normalize_usage_profile(rule.profile);
    if (rule.rule_id.empty()) {
        rule.rule_id = rule.profile + "-quota";
    }
    if (rule.quota_bytes == 0) {
        rule.quota_bytes = default_quota_for_profile(rule.profile);
    }
    if (rule.warning_threshold_bytes == 0 || rule.warning_threshold_bytes > rule.quota_bytes) {
        rule.warning_threshold_bytes = default_warning_for_quota(rule.quota_bytes);
    }

    UsagePolicyDecision decision{};
    decision.rule_id = rule.rule_id;
    decision.profile = rule.profile;
    decision.subject = usage_subject_for_observation(rule, observation);
    decision.quota_bytes = rule.quota_bytes;
    decision.used_bytes = observation.used_bytes;
    decision.remaining_bytes = observation.used_bytes >= rule.quota_bytes ? 0 : (rule.quota_bytes - observation.used_bytes);
    decision.enforcement_requested = false;

    if (!active) {
        decision.state = "inactive";
        decision.explanation = "Policy schedule is inactive: " + active_detail + ". No block, throttle, or router change was attempted.";
        return decision;
    }

    if (observation.used_bytes >= rule.quota_bytes) {
        decision.state = "quota-exceeded";
        decision.enforcement_requested = true;
        decision.explanation = "Usage is at or above the configured quota. This stage records an advisory enforcement request only; no traffic is blocked or throttled.";
        return decision;
    }

    if (observation.used_bytes >= rule.warning_threshold_bytes) {
        decision.state = "warning";
        decision.explanation = "Usage passed the warning threshold but remains below quota. This is an advisory warning only; no enforcement is attempted.";
        return decision;
    }

    decision.state = "ok";
    decision.explanation = "Usage remains below the warning threshold. No enforcement is needed.";
    return decision;
}

UsagePolicyResult evaluate_usage_policy(const UsagePolicyConfig& config) {
    UsagePolicyResult out{};
    out.success = false;
    out.persisted = false;
    out.advisory_only = true;

    if (!config.mock_mode) {
        out.limitations.push_back("Usage policy evaluation is advisory/mock-only in this stage; use --mock for deterministic verification.");
        out.message = "Usage policy engine is currently mock-only and does not read live router counters.";
        append_history("usage-policy", "advisory", "blocked", "mock-required");
        prune_history(128);
        return out;
    }

    auto rules = config.rules.empty() ? default_usage_policy_rules() : config.rules;
    auto observations = config.observations.empty() ? default_usage_policy_observations() : config.observations;
    if (rules.empty()) {
        out.limitations.push_back("At least one usage policy rule is required.");
        out.message = "No usage policy rules were configured.";
        append_history("usage-policy", "advisory", "blocked", "rules=0");
        prune_history(128);
        return out;
    }
    if (observations.empty()) {
        out.limitations.push_back("At least one usage observation is required.");
        out.message = "No usage observations were available.";
        append_history("usage-policy", "advisory", "blocked", "observations=0");
        prune_history(128);
        return out;
    }

    out.limitations.push_back("Advisory only: Prompt 66 never blocks, throttles, changes firewall rules, or changes router settings.");
    out.limitations.push_back("Usage observations are deterministic mock rollups until later safe router or bandwidth backends provide measured counters.");
    out.limitations.push_back("Family, guest, and work profiles are evaluated as policy warnings only.");

    for (const auto& rule : rules) {
        std::string active_detail;
        const bool active = usage_rule_active(rule, config.now_local, active_detail);
        bool matched = false;
        for (const auto& observation : observations) {
            if (!usage_observation_matches_rule(rule, observation)) {
                continue;
            }
            matched = true;
            auto decision = make_usage_policy_decision(rule, observation, active, active_detail);
            if (decision.state == "warning") {
                out.warnings.push_back(decision.subject + " is near quota for " + decision.profile + " profile.");
            }
            if (decision.state == "quota-exceeded") {
                out.warnings.push_back(decision.subject + " exceeded quota for " + decision.profile + " profile; advisory-only enforcement request recorded.");
            }
            out.decisions.push_back(std::move(decision));
        }
        if (!matched) {
            UsagePolicyObservation empty{};
            empty.group = rule.group;
            empty.device_id = rule.device_id;
            empty.target_ip = rule.target_ip;
            auto decision = make_usage_policy_decision(rule, empty, active, active_detail);
            decision.explanation = "No matching usage observation was available. The policy remains advisory and no traffic was changed.";
            out.decisions.push_back(std::move(decision));
        }
    }

    append_history(
        "usage-policy",
        "advisory",
        "ok",
        "decisions=" + std::to_string(out.decisions.size()) + ",advisory=true"
    );
    prune_history(128);

    out.success = true;
    out.persisted = true;
    out.message = "Usage policy evaluated in advisory-only mode; no block or throttle was attempted.";
    return out;
}

} // namespace netsentinel::diagnostics
