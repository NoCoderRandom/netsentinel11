#include "netsentinel/bandwidth/bandwidth_source.h"
#include "netsentinel/storage/storage.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <unordered_map>
#include <utility>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <ws2tcpip.h>
#endif

namespace netsentinel::bandwidth {

namespace {

class MockBandwidthSource final : public IBandwidthSource {
public:
    explicit MockBandwidthSource(MockBandwidthSourceConfig config) : config_(std::move(config)) {}

    BandwidthSourceCapability capability() const override {
        BandwidthSourceCapability capability{};
        capability.source_name = config_.source_name;
        capability.kind = BandwidthSourceKind::mock;
        capability.available = true;
        capability.realtime = true;
        capability.per_device = true;
        capability.aggregate = true;
        capability.requires_admin = false;
        capability.sends_network_traffic = false;
        capability.optional_dependency = false;
        capability.limitations = {
            "Deterministic test data only.",
            "No packets are captured or sent.",
            "Useful for UI, storage, report, and policy tests before real sources exist."
        };
        capability.safe_setup_hint = "Use --mock to verify bandwidth plumbing without touching the network.";
        return capability;
    }

    BandwidthSourceStatus collect_samples() override {
        BandwidthSourceStatus status{};
        status.capability = capability();

        BandwidthSample gateway{};
        gateway.source_name = config_.source_name;
        gateway.timestamp_utc = config_.timestamp_utc;
        gateway.rx_bytes = 53248000;
        gateway.tx_bytes = 11840000;
        gateway.identity.device_id = "mock-router";
        gateway.identity.ip_address = "192.168.50.1";
        gateway.identity.mac_address = "02:50:00:00:00:01";
        gateway.identity.hostname = "gateway";
        gateway.confidence = BandwidthConfidence::high;
        gateway.tags = {"mock", "router", "aggregate"};
        status.samples.push_back(gateway);

        BandwidthSample laptop{};
        laptop.source_name = config_.source_name;
        laptop.timestamp_utc = config_.timestamp_utc;
        laptop.rx_bytes = 18350080;
        laptop.tx_bytes = 9437184;
        laptop.identity.device_id = "mock-laptop";
        laptop.identity.ip_address = "192.168.50.22";
        laptop.identity.mac_address = "02:50:00:00:00:22";
        laptop.identity.hostname = "laptop";
        laptop.confidence = BandwidthConfidence::medium;
        laptop.tags = {"mock", "device"};
        status.samples.push_back(laptop);

        if (config_.include_low_confidence_sample) {
            BandwidthSample unknown{};
            unknown.source_name = config_.source_name;
            unknown.timestamp_utc = config_.timestamp_utc;
            unknown.rx_bytes = 2097152;
            unknown.tx_bytes = 524288;
            unknown.identity.device_id = "mock-unknown";
            unknown.identity.ip_address = "192.168.50.88";
            unknown.identity.mac_address = "02:50:00:00:00:88";
            unknown.identity.hostname = "unknown-device";
            unknown.confidence = BandwidthConfidence::low;
            unknown.tags = {"mock", "low-confidence"};
            status.samples.push_back(unknown);
        }

        for (const auto& sample : status.samples) {
            const auto validation = validate_bandwidth_sample(sample);
            if (validation.code != BandwidthErrorCode::none) {
                status.success = false;
                status.error = validation;
                return status;
            }
        }

        status.success = true;
        return status;
    }

private:
    MockBandwidthSourceConfig config_;
};

BandwidthSourceCapability planned_capability(
    std::string source_name,
    BandwidthSourceKind kind,
    bool per_device,
    bool aggregate,
    bool requires_admin,
    bool optional_dependency,
    std::string dependency_name,
    std::vector<std::string> limitations,
    std::string safe_setup_hint
) {
    BandwidthSourceCapability capability{};
    capability.source_name = std::move(source_name);
    capability.kind = kind;
    capability.available = false;
    capability.realtime = true;
    capability.per_device = per_device;
    capability.aggregate = aggregate;
    capability.requires_admin = requires_admin;
    capability.sends_network_traffic = false;
    capability.optional_dependency = optional_dependency;
    capability.dependency_name = std::move(dependency_name);
    capability.limitations = std::move(limitations);
    capability.safe_setup_hint = std::move(safe_setup_hint);
    return capability;
}

#ifdef _WIN32
std::string wide_to_utf8(const wchar_t* text) {
    if (text == nullptr || text[0] == L'\0') {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return {};
    }
    std::string out(static_cast<std::size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

std::filesystem::path windows_directory() {
    char buffer[MAX_PATH]{};
    const auto length = GetWindowsDirectoryA(buffer, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return std::filesystem::path{"C:\\Windows"};
    }
    return std::filesystem::path{buffer};
}

bool file_exists_no_throw(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

bool current_process_is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    const auto ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

std::vector<NpcapAdapterCapability> enumerate_windows_adapter_hints(bool installed, bool admin) {
    std::vector<NpcapAdapterCapability> out;
    ULONG buffer_size = 15 * 1024;
    std::vector<unsigned char> buffer(buffer_size);
    auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &buffer_size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.assign(buffer_size, 0);
        addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &buffer_size);
    }
    if (result != NO_ERROR) {
        return out;
    }

    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        NpcapAdapterCapability capability{};
        capability.adapter_id = adapter->AdapterName == nullptr ? std::string{} : std::string{adapter->AdapterName};
        capability.display_name = wide_to_utf8(adapter->FriendlyName);
        if (capability.display_name.empty()) {
            capability.display_name = capability.adapter_id;
        }

        const bool unsupported_type = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL;
        const bool down = adapter->OperStatus != IfOperStatusUp;
        capability.permission_granted = admin;
        capability.monitor_mode_supported = false;
        capability.supported = installed && admin && !unsupported_type && !down;

        if (!installed) {
            capability.user_message = "Npcap driver is missing; adapter capture capability is unavailable.";
        } else if (!admin) {
            capability.user_message = "Npcap may require administrator permissions for capture on this adapter.";
        } else if (unsupported_type) {
            capability.user_message = "Unsupported adapter type for packet capture reporting.";
        } else if (down) {
            capability.user_message = "Adapter is not currently up, so capture capability is unavailable.";
        } else {
            capability.user_message = "Adapter is eligible for future authorized capture reporting; no packets are captured in Prompt 53.";
        }
        capability.limitations.push_back("Prompt 53 performs detection only and does not capture packets.");
        capability.limitations.push_back("Monitor mode is not enabled or required for this stage.");
        if (unsupported_type) {
            capability.limitations.push_back("Unsupported adapter types are reported but not used.");
        }
        out.push_back(std::move(capability));
    }
    return out;
}
#else
bool file_exists_no_throw(const std::filesystem::path&) {
    return false;
}

bool current_process_is_elevated() {
    return false;
}

std::vector<NpcapAdapterCapability> enumerate_windows_adapter_hints(bool, bool) {
    return {};
}
#endif

std::vector<NpcapAdapterCapability> mock_npcap_adapters(bool installed, bool admin, bool include_unsupported) {
    std::vector<NpcapAdapterCapability> adapters;

    NpcapAdapterCapability ethernet{};
    ethernet.adapter_id = "mock-ethernet-0";
    ethernet.display_name = "Mock Ethernet";
    ethernet.permission_granted = admin;
    ethernet.monitor_mode_supported = false;
    ethernet.supported = installed && admin;
    ethernet.user_message = ethernet.supported
        ? "Mock adapter is eligible for future authorized capture reporting; no packets are captured in Prompt 53."
        : "Mock adapter capture is unavailable because Npcap is missing or the process is non-admin.";
    ethernet.limitations = {
        "Prompt 53 performs detection only and does not capture packets.",
        "Monitor mode is not enabled or required for this stage."
    };
    adapters.push_back(ethernet);

    if (include_unsupported) {
        NpcapAdapterCapability loopback{};
        loopback.adapter_id = "mock-loopback";
        loopback.display_name = "Mock Loopback";
        loopback.permission_granted = admin;
        loopback.monitor_mode_supported = false;
        loopback.supported = false;
        loopback.user_message = "Unsupported adapter type for packet capture reporting.";
        loopback.limitations = {
            "Unsupported adapter types are reported but not used.",
            "Monitor mode limitations are visible to the user."
        };
        adapters.push_back(loopback);
    }

    return adapters;
}

std::vector<std::string> split_pipe_fields(const std::string& line) {
    std::vector<std::string> fields;
    std::string current;
    for (const char ch : line) {
        if (ch == '|') {
            fields.push_back(current);
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    fields.push_back(current);
    return fields;
}

bool parse_flow_protocol_token(const std::string& value, FlowExportProtocol& protocol) {
    if (value == "netflow") {
        protocol = FlowExportProtocol::netflow;
        return true;
    }
    if (value == "sflow") {
        protocol = FlowExportProtocol::sflow;
        return true;
    }
    if (value == "ipfix") {
        protocol = FlowExportProtocol::ipfix;
        return true;
    }
    return false;
}

std::uint64_t parse_u64_or_zero(const std::string& value) {
    try {
        return static_cast<std::uint64_t>(std::stoull(value));
    } catch (...) {
        return 0;
    }
}

std::string bandwidth_lower_copy(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char ch : text) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

bool bandwidth_contains_any_ci(std::string_view text, const std::vector<std::string_view>& tokens) {
    const auto lower = bandwidth_lower_copy(text);
    for (const auto token : tokens) {
        if (lower.find(token) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string attribution_key_for_sample(const BandwidthSample& sample) {
    if (!sample.identity.mac_address.empty()) {
        return "mac:" + sample.identity.mac_address;
    }
    if (!sample.identity.ip_address.empty()) {
        return "ip:" + sample.identity.ip_address;
    }
    if (!sample.identity.device_id.empty()) {
        return "device:" + sample.identity.device_id;
    }
    return "unknown";
}

int attribution_source_priority(const std::string& source_name) {
    if (source_name == "flow-export-collector" || source_name == "openwrt-readonly-plugin") {
        return 90;
    }
    if (source_name == "snmp-router-counters") {
        return 70;
    }
    if (source_name == "router-plugin") {
        return 65;
    }
    if (source_name == "visible-lan-capture") {
        return 45;
    }
    if (source_name == "local-machine-counters") {
        return 40;
    }
    return 10;
}

std::string attribution_confidence_label(const BandwidthSample& sample) {
    if (sample.source_name == "upnp-igd-counters") {
        return "network-only";
    }
    if (sample.source_name == "local-machine-counters") {
        return "local-host-only";
    }
    if (sample.source_name == "flow-export-collector") {
        return "exact";
    }
    if (sample.source_name == "openwrt-readonly-plugin") {
        return "high";
    }
    return to_string(sample.confidence);
}

BandwidthSourceCapability local_machine_counter_capability(bool available) {
    BandwidthSourceCapability capability{};
    capability.source_name = "local-machine-counters";
    capability.kind = BandwidthSourceKind::local_machine;
    capability.available = available;
    capability.realtime = true;
    capability.per_device = false;
    capability.aggregate = true;
    capability.requires_admin = false;
    capability.sends_network_traffic = false;
    capability.optional_dependency = false;
    capability.safe_setup_hint = "Uses documented Windows interface counters for this PC only.";
    capability.limitations = {
        "Measures the Windows PC running NetSentinel11 only.",
        "Does not measure other LAN devices.",
        "Single reads provide totals; rates require a previous sample and elapsed time."
    };
    return capability;
}

#ifdef _WIN32
std::string local_computer_name() {
    char buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = static_cast<DWORD>(sizeof(buffer));
    if (GetComputerNameA(buffer, &size) && size > 0) {
        return std::string{buffer, buffer + size};
    }
    return "this-windows-pc";
}

BandwidthSourceStatus collect_windows_local_machine_counter_samples(const std::string& timestamp_utc) {
    BandwidthSourceStatus status{};
    status.capability = local_machine_counter_capability(true);

    ULONG table_size = 0;
    auto result = GetIfTable(nullptr, &table_size, FALSE);
    if (result != ERROR_INSUFFICIENT_BUFFER || table_size == 0) {
        status.success = false;
        status.error = {
            .code = BandwidthErrorCode::unavailable,
            .user_message = "Windows local interface counters are unavailable.",
            .technical_detail = "GetIfTable size query failed."
        };
        return status;
    }
    std::vector<unsigned char> table_buffer(table_size);
    auto* table = reinterpret_cast<MIB_IFTABLE*>(table_buffer.data());
    result = GetIfTable(table, &table_size, FALSE);
    if (result != NO_ERROR) {
        status.success = false;
        status.error = {
            .code = BandwidthErrorCode::unavailable,
            .user_message = "Windows local interface counters are unavailable.",
            .technical_detail = "GetIfTable failed."
        };
        return status;
    }

    const auto hostname = local_computer_name();
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwType == IF_TYPE_SOFTWARE_LOOPBACK || row.dwType == IF_TYPE_TUNNEL) {
            continue;
        }

        BandwidthSample sample{};
        sample.source_name = "local-machine-counters";
        sample.timestamp_utc = timestamp_utc;
        sample.rx_bytes = static_cast<std::uint64_t>(row.dwInOctets);
        sample.tx_bytes = static_cast<std::uint64_t>(row.dwOutOctets);
        sample.identity.device_id = "local-machine";
        sample.identity.hostname = hostname;
        sample.confidence = BandwidthConfidence::authoritative;
        sample.tags = {"local-machine", "windows-counter"};
        if (row.dwDescrLen > 0) {
            const auto description_length = static_cast<std::size_t>(row.dwDescrLen);
            const std::string description{
                reinterpret_cast<const char*>(row.bDescr),
                reinterpret_cast<const char*>(row.bDescr) + description_length
            };
            sample.tags.push_back("description:" + description);
        }
        status.samples.push_back(std::move(sample));
    }

    if (status.samples.empty()) {
        status.success = false;
        status.error = {
            .code = BandwidthErrorCode::unavailable,
            .user_message = "No active Windows network interfaces were available for local-machine bandwidth totals.",
            .technical_detail = "GetIfTable2 returned no active non-loopback interfaces."
        };
        return status;
    }

    status.success = true;
    return status;
}
#else
BandwidthSourceStatus collect_windows_local_machine_counter_samples(const std::string&) {
    BandwidthSourceStatus status{};
    status.capability = local_machine_counter_capability(false);
    status.success = false;
    status.error = {
        .code = BandwidthErrorCode::unsupported,
        .user_message = "Local-machine bandwidth counters are only implemented for Windows in this project.",
        .technical_detail = "Non-Windows build."
    };
    return status;
}
#endif

BandwidthSourceStatus collect_mock_local_machine_counter_samples(const std::string& timestamp_utc) {
    BandwidthSourceStatus status{};
    status.capability = local_machine_counter_capability(true);

    BandwidthSample sample{};
    sample.source_name = "local-machine-counters";
    sample.timestamp_utc = timestamp_utc;
    sample.rx_bytes = 440000000;
    sample.tx_bytes = 88000000;
    sample.identity.device_id = "local-machine";
    sample.identity.hostname = "mock-windows-pc";
    sample.identity.ip_address = "192.168.50.10";
    sample.confidence = BandwidthConfidence::authoritative;
    sample.tags = {"mock", "local-machine", "windows-counter"};
    status.samples.push_back(sample);

    status.success = true;
    return status;
}

} // namespace

std::string to_string(BandwidthConfidence confidence) {
    switch (confidence) {
        case BandwidthConfidence::unknown:
            return "unknown";
        case BandwidthConfidence::low:
            return "low";
        case BandwidthConfidence::medium:
            return "medium";
        case BandwidthConfidence::high:
            return "high";
        case BandwidthConfidence::authoritative:
            return "authoritative";
    }
    return "unknown";
}

std::string to_string(BandwidthSourceKind kind) {
    switch (kind) {
        case BandwidthSourceKind::mock:
            return "mock";
        case BandwidthSourceKind::local_machine:
            return "local-machine";
        case BandwidthSourceKind::packet_capture:
            return "packet-capture";
        case BandwidthSourceKind::snmp_router:
            return "snmp-router";
        case BandwidthSourceKind::upnp_igd:
            return "upnp-igd";
        case BandwidthSourceKind::flow_export:
            return "flow-export";
        case BandwidthSourceKind::router_plugin:
            return "router-plugin";
        case BandwidthSourceKind::agent:
            return "agent";
        case BandwidthSourceKind::manual_import:
            return "manual-import";
    }
    return "unknown";
}

std::string to_string(BandwidthErrorCode code) {
    switch (code) {
        case BandwidthErrorCode::none:
            return "none";
        case BandwidthErrorCode::unavailable:
            return "unavailable";
        case BandwidthErrorCode::permission_required:
            return "permission-required";
        case BandwidthErrorCode::unsupported:
            return "unsupported";
        case BandwidthErrorCode::invalid_argument:
            return "invalid-argument";
        case BandwidthErrorCode::source_failed:
            return "source-failed";
    }
    return "unknown";
}

std::string to_string(FlowExportProtocol protocol) {
    switch (protocol) {
        case FlowExportProtocol::netflow:
            return "netflow";
        case FlowExportProtocol::sflow:
            return "sflow";
        case FlowExportProtocol::ipfix:
            return "ipfix";
    }
    return "unknown";
}

std::unique_ptr<IBandwidthSource> make_mock_bandwidth_source(const MockBandwidthSourceConfig& config) {
    return std::make_unique<MockBandwidthSource>(config);
}

BandwidthSourceStatus collect_mock_bandwidth_samples(const MockBandwidthSourceConfig& config) {
    auto source = make_mock_bandwidth_source(config);
    return source->collect_samples();
}

std::vector<BandwidthSourceCapability> list_planned_bandwidth_source_capabilities() {
    std::vector<BandwidthSourceCapability> capabilities;
    capabilities.push_back(make_mock_bandwidth_source()->capability());
    capabilities.push_back(planned_capability(
        "local-machine-counters",
        BandwidthSourceKind::local_machine,
        false,
        true,
        false,
        false,
        "",
        {"Measures this Windows PC only.", "Does not explain traffic from other devices."},
        "Use this source for a safe local baseline before router or capture integrations exist."
    ));
    capabilities.push_back(planned_capability(
        "npcap-visible-lan",
        BandwidthSourceKind::packet_capture,
        true,
        true,
        true,
        true,
        "Npcap",
        {"No packet capture is implemented in Prompt 52.", "Switched LAN visibility is incomplete unless traffic is mirrored or otherwise visible."},
        "Install Npcap only if the user explicitly wants authorized capture in a later prompt."
    ));
    capabilities.push_back(planned_capability(
        "snmp-router-counters",
        BandwidthSourceKind::snmp_router,
        true,
        true,
        false,
        true,
        "SNMP-capable router",
        {"Requires router support and user-provided read-only credentials/community.", "Counter names and per-device fidelity vary by router."},
        "Use read-only polling only; never guess credentials."
    ));
    capabilities.push_back(planned_capability(
        "upnp-igd-counters",
        BandwidthSourceKind::upnp_igd,
        false,
        true,
        false,
        true,
        "UPnP/IGD router",
        {"Often exposes aggregate counters only.", "Many routers do not expose reliable byte counters."},
        "Use read-only IGD status actions only when the router advertises them."
    ));
    capabilities.push_back(planned_capability(
        "flow-export-collector",
        BandwidthSourceKind::flow_export,
        true,
        true,
        false,
        true,
        "NetFlow/sFlow/IPFIX exporter",
        {"Requires an authorized router/firewall exporter.", "Collector must be explicitly configured by the user."},
        "Listen only on documented local collector ports configured by the user."
    ));
    capabilities.push_back(planned_capability(
        "router-plugin",
        BandwidthSourceKind::router_plugin,
        true,
        true,
        false,
        true,
        "Router API/plugin",
        {"Accuracy depends on router API quality.", "Requires explicit user configuration."},
        "Prefer read-only APIs and fixture-tested plugins."
    ));
    capabilities.push_back(planned_capability(
        "optional-agent",
        BandwidthSourceKind::agent,
        true,
        true,
        false,
        true,
        "Installed NetSentinel agent",
        {"Requires explicit installation on authorized devices.", "Agent trust and authentication must be hardened before real use."},
        "Start with a mock authenticated protocol and clear install consent."
    ));
    capabilities.push_back(planned_capability(
        "manual-import",
        BandwidthSourceKind::manual_import,
        true,
        true,
        false,
        false,
        "",
        {"Imported data quality depends on source files.", "No live telemetry."},
        "Validate imports with dry-run summaries before writing storage."
    ));
    return capabilities;
}

std::vector<BandwidthAttributionResult> build_attribution_results(const std::vector<BandwidthSample>& samples) {
    std::vector<BandwidthAttributionResult> out;
    for (const auto& sample : samples) {
        BandwidthAttributionResult result{};
        const auto validation = validate_bandwidth_sample(sample);
        result.success = validation.code == BandwidthErrorCode::none;
        result.source_name = sample.source_name;
        result.identity = sample.identity;
        result.rx_delta_bytes = sample.rx_bytes;
        result.tx_delta_bytes = sample.tx_bytes;
        result.confidence = sample.confidence;
        result.explanation = result.success
            ? "Prompt 52 attribution passes through source-labeled counters without pretending to infer hidden traffic."
            : validation.user_message;
        if (sample.confidence == BandwidthConfidence::low || sample.confidence == BandwidthConfidence::unknown) {
            result.limitations.push_back("Low-confidence attribution must be displayed as an estimate.");
        }
        out.push_back(std::move(result));
    }
    return out;
}

BandwidthError validate_bandwidth_sample(const BandwidthSample& sample) {
    if (sample.source_name.empty()) {
        return {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Bandwidth sample is missing its source name.",
            .technical_detail = "BandwidthSample.source_name is empty."
        };
    }
    if (sample.timestamp_utc.empty()) {
        return {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Bandwidth sample is missing its timestamp.",
            .technical_detail = "BandwidthSample.timestamp_utc is empty."
        };
    }
    if (sample.identity.device_id.empty() && sample.identity.ip_address.empty() && sample.identity.mac_address.empty() && sample.identity.hostname.empty()) {
        return {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Bandwidth sample is missing device identity hints.",
            .technical_detail = "DeviceIdentityHint has no populated fields."
        };
    }
    return {};
}

NpcapDetectionReport detect_npcap_capabilities(const NpcapDetectionConfig& config) {
    NpcapDetectionReport report{};
    if (config.mock_mode) {
        report.installed = config.simulate_installed;
        report.driver_service_present = config.simulate_installed;
        report.current_user_admin = config.simulate_admin;
        report.adapters = mock_npcap_adapters(report.installed, report.current_user_admin, config.include_unsupported_adapter);
    } else {
#ifdef _WIN32
        const auto windows = windows_directory();
        const bool packet_dll = file_exists_no_throw(windows / "System32" / "Npcap" / "Packet.dll");
        const bool wpcap_dll = file_exists_no_throw(windows / "System32" / "Npcap" / "wpcap.dll");
        const bool driver = file_exists_no_throw(windows / "System32" / "drivers" / "npcap.sys");
        report.driver_service_present = driver;
        report.installed = driver && (packet_dll || wpcap_dll);
        report.current_user_admin = current_process_is_elevated();
        report.adapters = enumerate_windows_adapter_hints(report.installed, report.current_user_admin);
#else
        report.installed = false;
        report.driver_service_present = false;
        report.current_user_admin = false;
#endif
    }

    report.capture_available = report.installed && report.current_user_admin;
    report.monitor_mode_available = false;
    if (!report.installed) {
        report.messages.push_back("Missing driver: Npcap is not detected, so packet capture sources are unavailable.");
    }
    if (!report.driver_service_present) {
        report.messages.push_back("Missing driver service: npcap.sys was not found or could not be verified.");
    }
    if (!report.current_user_admin) {
        report.messages.push_back("Non-admin mode: capture may require administrator permissions and must fail closed until elevated.");
    }
    report.messages.push_back("Monitor-mode limitation: monitor mode is not enabled, required, or used in Prompt 53.");
    report.messages.push_back("No packet capture is started by this command.");
    if (report.adapters.empty()) {
        report.messages.push_back("Adapter enumeration produced no capture-capable adapters; this is safe and non-fatal.");
    }

    report.source_capability.source_name = "npcap-visible-lan";
    report.source_capability.kind = BandwidthSourceKind::packet_capture;
    report.source_capability.available = report.capture_available;
    report.source_capability.realtime = true;
    report.source_capability.per_device = true;
    report.source_capability.aggregate = true;
    report.source_capability.requires_admin = true;
    report.source_capability.sends_network_traffic = false;
    report.source_capability.optional_dependency = true;
    report.source_capability.dependency_name = "Npcap";
    report.source_capability.safe_setup_hint = "Install Npcap only when the user explicitly wants authorized visible-LAN capture in a later prompt.";
    report.source_capability.limitations = {
        "Prompt 53 reports capability only and does not capture packets.",
        "A switched LAN may not expose other devices' traffic unless the traffic is mirrored or otherwise visible.",
        "Monitor mode support varies by adapter and is not used here."
    };
    for (const auto& message : report.messages) {
        report.source_capability.limitations.push_back(message);
    }
    return report;
}

LocalMachineBandwidthSnapshot collect_local_machine_bandwidth(const LocalMachineBandwidthConfig& config) {
    LocalMachineBandwidthSnapshot snapshot{};
    snapshot.status = config.mock_mode
        ? collect_mock_local_machine_counter_samples(config.timestamp_utc)
        : collect_windows_local_machine_counter_samples(config.timestamp_utc);
    snapshot.success = snapshot.status.success;
    snapshot.error = snapshot.status.error;
    snapshot.limitation = "This meter measures this Windows PC only and does not measure other LAN devices.";
    if (!snapshot.success) {
        snapshot.storage_message = "Rollup not persisted because local-machine counters were unavailable.";
        return snapshot;
    }

    for (const auto& sample : snapshot.status.samples) {
        snapshot.rx_total_bytes += sample.rx_bytes;
        snapshot.tx_total_bytes += sample.tx_bytes;
    }
    if (config.has_previous_totals && config.elapsed_seconds > 0.0) {
        const auto rx_delta = snapshot.rx_total_bytes > config.previous_rx_total_bytes
            ? snapshot.rx_total_bytes - config.previous_rx_total_bytes
            : 0;
        const auto tx_delta = snapshot.tx_total_bytes > config.previous_tx_total_bytes
            ? snapshot.tx_total_bytes - config.previous_tx_total_bytes
            : 0;
        snapshot.rx_rate_bps = static_cast<double>(rx_delta) * 8.0 / config.elapsed_seconds;
        snapshot.tx_rate_bps = static_cast<double>(tx_delta) * 8.0 / config.elapsed_seconds;
    }

    snapshot.attributions = build_attribution_results(snapshot.status.samples);
    for (auto& attribution : snapshot.attributions) {
        attribution.explanation = "Local-machine Windows counters measure this PC only; no other LAN device traffic is inferred.";
        attribution.limitations.push_back(snapshot.limitation);
    }

    if (!config.persist_rollup) {
        snapshot.storage_message = "Rollup persistence was not requested.";
        return snapshot;
    }

    netsentinel::storage::BandwidthRollupRecord record{};
    record.source_name = "local-machine-counters";
    record.device_id = "local-machine";
    record.adapter_id = "aggregate";
    record.timestamp_utc = config.timestamp_utc;
    record.rx_total_bytes = snapshot.rx_total_bytes;
    record.tx_total_bytes = snapshot.tx_total_bytes;
    record.rx_rate_bps = snapshot.rx_rate_bps;
    record.tx_rate_bps = snapshot.tx_rate_bps;
    record.scope = snapshot.scope;
    record.confidence = to_string(BandwidthConfidence::authoritative);
    record.notes = snapshot.limitation;

    netsentinel::storage::StorageConfig storage_config{};
    storage_config.database_path = config.database_path;
    const auto stored = netsentinel::storage::append_bandwidth_rollup(record, storage_config);
    if (stored) {
        snapshot.persisted = true;
        snapshot.storage_message = "Local-machine bandwidth rollup stored.";
    } else {
        snapshot.persisted = false;
        snapshot.storage_message = "Local-machine bandwidth rollup storage failed: " + stored.error().user_message;
    }
    return snapshot;
}

VisibleLanCaptureReport collect_visible_lan_capture_bandwidth(const VisibleLanCaptureConfig& config) {
    VisibleLanCaptureReport report{};
    report.adapter_id = config.adapter_id;
    report.dry_run = config.dry_run;
    report.limitations = {
        "Visible-LAN capture only sees traffic visible to the selected adapter.",
        "On a normal switched LAN this is not full-network bandwidth unless traffic is mirrored, gateway-visible, or otherwise observable.",
        "No packet injection, ARP spoofing, MITM, deauth, or disruption is used."
    };

    if (config.mock_mode) {
        report.success = true;
        report.capture_started = !config.dry_run;
        report.dry_run = config.dry_run;
        report.user_message = config.dry_run
            ? "Mock visible-LAN capture dry run generated deterministic attribution without packets."
            : "Mock visible-LAN capture generated deterministic visible-traffic samples without touching the network.";

        BandwidthSample router{};
        router.source_name = "visible-lan-capture";
        router.timestamp_utc = config.timestamp_utc;
        router.rx_bytes = 12000000;
        router.tx_bytes = 4500000;
        router.identity.device_id = "visible-router-flow";
        router.identity.ip_address = "192.168.50.1";
        router.identity.mac_address = "02:50:00:00:00:01";
        router.identity.hostname = "gateway-visible";
        router.confidence = config.assume_mirrored_or_gateway_visible ? BandwidthConfidence::medium : BandwidthConfidence::low;
        router.tags = {"mock", "visible-lan", "mac-ip-attribution"};
        report.samples.push_back(router);

        BandwidthSample camera{};
        camera.source_name = "visible-lan-capture";
        camera.timestamp_utc = config.timestamp_utc;
        camera.rx_bytes = 3400000;
        camera.tx_bytes = 9100000;
        camera.identity.device_id = "visible-camera-flow";
        camera.identity.ip_address = "192.168.50.44";
        camera.identity.mac_address = "02:50:00:00:00:44";
        camera.identity.hostname = "camera-visible";
        camera.confidence = BandwidthConfidence::low;
        camera.tags = {"mock", "visible-lan", "partial-visibility"};
        report.samples.push_back(camera);

        report.attributions = build_attribution_results(report.samples);
        for (auto& attribution : report.attributions) {
            attribution.explanation = "Visible capture attribution uses MAC/IP hints that were visible on the selected adapter.";
            attribution.limitations.push_back("May be incomplete on switched networks unless mirrored or gateway-visible.");
        }
        return report;
    }

    NpcapDetectionConfig npcap_config{};
    report.npcap = detect_npcap_capabilities(npcap_config);
    if (config.dry_run) {
        report.success = true;
        report.capture_started = false;
        report.user_message = "Dry run only: Npcap capability was checked, but no packet capture was started.";
        return report;
    }
    if (!config.confirmed) {
        report.success = false;
        report.capture_started = false;
        report.error = {
            .code = BandwidthErrorCode::permission_required,
            .user_message = "Visible-LAN capture requires explicit confirmation.",
            .technical_detail = "Run with --confirm after reviewing the visible-traffic limitations."
        };
        report.user_message = report.error.user_message;
        return report;
    }
    if (!report.npcap.capture_available) {
        report.success = false;
        report.capture_started = false;
        report.error = {
            .code = BandwidthErrorCode::unavailable,
            .user_message = "Npcap capture is unavailable; install Npcap and run with required permissions or use --mock/--dry-run.",
            .technical_detail = "NpcapDetectionReport.capture_available is false."
        };
        report.user_message = report.error.user_message;
        return report;
    }

    report.success = false;
    report.capture_started = false;
    report.error = {
        .code = BandwidthErrorCode::unsupported,
        .user_message = "Npcap capture backend is not linked in this build stage; Prompt 55 exposes safe capability and mock attribution only.",
        .technical_detail = "No Npcap SDK capture implementation is compiled."
    };
    report.user_message = report.error.user_message;
    return report;
}

CounterDeltaResult calculate_counter_delta(std::uint64_t previous, std::uint64_t current, std::uint64_t max_counter_value) {
    CounterDeltaResult result{};
    if (current >= previous) {
        result.delta = current - previous;
        return result;
    }
    result.rollover_detected = true;
    result.delta = (max_counter_value - previous) + current + 1;
    return result;
}

SnmpRouterCounterReport collect_snmp_router_counters(const SnmpRouterCounterConfig& config) {
    SnmpRouterCounterReport report{};
    report.router_ip = config.router_ip;
    report.read_only = true;
    report.credential_reference_used = !config.credential_reference.empty();
    report.limitations = {
        "Read-only SNMP only; no credential guessing or write operations are allowed.",
        "Credentials must be referenced from Windows Credential Manager or an equivalent safe store.",
        "Per-device fidelity depends on router interface counters and bridge/MAC table quality.",
        "Counter rollover is handled for monotonically increasing interface counters."
    };

    if (config.router_ip.empty()) {
        report.success = false;
        report.error = {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Router IP is required for SNMP bandwidth counters.",
            .technical_detail = "SnmpRouterCounterConfig.router_ip is empty."
        };
        report.user_message = report.error.user_message;
        return report;
    }

    if (config.mock_mode) {
        report.success = true;
        report.network_poll_started = false;
        report.user_message = "Mock read-only SNMP router counters generated from deterministic fixtures.";

        SnmpInterfaceCounter lan{};
        lan.interface_id = "ifIndex-1";
        lan.interface_name = "lan1";
        lan.mac_address = "02:50:00:00:00:22";
        lan.ip_address_hint = "192.168.50.22";
        lan.previous_rx_counter = 1000000;
        lan.previous_tx_counter = 250000;
        lan.current_rx_counter = 1420000;
        lan.current_tx_counter = 360000;
        auto lan_rx = calculate_counter_delta(lan.previous_rx_counter, lan.current_rx_counter, 0xffffffffffffffffULL);
        auto lan_tx = calculate_counter_delta(lan.previous_tx_counter, lan.current_tx_counter, 0xffffffffffffffffULL);
        lan.rx_delta_bytes = lan_rx.delta;
        lan.tx_delta_bytes = lan_tx.delta;
        lan.rollover_detected = lan_rx.rollover_detected || lan_tx.rollover_detected;
        lan.confidence = BandwidthConfidence::medium;
        report.interfaces.push_back(lan);

        SnmpInterfaceCounter wifi{};
        wifi.interface_id = "ifIndex-7";
        wifi.interface_name = "wifi-clients";
        wifi.mac_address = "02:50:00:00:00:44";
        wifi.ip_address_hint = "192.168.50.44";
        wifi.previous_rx_counter = 4294967000ULL;
        wifi.previous_tx_counter = 4294966500ULL;
        wifi.current_rx_counter = 320;
        wifi.current_tx_counter = 900;
        auto wifi_rx = calculate_counter_delta(wifi.previous_rx_counter, wifi.current_rx_counter, 0xffffffffULL);
        auto wifi_tx = calculate_counter_delta(wifi.previous_tx_counter, wifi.current_tx_counter, 0xffffffffULL);
        wifi.rx_delta_bytes = wifi_rx.delta;
        wifi.tx_delta_bytes = wifi_tx.delta;
        wifi.rollover_detected = wifi_rx.rollover_detected || wifi_tx.rollover_detected;
        wifi.confidence = BandwidthConfidence::low;
        report.interfaces.push_back(wifi);

        for (const auto& iface : report.interfaces) {
            BandwidthSample sample{};
            sample.source_name = "snmp-router-counters";
            sample.timestamp_utc = config.timestamp_utc;
            sample.rx_bytes = iface.rx_delta_bytes;
            sample.tx_bytes = iface.tx_delta_bytes;
            sample.identity.device_id = "snmp-" + iface.interface_id;
            sample.identity.ip_address = iface.ip_address_hint;
            sample.identity.mac_address = iface.mac_address;
            sample.identity.hostname = iface.interface_name;
            sample.confidence = iface.confidence;
            sample.tags = {"mock", "snmp", "read-only", iface.interface_id};
            if (iface.rollover_detected) {
                sample.tags.push_back("rollover-handled");
            }
            report.samples.push_back(std::move(sample));
        }

        report.attributions = build_attribution_results(report.samples);
        for (auto& attribution : report.attributions) {
            attribution.explanation = "Read-only SNMP interface counters were attributed using visible interface/MAC hints from mock bridge data.";
            attribution.limitations.push_back("SNMP interface counters may represent ports, VLANs, or aggregates rather than exact devices.");
        }
        return report;
    }

    if (config.credential_reference.empty()) {
        report.success = false;
        report.error = {
            .code = BandwidthErrorCode::permission_required,
            .user_message = "SNMP credentials must be configured by safe credential reference; raw community strings are not accepted here.",
            .technical_detail = "SnmpRouterCounterConfig.credential_reference is empty."
        };
        report.user_message = report.error.user_message;
        return report;
    }

    if (config.dry_run) {
        report.success = true;
        report.network_poll_started = false;
        report.user_message = "Dry run only: SNMP credential reference and read-only plan validated; no network polling started.";
        return report;
    }

    report.success = false;
    report.network_poll_started = false;
    report.error = {
        .code = BandwidthErrorCode::unsupported,
        .user_message = "Real SNMP polling backend is not linked in this stage; use --mock or --dry-run.",
        .technical_detail = "No SNMP client dependency is compiled for Prompt 56."
    };
    report.user_message = report.error.user_message;
    return report;
}

UpnpIgdCounterReport collect_upnp_igd_counters(const UpnpIgdCounterConfig& config) {
    UpnpIgdCounterReport report{};
    report.gateway = config.gateway;
    report.read_only = true;
    report.network_wide = true;
    report.limitations = {
        "Read-only UPnP/IGD telemetry only; this stage does not add, delete, or change port mappings.",
        "Many routers expose only network-wide WAN counters, not per-device counters.",
        "Routers that do not expose useful counters must be reported gracefully."
    };

    if (config.gateway.empty()) {
        report.success = false;
        report.error = {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Gateway is required for UPnP/IGD bandwidth counters.",
            .technical_detail = "UpnpIgdCounterConfig.gateway is empty."
        };
        report.user_message = report.error.user_message;
        return report;
    }

    if (config.mock_no_counters) {
        report.success = true;
        report.counters_available = false;
        report.network_poll_started = false;
        report.user_message = "Router did not expose useful UPnP/IGD byte counters; no data was recorded.";
        return report;
    }

    if (config.mock_mode) {
        report.success = true;
        report.counters_available = true;
        report.network_poll_started = false;
        report.user_message = "Mock read-only UPnP/IGD WAN counters generated from deterministic fixtures.";
        const std::uint64_t current_rx = 945000000;
        const std::uint64_t current_tx = 138000000;
        const auto rx_delta = calculate_counter_delta(config.previous_rx_total_bytes, current_rx, 0xffffffffffffffffULL);
        const auto tx_delta = calculate_counter_delta(config.previous_tx_total_bytes, current_tx, 0xffffffffffffffffULL);
        report.rx_delta_bytes = rx_delta.delta;
        report.tx_delta_bytes = tx_delta.delta;
        if (config.elapsed_seconds > 0.0) {
            report.rx_rate_bps = static_cast<double>(report.rx_delta_bytes) * 8.0 / config.elapsed_seconds;
            report.tx_rate_bps = static_cast<double>(report.tx_delta_bytes) * 8.0 / config.elapsed_seconds;
        }

        BandwidthSample sample{};
        sample.source_name = "upnp-igd-counters";
        sample.timestamp_utc = config.timestamp_utc;
        sample.rx_bytes = report.rx_delta_bytes;
        sample.tx_bytes = report.tx_delta_bytes;
        sample.identity.device_id = "network-wide-wan";
        sample.identity.ip_address = config.gateway;
        sample.identity.hostname = "upnp-igd-gateway";
        sample.confidence = BandwidthConfidence::low;
        sample.tags = {"mock", "upnp-igd", "network-wide", "read-only"};
        report.samples.push_back(sample);
        report.attributions = build_attribution_results(report.samples);
        for (auto& attribution : report.attributions) {
            attribution.explanation = "UPnP/IGD counters are treated as network-wide WAN telemetry because the router did not expose per-device mapping.";
            attribution.limitations.push_back("Attribution level is network-wide, not per-device.");
        }
        return report;
    }

    if (config.dry_run) {
        report.success = true;
        report.counters_available = false;
        report.network_poll_started = false;
        report.user_message = "Dry run only: UPnP/IGD read-only counter plan validated; no router request was sent.";
        return report;
    }

    report.success = false;
    report.counters_available = false;
    report.network_poll_started = false;
    report.error = {
        .code = BandwidthErrorCode::unsupported,
        .user_message = "Real UPnP/IGD counter polling is not linked in this stage; use --mock or --dry-run.",
        .technical_detail = "No UPnP client dependency is compiled for Prompt 57."
    };
    report.user_message = report.error.user_message;
    return report;
}

std::vector<std::string> mock_flow_fixture_lines() {
    return {
        "netflow|edge-router|192.168.50.22|8.8.8.8|02:50:00:00:00:22|00:00:5e:00:53:01|1250000|900|lan1|wan|2026-05-02T16:00:00Z",
        "sflow|edge-router|192.168.50.44|192.168.50.1|02:50:00:00:00:44|02:50:00:00:00:01|640000|420|wifi|lan|2026-05-02T16:00:01Z",
        "ipfix|firewall|192.168.50.88|1.1.1.1|02:50:00:00:00:88|00:00:5e:00:53:02|99000|80|lan2|wan|2026-05-02T16:00:02Z"
    };
}

FlowParseResult parse_flow_fixture_line(const std::string& line) {
    FlowParseResult result{};
    const auto fields = split_pipe_fields(line);
    if (fields.size() != 11) {
        result.error = {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Flow fixture record has the wrong field count.",
            .technical_detail = "Expected 11 pipe-delimited fields."
        };
        return result;
    }
    if (!parse_flow_protocol_token(fields[0], result.record.protocol)) {
        result.error = {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Flow fixture record has an unsupported protocol.",
            .technical_detail = fields[0]
        };
        return result;
    }
    result.record.exporter = fields[1];
    result.record.source_ip = fields[2];
    result.record.destination_ip = fields[3];
    result.record.source_mac = fields[4];
    result.record.destination_mac = fields[5];
    result.record.bytes = parse_u64_or_zero(fields[6]);
    result.record.packets = parse_u64_or_zero(fields[7]);
    result.record.ingress_interface = fields[8];
    result.record.egress_interface = fields[9];
    result.record.timestamp_utc = fields[10];
    if (result.record.exporter.empty() || result.record.source_ip.empty() || result.record.destination_ip.empty() ||
        result.record.bytes == 0 || result.record.timestamp_utc.empty()) {
        result.error = {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Flow fixture record is missing required exporter/IP/byte/timestamp data.",
            .technical_detail = line
        };
        return result;
    }
    result.success = true;
    return result;
}

FlowCollectorReport collect_flow_exports(const FlowCollectorConfig& config) {
    FlowCollectorReport report{};
    report.bind_address = config.bind_address;
    report.port = config.port;
    report.explicit_enablement = config.enabled;
    report.limitations = {
        "Passive flow collection only accepts exports from authorized routers/firewalls.",
        "The collector may listen only on configured local ports after explicit user enablement.",
        "Flow exports can provide stronger per-device bandwidth when the router exports source/destination flow data.",
        "No scanning, packet injection, or active probing is performed by this collector."
    };

    if (config.port == 0) {
        report.success = false;
        report.error = {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "Flow collector port must be non-zero.",
            .technical_detail = "FlowCollectorConfig.port is 0."
        };
        report.user_message = report.error.user_message;
        return report;
    }

    if (config.mock_mode) {
        const auto fixtures = config.fixture_lines.empty() ? mock_flow_fixture_lines() : config.fixture_lines;
        for (const auto& line : fixtures) {
            const auto parsed = parse_flow_fixture_line(line);
            if (!parsed.success) {
                report.success = false;
                report.error = parsed.error;
                report.user_message = parsed.error.user_message;
                return report;
            }
            report.records.push_back(parsed.record);
        }
        for (const auto& record : report.records) {
            BandwidthSample sample{};
            sample.source_name = "flow-export-collector";
            sample.timestamp_utc = record.timestamp_utc;
            sample.rx_bytes = record.bytes;
            sample.tx_bytes = 0;
            sample.identity.device_id = "flow-" + record.source_ip;
            sample.identity.ip_address = record.source_ip;
            sample.identity.mac_address = record.source_mac;
            sample.identity.hostname = record.exporter;
            sample.confidence = BandwidthConfidence::high;
            sample.tags = {"mock", "flow-export", to_string(record.protocol), record.ingress_interface, record.egress_interface};
            report.samples.push_back(std::move(sample));
        }
        report.attributions = build_attribution_results(report.samples);
        for (auto& attribution : report.attributions) {
            attribution.explanation = "Router-exported flow records provide source/destination metadata for stronger per-device bandwidth attribution.";
        }
        report.success = true;
        report.listener_started = false;
        report.user_message = "Mock flow export fixtures parsed into bandwidth samples without opening a listener.";
        return report;
    }

    if (!config.enabled) {
        report.success = false;
        report.listener_started = false;
        report.error = {
            .code = BandwidthErrorCode::permission_required,
            .user_message = "Flow collector requires explicit --enable before listening on a local port.",
            .technical_detail = "FlowCollectorConfig.enabled is false."
        };
        report.user_message = report.error.user_message;
        return report;
    }

    if (config.dry_run) {
        report.success = true;
        report.listener_started = false;
        report.user_message = "Dry run only: flow collector bind address and port validated; no socket was opened.";
        return report;
    }

    report.success = false;
    report.listener_started = false;
    report.error = {
        .code = BandwidthErrorCode::unsupported,
        .user_message = "Real UDP flow collector backend is not implemented in this stage; use --mock or --dry-run.",
        .technical_detail = "No NetFlow/sFlow/IPFIX socket listener is compiled for Prompt 58."
    };
    report.user_message = report.error.user_message;
    return report;
}

std::vector<RouterPluginCapability> list_router_plugin_capabilities() {
    return {
        {
            .plugin_id = "mock-router",
            .display_name = "Mock Router Plugin",
            .vendor_family = "fixture",
            .implemented = true,
            .read_only_telemetry = true,
            .reversible_access_control = true,
            .documented_api_required = true,
            .credential_reference_required = false,
            .planned_adapter = "test fixture",
            .limitations = {"Deterministic fixture only.", "No network calls are made."}
        },
        {
            .plugin_id = "openwrt-readonly-fixture",
            .display_name = "OpenWrt Read-only Fixture",
            .vendor_family = "OpenWrt",
            .implemented = true,
            .read_only_telemetry = true,
            .reversible_access_control = false,
            .documented_api_required = true,
            .credential_reference_required = true,
            .planned_adapter = "Prompt 60",
            .limitations = {"Fixture demonstrates documented read-only telemetry shape only.", "No real OpenWrt API call is made in Prompt 59."}
        },
        {
            .plugin_id = "opnsense-pfsense",
            .display_name = "OPNsense/pfSense API",
            .vendor_family = "OPNsense/pfSense",
            .implemented = false,
            .read_only_telemetry = true,
            .reversible_access_control = true,
            .documented_api_required = true,
            .credential_reference_required = true,
            .planned_adapter = "future",
            .limitations = {"Use documented APIs only.", "No password scraping or hidden endpoints."}
        },
        {
            .plugin_id = "mikrotik-routeros",
            .display_name = "MikroTik RouterOS",
            .vendor_family = "MikroTik RouterOS",
            .implemented = false,
            .read_only_telemetry = true,
            .reversible_access_control = true,
            .documented_api_required = true,
            .credential_reference_required = true,
            .planned_adapter = "future",
            .limitations = {"Use documented RouterOS APIs only.", "Credentials must be referenced from a safe store."}
        },
        {
            .plugin_id = "unifi",
            .display_name = "UniFi Controller",
            .vendor_family = "UniFi",
            .implemented = false,
            .read_only_telemetry = true,
            .reversible_access_control = true,
            .documented_api_required = true,
            .credential_reference_required = true,
            .planned_adapter = "future",
            .limitations = {"Use user-configured controller endpoints only.", "No cloud scraping."}
        },
        {
            .plugin_id = "fritzbox",
            .display_name = "FRITZ!Box",
            .vendor_family = "FRITZ!Box",
            .implemented = false,
            .read_only_telemetry = true,
            .reversible_access_control = true,
            .documented_api_required = true,
            .credential_reference_required = true,
            .planned_adapter = "future",
            .limitations = {"Use documented user-approved router interfaces only."}
        },
        {
            .plugin_id = "asuswrt-merlin",
            .display_name = "ASUSWRT/Merlin",
            .vendor_family = "ASUSWRT/Merlin",
            .implemented = false,
            .read_only_telemetry = true,
            .reversible_access_control = true,
            .documented_api_required = true,
            .credential_reference_required = true,
            .planned_adapter = "future",
            .limitations = {"Use documented APIs or user-installed scripts only.", "No hidden endpoints."}
        },
        {
            .plugin_id = "pihole",
            .display_name = "Pi-hole",
            .vendor_family = "Pi-hole",
            .implemented = false,
            .read_only_telemetry = true,
            .reversible_access_control = true,
            .documented_api_required = true,
            .credential_reference_required = true,
            .planned_adapter = "future",
            .limitations = {"DNS-control actions must be reversible and explicit."}
        },
        {
            .plugin_id = "adguard-home",
            .display_name = "AdGuard Home",
            .vendor_family = "AdGuard Home",
            .implemented = false,
            .read_only_telemetry = true,
            .reversible_access_control = true,
            .documented_api_required = true,
            .credential_reference_required = true,
            .planned_adapter = "future",
            .limitations = {"DNS-control actions must be reversible and explicit."}
        }
    };
}

RouterPluginResult run_router_plugin_request(const RouterPluginRequest& request) {
    RouterPluginResult result{};
    result.plugin_id = request.plugin_id;
    result.operation = request.operation;
    result.limitations = {
        "Router plugins may use only documented vendor/user-approved APIs.",
        "Credentials must be referenced from a safe store, not scraped from browsers or config pages.",
        "Access-control actions must be reversible and require confirmation before apply."
    };

    const auto capabilities = list_router_plugin_capabilities();
    auto match = std::find_if(
        capabilities.begin(),
        capabilities.end(),
        [&](const RouterPluginCapability& capability) {
            return capability.plugin_id == request.plugin_id;
        }
    );
    if (match == capabilities.end()) {
        result.success = false;
        result.error = {
            .code = BandwidthErrorCode::unsupported,
            .user_message = "Unknown router plugin id.",
            .technical_detail = request.plugin_id
        };
        result.user_message = result.error.user_message;
        return result;
    }

    if (!match->implemented && !request.mock_mode) {
        result.success = false;
        result.error = {
            .code = BandwidthErrorCode::unsupported,
            .user_message = "Router plugin adapter is planned but not implemented yet.",
            .technical_detail = request.plugin_id
        };
        result.user_message = result.error.user_message;
        return result;
    }

    if (request.operation == "list" || request.operation == "telemetry") {
        result.success = true;
        result.user_message = "Mock router plugin returned read-only telemetry fixture.";
        BandwidthSample sample{};
        sample.source_name = "router-plugin";
        sample.timestamp_utc = "2026-05-02T17:00:00Z";
        sample.rx_bytes = 7200000;
        sample.tx_bytes = 3100000;
        sample.identity.device_id = "router-plugin-device";
        sample.identity.ip_address = "192.168.50.22";
        sample.identity.mac_address = "02:50:00:00:00:22";
        sample.identity.hostname = request.plugin_id;
        sample.confidence = BandwidthConfidence::medium;
        sample.tags = {"mock", "router-plugin", "read-only"};
        result.telemetry_samples.push_back(sample);
        return result;
    }

    if (request.operation == "block" || request.operation == "unblock" || request.operation == "limit") {
        result.reversible = true;
        if (request.target_device_id.empty()) {
            result.success = false;
            result.error = {
                .code = BandwidthErrorCode::invalid_argument,
                .user_message = "Router plugin access-control operation requires a target device id.",
                .technical_detail = "RouterPluginRequest.target_device_id is empty."
            };
            result.user_message = result.error.user_message;
            return result;
        }
        if (!request.dry_run && !request.confirmed) {
            result.success = false;
            result.requires_confirmation = true;
            result.error = {
                .code = BandwidthErrorCode::permission_required,
                .user_message = "Router plugin action requires --confirm before apply.",
                .technical_detail = "Apply requested without confirmation."
            };
            result.user_message = result.error.user_message;
            return result;
        }
        result.success = true;
        result.applied = !request.dry_run;
        result.user_message = request.dry_run
            ? "Dry-run reversible router plugin action planned; no router changes were made."
            : "Mock reversible router plugin action applied in fixture mode.";
        return result;
    }

    result.success = false;
    result.error = {
        .code = BandwidthErrorCode::invalid_argument,
        .user_message = "Unsupported router plugin operation.",
        .technical_detail = request.operation
    };
    result.user_message = result.error.user_message;
    return result;
}

std::string normalize_limit_backend(std::string_view backend) {
    const auto lower = bandwidth_lower_copy(backend);
    if (lower.empty() || lower == "mock" || lower == "fixture") {
        return "mock";
    }
    if (lower == "openwrt" || lower == "openwrt-qos" || lower == "openwrt-prototype") {
        return "openwrt";
    }
    if (lower == "windows-firewall" || lower == "windows-firewall-local" || lower == "local-firewall") {
        return "windows-firewall-local";
    }
    if (lower == "pihole" || lower == "pi-hole") {
        return "pihole";
    }
    if (lower == "adguard" || lower == "adguard-home") {
        return "adguard";
    }
    if (lower == "router-plugin" || lower == "router") {
        return "router-plugin";
    }
    return lower;
}

std::string normalize_limit_action(std::string_view action) {
    const auto lower = bandwidth_lower_copy(action);
    if (lower.empty() || lower == "rate-limit" || lower == "throttle") {
        return "limit";
    }
    if (lower == "block" || lower == "pause-internet" || lower == "pause") {
        return "pause";
    }
    if (lower == "unblock" || lower == "unpause" || lower == "restore") {
        return "resume";
    }
    return lower;
}

std::string limit_target_label(const BandwidthLimitRequest& request) {
    if (!request.target_device_id.empty()) {
        return request.target_device_id;
    }
    if (!request.target_ip.empty()) {
        return request.target_ip;
    }
    return {};
}

std::string limit_rate_detail(const BandwidthLimitRequest& request) {
    std::vector<std::string> parts;
    if (request.download_limit_kbps > 0) {
        parts.push_back("download=" + std::to_string(request.download_limit_kbps) + "kbps");
    }
    if (request.upload_limit_kbps > 0) {
        parts.push_back("upload=" + std::to_string(request.upload_limit_kbps) + "kbps");
    }
    if (parts.empty()) {
        return "no rate values";
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

BandwidthLimitResult make_limit_failure(
    const BandwidthLimitRequest& request,
    const std::string& backend,
    const std::string& action,
    BandwidthErrorCode code,
    const std::string& message,
    const std::string& detail,
    bool requires_confirmation = false,
    bool unsafe_method_rejected = false
) {
    BandwidthLimitResult result{};
    result.success = false;
    result.applied = false;
    result.dry_run = true;
    result.reversible = true;
    result.requires_confirmation = requires_confirmation;
    result.documented_api_used = true;
    result.unsafe_method_rejected = unsafe_method_rejected;
    result.logged = true;
    result.backend = backend;
    result.action = action;
    result.error = {
        .code = code,
        .user_message = message,
        .technical_detail = detail
    };
    result.user_message = message;
    result.limitations = {
        "Safe bandwidth limit backends never use ARP spoofing, deauth, MITM, packet injection, credential attacks, or stealth behavior.",
        "Actions require dry-run planning first and explicit confirmation before apply unless a saved rule is present.",
        "Every apply-capable path must be reversible and logged."
    };
    result.audit_log.push_back("blocked backend=" + backend + " action=" + action + " target=" + (limit_target_label(request).empty() ? "(none)" : limit_target_label(request)));
    return result;
}

std::vector<BandwidthLimitBackendCapability> list_safe_bandwidth_limit_backends() {
    return {
        BandwidthLimitBackendCapability{
            .backend_id = "mock",
            .display_name = "Mock reversible bandwidth limiter",
            .implemented = true,
            .supports_bandwidth_limit = true,
            .supports_pause_resume = true,
            .requires_credentials = false,
            .documented_api_required = true,
            .reversible_actions = true,
            .limitations = {"Deterministic fixture only.", "No network, router, firewall, or DNS state is changed."}
        },
        BandwidthLimitBackendCapability{
            .backend_id = "openwrt",
            .display_name = "OpenWrt QoS/firewall prototype",
            .implemented = true,
            .supports_bandwidth_limit = true,
            .supports_pause_resume = true,
            .requires_credentials = true,
            .documented_api_required = true,
            .reversible_actions = true,
            .limitations = {"Mock/dry-run only in Prompt 67.", "Uses documented UCI/firewall/QoS plan shapes only.", "No real router request is sent by this stage."}
        },
        BandwidthLimitBackendCapability{
            .backend_id = "windows-firewall-local",
            .display_name = "Windows Firewall local PC control",
            .implemented = true,
            .supports_bandwidth_limit = false,
            .supports_pause_resume = true,
            .requires_credentials = false,
            .documented_api_required = true,
            .reversible_actions = true,
            .limitations = {"Can only affect this Windows PC.", "Cannot provide per-device LAN bandwidth limits."}
        },
        BandwidthLimitBackendCapability{
            .backend_id = "pihole",
            .display_name = "Pi-hole DNS group control",
            .implemented = false,
            .supports_bandwidth_limit = false,
            .supports_pause_resume = true,
            .requires_credentials = true,
            .documented_api_required = true,
            .reversible_actions = true,
            .limitations = {"Future DNS-only pause/resume; not a bandwidth limiter.", "Must be explicit, reversible, and credential-referenced."}
        },
        BandwidthLimitBackendCapability{
            .backend_id = "adguard",
            .display_name = "AdGuard Home DNS group control",
            .implemented = false,
            .supports_bandwidth_limit = false,
            .supports_pause_resume = true,
            .requires_credentials = true,
            .documented_api_required = true,
            .reversible_actions = true,
            .limitations = {"Future DNS-only pause/resume; not a bandwidth limiter.", "Must be explicit, reversible, and credential-referenced."}
        }
    };
}

BandwidthLimitResult run_safe_bandwidth_limit_backend(const BandwidthLimitRequest& request) {
    const auto backend = normalize_limit_backend(request.backend);
    const auto action = normalize_limit_action(request.action);
    const auto target = limit_target_label(request);

    if (bandwidth_contains_any_ci(
            request.backend + " " + request.action + " " + request.endpoint + " " + request.rule_id,
            {"arp-spoof", "arp spoof", "spoofing", "deauth", "deauthentication", "mitm", "man-in-the-middle", "evil twin", "packet injection", "bruteforce", "brute force"}
        )) {
        return make_limit_failure(
            request,
            backend,
            action,
            BandwidthErrorCode::unsupported,
            "Unsafe enforcement method rejected by the safety contract.",
            "Request contained a forbidden disruption or credential-attack token.",
            false,
            true
        );
    }

    const auto capabilities = list_safe_bandwidth_limit_backends();
    const auto capability = std::find_if(
        capabilities.begin(),
        capabilities.end(),
        [&](const BandwidthLimitBackendCapability& item) {
            return item.backend_id == backend;
        }
    );
    if (capability == capabilities.end() && backend != "router-plugin") {
        return make_limit_failure(
            request,
            backend,
            action,
            BandwidthErrorCode::unsupported,
            "Unsupported safe bandwidth limit backend.",
            backend
        );
    }

    if (action != "limit" && action != "pause" && action != "resume") {
        return make_limit_failure(
            request,
            backend,
            action,
            BandwidthErrorCode::invalid_argument,
            "Unsupported bandwidth control action.",
            action
        );
    }

    if (target.empty()) {
        return make_limit_failure(
            request,
            backend,
            action,
            BandwidthErrorCode::invalid_argument,
            "Bandwidth limit action requires --target or --target-ip.",
            "No target supplied."
        );
    }

    if (action == "limit" && request.download_limit_kbps <= 0 && request.upload_limit_kbps <= 0) {
        return make_limit_failure(
            request,
            backend,
            action,
            BandwidthErrorCode::invalid_argument,
            "Bandwidth limit action requires --download-kbps and/or --upload-kbps.",
            "No limit values supplied."
        );
    }

    if (capability != capabilities.end()) {
        if (action == "limit" && !capability->supports_bandwidth_limit) {
            return make_limit_failure(
                request,
                backend,
                action,
                BandwidthErrorCode::unsupported,
                "Selected backend does not support bandwidth limits.",
                backend
            );
        }
        if ((action == "pause" || action == "resume") && !capability->supports_pause_resume) {
            return make_limit_failure(
                request,
                backend,
                action,
                BandwidthErrorCode::unsupported,
                "Selected backend does not support pause/resume actions.",
                backend
            );
        }
        if (!capability->implemented && !request.mock_mode) {
            return make_limit_failure(
                request,
                backend,
                action,
                BandwidthErrorCode::unsupported,
                "Selected backend is planned but not implemented yet.",
                backend
            );
        }
    }

    if (!request.dry_run && !request.confirmed && !request.saved_rule) {
        return make_limit_failure(
            request,
            backend,
            action,
            BandwidthErrorCode::permission_required,
            "Bandwidth control apply requires --confirm unless a saved rule is present.",
            "Apply requested without confirmation or saved rule.",
            true
        );
    }

    BandwidthLimitResult result{};
    result.success = true;
    result.applied = !request.dry_run;
    result.dry_run = request.dry_run;
    result.reversible = true;
    result.requires_confirmation = false;
    result.documented_api_used = true;
    result.unsafe_method_rejected = false;
    result.logged = true;
    result.backend = backend;
    result.action = action;
    result.rollback_id = request.rule_id.empty()
        ? "rollback-" + backend + "-" + action + "-" + target
        : "rollback-" + request.rule_id;
    result.limitations = {
        "No spoofing, deauth, MITM, packet injection, exploit payloads, brute force, or stealth behavior is implemented.",
        "Dry-run mode performs planning only and makes no network, router, firewall, or DNS change.",
        "Apply-capable paths require confirmation or a saved rule and must record a reversible rollback id."
    };
    result.audit_log.push_back("planned backend=" + backend + " action=" + action + " target=" + target + " dry_run=" + (request.dry_run ? "true" : "false"));

    if (backend == "mock") {
        result.steps.push_back({
            .backend = backend,
            .action = action,
            .target = target,
            .status = request.dry_run ? "planned" : "mock-applied",
            .reversible_action = action == "resume" ? "pause" : "resume",
            .detail = action == "limit"
                ? "Mock reversible limit plan for " + limit_rate_detail(request) + "."
                : "Mock reversible " + action + " plan; no traffic is touched."
        });
        result.user_message = request.dry_run
            ? "Safe mock bandwidth control plan generated; no changes were made."
            : "Safe mock bandwidth control action applied in fixture mode only.";
        return result;
    }

    if (backend == "openwrt") {
        if (request.endpoint.empty() || request.credential_reference.empty()) {
            return make_limit_failure(
                request,
                backend,
                action,
                BandwidthErrorCode::permission_required,
                "OpenWrt safe backend requires --endpoint and --credential-ref.",
                "Endpoint or credential reference missing."
            );
        }
        result.steps.push_back({
            .backend = backend,
            .action = action,
            .target = target,
            .status = request.dry_run ? "planned" : (request.mock_mode ? "mock-applied" : "blocked"),
            .reversible_action = action == "resume" ? "restore previous pause rule" : "remove generated OpenWrt rule " + result.rollback_id,
            .detail = action == "limit"
                ? "Documented OpenWrt UCI/QoS prototype would set " + limit_rate_detail(request) + " for target using credential reference only."
                : "Documented OpenWrt firewall prototype would " + action + " target access using credential reference only."
        });
        result.limitations.push_back("Prompt 67 OpenWrt apply is mock-only; real router mutation remains disabled until a reviewed transport is added.");
        if (!request.dry_run && !request.mock_mode) {
            result.success = false;
            result.applied = false;
            result.dry_run = true;
            result.error = {
                .code = BandwidthErrorCode::unsupported,
                .user_message = "Real OpenWrt apply is not enabled in Prompt 67; use --mock or --dry-run.",
                .technical_detail = "No OpenWrt write transport is compiled."
            };
            result.user_message = result.error.user_message;
            result.audit_log.push_back("blocked real-openwrt-apply");
            return result;
        }
        result.user_message = request.dry_run
            ? "OpenWrt safe backend dry-run plan generated; no router request was sent."
            : "OpenWrt safe backend mock apply recorded; no router request was sent.";
        return result;
    }

    if (backend == "windows-firewall-local") {
        result.steps.push_back({
            .backend = backend,
            .action = action,
            .target = target,
            .status = request.dry_run ? "planned" : (request.mock_mode ? "mock-applied" : "blocked"),
            .reversible_action = action == "pause" ? "resume" : "pause",
            .detail = "Local Windows Firewall plan affects only this PC; it cannot disconnect or throttle other LAN devices."
        });
        if (!request.dry_run && !request.mock_mode) {
            result.success = false;
            result.applied = false;
            result.dry_run = true;
            result.error = {
                .code = BandwidthErrorCode::unsupported,
                .user_message = "Real Windows Firewall apply is not enabled from the bandwidth CLI yet; dry-run and mock apply are available.",
                .technical_detail = "No elevated firewall service path is invoked."
            };
            result.user_message = result.error.user_message;
            return result;
        }
        result.user_message = request.dry_run
            ? "Windows Firewall local-only dry-run plan generated; no firewall rule was changed."
            : "Windows Firewall local-only mock apply recorded; no firewall rule was changed.";
        return result;
    }

    if (backend == "router-plugin") {
        RouterPluginRequest plugin_request{};
        plugin_request.mock_mode = request.mock_mode;
        plugin_request.dry_run = request.dry_run;
        plugin_request.confirmed = request.confirmed || request.saved_rule;
        plugin_request.plugin_id = "mock-router";
        plugin_request.operation = action == "pause" ? "block" : (action == "resume" ? "unblock" : "limit");
        plugin_request.target_device_id = target;
        plugin_request.credential_reference = request.credential_reference;
        const auto plugin_result = run_router_plugin_request(plugin_request);
        if (!plugin_result.success) {
            return make_limit_failure(
                request,
                backend,
                action,
                plugin_result.error.code,
                plugin_result.error.user_message,
                plugin_result.error.technical_detail,
                plugin_result.requires_confirmation
            );
        }
        result.steps.push_back({
            .backend = backend,
            .action = action,
            .target = target,
            .status = plugin_result.applied ? "mock-applied" : "planned",
            .reversible_action = action == "resume" ? "pause" : "resume",
            .detail = "Delegated to documented router plugin contract; password scraping is forbidden."
        });
        result.applied = plugin_result.applied;
        result.dry_run = !plugin_result.applied;
        result.user_message = plugin_result.user_message;
        return result;
    }

    return make_limit_failure(
        request,
        backend,
        action,
        BandwidthErrorCode::unsupported,
        "Selected backend is planned but not enabled in this stage.",
        backend
    );
}

std::vector<UnknownDeviceObservation> mock_unknown_device_observations() {
    return {
        UnknownDeviceObservation{
            .device_id = "known-router",
            .hostname = "gateway",
            .ip_address = "192.168.50.1",
            .mac_address = "02:50:00:00:00:01",
            .vendor_hint = "RouterCorp",
            .device_type = "router",
            .labels = {"trusted", "gateway"},
            .trusted = true,
            .last_seen_utc = "2026-05-02T19:00:00Z"
        },
        UnknownDeviceObservation{
            .device_id = "unknown-phone",
            .hostname = "android-unknown",
            .ip_address = "192.168.50.88",
            .mac_address = "02:50:00:00:00:88",
            .vendor_hint = "unknown",
            .device_type = "unknown",
            .labels = {},
            .trusted = false,
            .last_seen_utc = "2026-05-02T19:01:00Z"
        },
        UnknownDeviceObservation{
            .device_id = "guest-tablet",
            .hostname = "guest-tablet",
            .ip_address = "192.168.50.130",
            .mac_address = "02:50:00:00:00:30",
            .vendor_hint = "TabletCo",
            .device_type = "tablet",
            .labels = {"guest"},
            .trusted = false,
            .last_seen_utc = "2026-05-02T19:02:00Z"
        }
    };
}

bool has_label_ci(const std::vector<std::string>& labels, std::string_view needle) {
    const auto lower_needle = bandwidth_lower_copy(needle);
    for (const auto& label : labels) {
        if (bandwidth_lower_copy(label) == lower_needle) {
            return true;
        }
    }
    return false;
}

bool is_unknown_device_observation(const UnknownDeviceObservation& device) {
    if (device.trusted || has_label_ci(device.labels, "trusted") || has_label_ci(device.labels, "known")) {
        return false;
    }
    const auto type = bandwidth_lower_copy(device.device_type);
    const auto vendor = bandwidth_lower_copy(device.vendor_hint);
    return type.empty() || type == "unknown" || vendor.empty() || vendor == "unknown" || has_label_ci(device.labels, "guest");
}

std::string autoblock_target_for_device(const UnknownDeviceObservation& device) {
    if (!device.device_id.empty()) {
        return device.device_id;
    }
    if (!device.ip_address.empty()) {
        return device.ip_address;
    }
    if (!device.mac_address.empty()) {
        return device.mac_address;
    }
    return "(unknown-device)";
}

AutoblockPolicyResult run_unknown_device_autoblock_policy(const AutoblockPolicyConfig& config) {
    AutoblockPolicyResult result{};
    result.alert_only = !config.enforcement_enabled;
    result.enforcement_enabled = config.enforcement_enabled;
    result.rollback_button_available = !config.enforcement_enabled || config.rollback_button_required;
    result.limitations = {
        "Default mode is alert-only and never blocks a device.",
        "Enforcement delegates only to configured safe backends from Prompt 67.",
        "No ARP spoofing, deauthentication, jamming, MITM, packet injection, exploit payloads, brute force, or stealth behavior is used.",
        "Rollback must be available before enforcement can proceed."
    };

    if (!config.mock_mode) {
        result.success = false;
        result.user_message = "Unknown-device autoblock orchestration is mock/stored-inventory only in this stage; use --mock for deterministic verification.";
        return result;
    }

    if (config.enforcement_enabled && config.safe_backend.empty()) {
        result.success = false;
        result.user_message = "Autoblock enforcement requires a configured safe backend.";
        return result;
    }

    if (config.enforcement_enabled && config.rollback_button_required == false) {
        result.success = false;
        result.user_message = "Autoblock enforcement requires rollback button availability.";
        return result;
    }

    const auto devices = config.devices.empty() ? mock_unknown_device_observations() : config.devices;
    bool backend_failed = false;
    for (const auto& device : devices) {
        AutoblockDecision decision{};
        decision.device_id = autoblock_target_for_device(device);
        decision.ip_address = device.ip_address;
        decision.mac_address = device.mac_address;
        decision.unknown = is_unknown_device_observation(device);
        decision.rollback_available = !config.enforcement_enabled;

        if (!decision.unknown) {
            decision.state = "trusted-or-known";
            decision.detail = "Device is trusted or classified, so autoblock does not alert or enforce.";
            result.decisions.push_back(std::move(decision));
            continue;
        }

        result.alerts.push_back("Unknown device observed: " + decision.device_id + " " + device.ip_address);
        if (!config.enforcement_enabled) {
            decision.state = "alert-only";
            decision.detail = "Unknown device alert generated. Default safe mode does not block or throttle.";
            result.decisions.push_back(std::move(decision));
            continue;
        }

        BandwidthLimitRequest limit{};
        limit.mock_mode = config.mock_mode;
        limit.dry_run = config.dry_run;
        limit.confirmed = config.confirmed;
        limit.saved_rule = config.saved_rule;
        limit.backend = config.safe_backend;
        limit.action = "pause";
        limit.target_device_id = device.device_id;
        limit.target_ip = device.ip_address;
        limit.endpoint = config.endpoint;
        limit.credential_reference = config.credential_reference;
        limit.rule_id = config.rule_id.empty() ? "autoblock-unknown-devices" : config.rule_id;
        decision.enforcement_attempted = true;
        decision.backend_result = run_safe_bandwidth_limit_backend(limit);
        decision.rollback_available = decision.backend_result.success && !decision.backend_result.rollback_id.empty();
        decision.rollback_id = decision.backend_result.rollback_id;
        if (!decision.backend_result.success) {
            backend_failed = true;
            decision.state = "backend-error";
            decision.detail = "Safe backend rejected autoblock request: " + decision.backend_result.user_message;
        } else {
            decision.state = decision.backend_result.applied ? "mock-blocked" : "planned-block";
            decision.detail = decision.backend_result.user_message;
        }
        result.decisions.push_back(std::move(decision));
    }

    result.success = !backend_failed;
    result.rollback_button_available = true;
    result.user_message = result.alert_only
        ? "Unknown-device autoblock evaluated in alert-only mode."
        : (backend_failed ? "Autoblock enforcement plan encountered a safe-backend error." : "Autoblock enforcement plan evaluated with rollback support.");
    return result;
}

std::vector<std::string> mock_openwrt_telemetry_lines() {
    return {
        "OpenWrt 23.05|laptop|192.168.50.22|02:50:00:00:00:22|18400000|9300000|online",
        "OpenWrt 23.05|camera|192.168.50.44|02:50:00:00:00:44|4200000|11800000|online",
        "OpenWrt 23.05|old-phone|192.168.50.77|02:50:00:00:00:77|500000|120000|offline"
    };
}

OpenWrtTelemetryParseResult parse_openwrt_telemetry_line(const std::string& line) {
    OpenWrtTelemetryParseResult result{};
    const auto fields = split_pipe_fields(line);
    if (fields.size() != 7) {
        result.error = {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "OpenWrt telemetry fixture has the wrong field count.",
            .technical_detail = "Expected 7 pipe-delimited fields."
        };
        return result;
    }
    result.firmware_version = fields[0];
    result.device.hostname = fields[1];
    result.device.ip_address = fields[2];
    result.device.mac_address = fields[3];
    result.device.rx_bytes = parse_u64_or_zero(fields[4]);
    result.device.tx_bytes = parse_u64_or_zero(fields[5]);
    result.device.online = fields[6] == "online";
    result.device.device_id = "openwrt-" + result.device.mac_address;
    if (result.firmware_version.rfind("OpenWrt ", 0) != 0) {
        result.error = {
            .code = BandwidthErrorCode::unsupported,
            .user_message = "Unsupported firmware: expected an OpenWrt telemetry response.",
            .technical_detail = result.firmware_version
        };
        return result;
    }
    if (result.device.hostname.empty() || result.device.ip_address.empty() || result.device.mac_address.empty()) {
        result.error = {
            .code = BandwidthErrorCode::invalid_argument,
            .user_message = "OpenWrt telemetry fixture is missing hostname, IP, or MAC data.",
            .technical_detail = line
        };
        return result;
    }
    result.success = true;
    return result;
}

OpenWrtTelemetryReport collect_openwrt_readonly_telemetry(const OpenWrtTelemetryConfig& config) {
    OpenWrtTelemetryReport report{};
    report.endpoint = config.endpoint;
    report.transport = config.transport;
    report.credential_reference_used = !config.credential_reference.empty();
    report.read_only = true;
    report.limitations = {
        "OpenWrt plugin is read-only in this stage.",
        "Use documented OpenWrt RPC or SSH command paths only when explicit credentials are configured.",
        "Never alter firewall, QoS, DHCP, or wireless configuration in Prompt 60.",
        "Credentials must be referenced from a safe store rather than embedded in logs or project files."
    };

    if (config.mock_unsupported_firmware) {
        const auto parsed = parse_openwrt_telemetry_line("VendorOS 1.0|router|192.168.50.1|02:50:00:00:00:01|1|1|online");
        report.success = false;
        report.firmware_supported = false;
        report.error = parsed.error;
        report.user_message = parsed.error.user_message;
        return report;
    }

    if (config.mock_mode) {
        const auto lines = config.fixture_lines.empty() ? mock_openwrt_telemetry_lines() : config.fixture_lines;
        for (const auto& line : lines) {
            const auto parsed = parse_openwrt_telemetry_line(line);
            if (!parsed.success) {
                report.success = false;
                report.error = parsed.error;
                report.user_message = parsed.error.user_message;
                return report;
            }
            report.firmware_version = parsed.firmware_version;
            report.devices.push_back(parsed.device);
        }
        for (const auto& device : report.devices) {
            BandwidthSample sample{};
            sample.source_name = "openwrt-readonly-plugin";
            sample.timestamp_utc = "2026-05-02T18:00:00Z";
            sample.rx_bytes = device.rx_bytes;
            sample.tx_bytes = device.tx_bytes;
            sample.identity.device_id = device.device_id;
            sample.identity.ip_address = device.ip_address;
            sample.identity.mac_address = device.mac_address;
            sample.identity.hostname = device.hostname;
            sample.confidence = BandwidthConfidence::high;
            sample.tags = {"mock", "openwrt", "read-only", device.online ? "online" : "offline"};
            report.samples.push_back(std::move(sample));
        }
        report.success = true;
        report.firmware_supported = true;
        report.network_request_started = false;
        report.user_message = "Mock OpenWrt read-only telemetry parsed from documented-shape fixtures.";
        return report;
    }

    if (config.endpoint.empty() || config.credential_reference.empty()) {
        report.success = false;
        report.error = {
            .code = BandwidthErrorCode::permission_required,
            .user_message = "OpenWrt telemetry requires an endpoint and credential reference before any real request.",
            .technical_detail = "OpenWrtTelemetryConfig endpoint or credential_reference is empty."
        };
        report.user_message = report.error.user_message;
        return report;
    }

    if (config.dry_run) {
        report.success = true;
        report.firmware_supported = false;
        report.network_request_started = false;
        report.user_message = "Dry run only: OpenWrt endpoint and credential reference validated; no router request was sent.";
        return report;
    }

    report.success = false;
    report.network_request_started = false;
    report.error = {
        .code = BandwidthErrorCode::unsupported,
        .user_message = "Real OpenWrt RPC/SSH client is not linked in this stage; use --mock or --dry-run.",
        .technical_detail = "No OpenWrt transport dependency is compiled for Prompt 60."
    };
    report.user_message = report.error.user_message;
    return report;
}

std::vector<BandwidthSample> mock_bandwidth_attribution_samples() {
    std::vector<BandwidthSample> out;

    LocalMachineBandwidthConfig local{};
    local.mock_mode = true;
    const auto local_snapshot = collect_local_machine_bandwidth(local);
    out.insert(out.end(), local_snapshot.status.samples.begin(), local_snapshot.status.samples.end());

    VisibleLanCaptureConfig capture{};
    capture.mock_mode = true;
    capture.dry_run = false;
    const auto visible = collect_visible_lan_capture_bandwidth(capture);
    out.insert(out.end(), visible.samples.begin(), visible.samples.end());

    SnmpRouterCounterConfig snmp{};
    snmp.mock_mode = true;
    const auto snmp_report = collect_snmp_router_counters(snmp);
    out.insert(out.end(), snmp_report.samples.begin(), snmp_report.samples.end());

    UpnpIgdCounterConfig upnp{};
    upnp.mock_mode = true;
    const auto upnp_report = collect_upnp_igd_counters(upnp);
    out.insert(out.end(), upnp_report.samples.begin(), upnp_report.samples.end());

    FlowCollectorConfig flow{};
    flow.mock_mode = true;
    const auto flow_report = collect_flow_exports(flow);
    out.insert(out.end(), flow_report.samples.begin(), flow_report.samples.end());

    OpenWrtTelemetryConfig openwrt{};
    openwrt.mock_mode = true;
    const auto openwrt_report = collect_openwrt_readonly_telemetry(openwrt);
    out.insert(out.end(), openwrt_report.samples.begin(), openwrt_report.samples.end());

    return out;
}

BandwidthAttributionMergeReport attribute_bandwidth_per_device(
    const std::vector<BandwidthSample>& samples,
    const BandwidthAttributionMergeConfig& config
) {
    BandwidthAttributionMergeReport report{};
    report.limitations = {
        "UPnP/IGD aggregate counters are kept as network-only and are not added to per-device totals.",
        "Overlapping per-device sources are not summed; the highest-priority source is selected to avoid double-counting.",
        "Conflicting source details remain visible instead of pretending precision."
    };

    struct SourceAggregate {
        AttributionSourceDetail detail;
        DeviceIdentityHint identity;
    };

    std::unordered_map<std::string, std::unordered_map<std::string, SourceAggregate>> grouped;
    for (const auto& sample : samples) {
        if (sample.source_name == "upnp-igd-counters") {
            report.network_only_rx_bytes += sample.rx_bytes;
            report.network_only_tx_bytes += sample.tx_bytes;
            continue;
        }
        const auto key = attribution_key_for_sample(sample);
        auto& aggregate = grouped[key][sample.source_name];
        aggregate.detail.source_name = sample.source_name;
        aggregate.detail.rx_bytes += sample.rx_bytes;
        aggregate.detail.tx_bytes += sample.tx_bytes;
        aggregate.detail.confidence = attribution_confidence_label(sample);
        aggregate.detail.note = "Source detail retained for auditability.";
        aggregate.identity = sample.identity;
    }

    for (const auto& by_device : grouped) {
        PerDeviceBandwidthUsage usage{};
        usage.device_key = by_device.first;
        const AttributionSourceDetail* best = nullptr;
        int best_priority = -1;
        for (const auto& by_source : by_device.second) {
            const auto priority = attribution_source_priority(by_source.first);
            usage.source_details.push_back(by_source.second.detail);
            if (best == nullptr || priority > best_priority) {
                best = &by_source.second.detail;
                best_priority = priority;
                usage.identity = by_source.second.identity;
            }
        }
        if (best == nullptr) {
            continue;
        }
        usage.rx_bytes = best->rx_bytes;
        usage.tx_bytes = best->tx_bytes;
        usage.confidence = best->confidence;
        if (config.elapsed_seconds > 0.0) {
            usage.rx_rate_bps = static_cast<double>(usage.rx_bytes) * 8.0 / config.elapsed_seconds;
            usage.tx_rate_bps = static_cast<double>(usage.tx_bytes) * 8.0 / config.elapsed_seconds;
        }
        const auto best_total = best->rx_bytes + best->tx_bytes;
        for (const auto& detail : usage.source_details) {
            const auto detail_total = detail.rx_bytes + detail.tx_bytes;
            if (usage.source_details.size() > 1 && best_total > 0 && detail_total > 0 &&
                (detail_total > (best_total + best_total / 4) || detail_total < (best_total * 3 / 4))) {
                usage.conflict = true;
            }
        }
        if (usage.conflict) {
            const auto message = "Conflicting bandwidth sources for " + usage.device_key + "; using " + best->source_name + " while retaining all details.";
            usage.limitations.push_back(message);
            report.conflicts.push_back(message);
        }
        if (usage.confidence == "local-host-only") {
            usage.limitations.push_back("This row measures only the Windows PC running NetSentinel11.");
        }
        report.devices.push_back(std::move(usage));
    }

    std::sort(report.devices.begin(), report.devices.end(), [](const auto& left, const auto& right) {
        return left.device_key < right.device_key;
    });
    report.success = true;
    report.user_message = "Bandwidth attribution merged source details without double-counting overlapping measurements.";
    return report;
}

BandwidthAnomalyReport analyze_bandwidth_top_talkers_and_anomalies(
    const std::vector<PerDeviceBandwidthUsage>& current,
    const std::vector<PerDeviceBandwidthUsage>& baseline,
    const BandwidthAnomalyRuleConfig& config
) {
    BandwidthAnomalyReport report{};
    std::unordered_map<std::string, std::uint64_t> baseline_totals;
    for (const auto& device : baseline) {
        baseline_totals[device.device_key] = device.rx_bytes + device.tx_bytes;
    }

    std::vector<PerDeviceBandwidthUsage> sorted = current;
    std::sort(sorted.begin(), sorted.end(), [](const auto& left, const auto& right) {
        return (left.rx_bytes + left.tx_bytes) > (right.rx_bytes + right.tx_bytes);
    });

    const auto limit = std::min(config.top_talker_limit, sorted.size());
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& device = sorted[i];
        TopTalkerEntry entry{};
        entry.device_id = device.device_key;
        entry.confidence = device.confidence;
        entry.rx_bytes = device.rx_bytes;
        entry.tx_bytes = device.tx_bytes;
        entry.total_bytes = device.rx_bytes + device.tx_bytes;
        entry.evidence.push_back("rank=" + std::to_string(i + 1));
        entry.evidence.push_back("rx_bytes=" + std::to_string(device.rx_bytes));
        entry.evidence.push_back("tx_bytes=" + std::to_string(device.tx_bytes));
        entry.evidence.push_back("confidence=" + device.confidence);
        report.top_talkers.push_back(std::move(entry));
    }

    for (const auto& device : current) {
        const auto total = device.rx_bytes + device.tx_bytes;
        const auto baseline_it = baseline_totals.find(device.device_key);
        const auto baseline_total = baseline_it == baseline_totals.end() ? 0 : baseline_it->second;

        if (device.rx_bytes >= config.spike_rx_threshold_bytes && baseline_total > 0 && total > baseline_total * 3) {
            BandwidthAnomalyAlert alert{};
            alert.alert_id = "bandwidth-spike-" + device.device_key;
            alert.device_id = device.device_key;
            alert.kind = "bandwidth-spike";
            alert.severity = "medium";
            alert.explanation = "Unusual traffic pattern: current download volume is much higher than the baseline.";
            alert.evidence = {
                "current_total_bytes=" + std::to_string(total),
                "baseline_total_bytes=" + std::to_string(baseline_total),
                "threshold_rx_bytes=" + std::to_string(config.spike_rx_threshold_bytes)
            };
            report.alerts.push_back(std::move(alert));
        }

        if (device.tx_bytes >= config.unusual_upload_threshold_bytes) {
            BandwidthAnomalyAlert alert{};
            alert.alert_id = "unusual-upload-" + device.device_key;
            alert.device_id = device.device_key;
            alert.kind = "unusual-upload";
            alert.severity = "medium";
            alert.explanation = "Unusual traffic pattern: upload volume exceeded the configured threshold.";
            alert.evidence = {
                "tx_bytes=" + std::to_string(device.tx_bytes),
                "threshold_tx_bytes=" + std::to_string(config.unusual_upload_threshold_bytes),
                "confidence=" + device.confidence
            };
            report.alerts.push_back(std::move(alert));
        }

        if (baseline_total <= config.quiet_device_baseline_bytes && total >= config.quiet_device_active_threshold_bytes) {
            BandwidthAnomalyAlert alert{};
            alert.alert_id = "quiet-device-active-" + device.device_key;
            alert.device_id = device.device_key;
            alert.kind = "quiet-device-suddenly-active";
            alert.severity = "low";
            alert.explanation = "Unusual traffic pattern: a previously quiet device became active.";
            alert.evidence = {
                "current_total_bytes=" + std::to_string(total),
                "baseline_total_bytes=" + std::to_string(baseline_total),
                "quiet_baseline_bytes=" + std::to_string(config.quiet_device_baseline_bytes)
            };
            report.alerts.push_back(std::move(alert));
        }
    }

    report.tuning_notes = {
        "Thresholds are tunable and should be adjusted per network.",
        "Alerts describe unusual traffic patterns only; they are not malware detections.",
        "Evidence includes bytes, thresholds, confidence, and baseline comparisons."
    };
    report.success = true;
    report.user_message = "Top talkers and explainable bandwidth anomaly alerts generated.";
    return report;
}

BandwidthAnomalyReport mock_bandwidth_anomaly_report() {
    const auto samples = mock_bandwidth_attribution_samples();
    BandwidthAttributionMergeConfig merge_config{};
    merge_config.elapsed_seconds = 30.0;
    auto current_report = attribute_bandwidth_per_device(samples, merge_config);

    std::vector<PerDeviceBandwidthUsage> baseline;
    for (auto device : current_report.devices) {
        device.rx_bytes = std::min<std::uint64_t>(device.rx_bytes / 8, 80000);
        device.tx_bytes = std::min<std::uint64_t>(device.tx_bytes / 8, 20000);
        baseline.push_back(std::move(device));
    }

    BandwidthAnomalyRuleConfig config{};
    config.top_talker_limit = 3;
    config.spike_rx_threshold_bytes = 1000000;
    config.unusual_upload_threshold_bytes = 1000000;
    config.quiet_device_baseline_bytes = 120000;
    config.quiet_device_active_threshold_bytes = 900000;
    return analyze_bandwidth_top_talkers_and_anomalies(current_report.devices, baseline, config);
}

std::string bandwidth_capabilities_markdown(const std::vector<BandwidthSourceCapability>& capabilities) {
    std::ostringstream out;
    out << "# Bandwidth Source Capabilities\n\n";
    out << "Prompt 52 defines source contracts only. No packet capture, router polling, or flow collection is active in this stage.\n\n";
    for (const auto& capability : capabilities) {
        out << "- " << capability.source_name
            << " kind=" << to_string(capability.kind)
            << " available=" << (capability.available ? "yes" : "planned")
            << " per_device=" << (capability.per_device ? "yes" : "no")
            << " aggregate=" << (capability.aggregate ? "yes" : "no")
            << " requires_admin=" << (capability.requires_admin ? "yes" : "no")
            << " optional_dependency=" << (capability.optional_dependency ? "yes" : "no")
            << "\n";
        if (!capability.dependency_name.empty()) {
            out << "  dependency: " << capability.dependency_name << "\n";
        }
        out << "  setup: " << capability.safe_setup_hint << "\n";
        for (const auto& limitation : capability.limitations) {
            out << "  limitation: " << limitation << "\n";
        }
    }
    return out.str();
}

std::string npcap_detection_markdown(const NpcapDetectionReport& report) {
    std::ostringstream out;
    out << "# Npcap Capability Report\n\n";
    out << "- Installed: " << (report.installed ? "yes" : "no") << "\n";
    out << "- Driver service present: " << (report.driver_service_present ? "yes" : "no") << "\n";
    out << "- Administrator permissions: " << (report.current_user_admin ? "yes" : "no") << "\n";
    out << "- Capture available: " << (report.capture_available ? "yes" : "no") << "\n";
    out << "- Monitor mode available: " << (report.monitor_mode_available ? "yes" : "no") << "\n";
    out << "- Adapters reported: " << report.adapters.size() << "\n\n";
    out << "## Messages\n";
    for (const auto& message : report.messages) {
        out << "- " << message << "\n";
    }
    out << "\n## Adapter capabilities\n";
    for (const auto& adapter : report.adapters) {
        out << "- " << adapter.display_name
            << " id=" << adapter.adapter_id
            << " supported=" << (adapter.supported ? "yes" : "no")
            << " permission_granted=" << (adapter.permission_granted ? "yes" : "no")
            << " monitor_mode_supported=" << (adapter.monitor_mode_supported ? "yes" : "no")
            << "\n";
        out << "  message: " << adapter.user_message << "\n";
        for (const auto& limitation : adapter.limitations) {
            out << "  limitation: " << limitation << "\n";
        }
    }
    out << "\n## Safety\n";
    out << "- No packet capture is started by this report.\n";
    out << "- Missing driver, non-admin mode, unsupported adapter, and monitor-mode limitations are reported as safe capability messages.\n";
    return out.str();
}

std::string local_machine_bandwidth_markdown(const LocalMachineBandwidthSnapshot& snapshot) {
    std::ostringstream out;
    out << "# Local Machine Bandwidth\n\n";
    out << "- Status: " << (snapshot.success ? "ok" : "error") << "\n";
    out << "- Scope: " << snapshot.scope << "\n";
    out << "- RX total bytes: " << snapshot.rx_total_bytes << "\n";
    out << "- TX total bytes: " << snapshot.tx_total_bytes << "\n";
    out << "- RX rate bps: " << snapshot.rx_rate_bps << "\n";
    out << "- TX rate bps: " << snapshot.tx_rate_bps << "\n";
    out << "- Persisted: " << (snapshot.persisted ? "yes" : "no") << "\n";
    out << "- Storage: " << snapshot.storage_message << "\n";
    out << "- Limitation: " << snapshot.limitation << "\n";
    if (!snapshot.success) {
        out << "- Error: " << to_string(snapshot.error.code) << " " << snapshot.error.user_message << "\n";
    }
    out << "\n## Samples\n";
    for (const auto& sample : snapshot.status.samples) {
        out << "- source=" << sample.source_name
            << " timestamp=" << sample.timestamp_utc
            << " rx_bytes=" << sample.rx_bytes
            << " tx_bytes=" << sample.tx_bytes
            << " device_id=" << sample.identity.device_id
            << " hostname=" << sample.identity.hostname
            << " confidence=" << to_string(sample.confidence)
            << "\n";
    }
    return out.str();
}

std::string visible_lan_capture_markdown(const VisibleLanCaptureReport& report) {
    std::ostringstream out;
    out << "# Visible LAN Capture Bandwidth\n\n";
    out << "- Status: " << (report.success ? "ok" : "error") << "\n";
    out << "- Adapter: " << report.adapter_id << "\n";
    out << "- Dry run: " << (report.dry_run ? "yes" : "no") << "\n";
    out << "- Capture started: " << (report.capture_started ? "yes" : "no") << "\n";
    out << "- Packet injection used: " << (report.injection_used ? "yes" : "no") << "\n";
    out << "- Message: " << report.user_message << "\n";
    if (!report.success) {
        out << "- Error: " << to_string(report.error.code) << " " << report.error.user_message << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : report.limitations) {
        out << "- " << limitation << "\n";
    }
    out << "\n## Samples\n";
    for (const auto& sample : report.samples) {
        out << "- source=" << sample.source_name
            << " timestamp=" << sample.timestamp_utc
            << " rx_bytes=" << sample.rx_bytes
            << " tx_bytes=" << sample.tx_bytes
            << " confidence=" << to_string(sample.confidence)
            << " ip=" << sample.identity.ip_address
            << " mac=" << sample.identity.mac_address
            << " hostname=" << sample.identity.hostname
            << "\n";
    }
    out << "\n## Safety\n";
    out << "- Capture is limited to traffic visible on the selected adapter.\n";
    out << "- This is not full-network bandwidth unless mirrored/gateway traffic is visible.\n";
    out << "- No packet injection or disruptive network behavior is used.\n";
    return out.str();
}

std::string snmp_router_counter_markdown(const SnmpRouterCounterReport& report) {
    std::ostringstream out;
    out << "# SNMP Router Counter Bandwidth\n\n";
    out << "- Status: " << (report.success ? "ok" : "error") << "\n";
    out << "- Router: " << report.router_ip << "\n";
    out << "- Read-only SNMP: " << (report.read_only ? "yes" : "no") << "\n";
    out << "- Credential reference used: " << (report.credential_reference_used ? "yes" : "no") << "\n";
    out << "- Network poll started: " << (report.network_poll_started ? "yes" : "no") << "\n";
    out << "- Interfaces: " << report.interfaces.size() << "\n";
    out << "- Samples: " << report.samples.size() << "\n";
    out << "- Message: " << report.user_message << "\n";
    if (!report.success) {
        out << "- Error: " << to_string(report.error.code) << " " << report.error.user_message << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : report.limitations) {
        out << "- " << limitation << "\n";
    }
    out << "\n## Interfaces\n";
    for (const auto& iface : report.interfaces) {
        out << "- " << iface.interface_name
            << " id=" << iface.interface_id
            << " rx_delta_bytes=" << iface.rx_delta_bytes
            << " tx_delta_bytes=" << iface.tx_delta_bytes
            << " confidence=" << to_string(iface.confidence)
            << " rollover=" << (iface.rollover_detected ? "yes" : "no")
            << " mac=" << iface.mac_address
            << " ip_hint=" << iface.ip_address_hint
            << "\n";
    }
    out << "\n## Safety\n";
    out << "- Read-only SNMP only.\n";
    out << "- No credential guessing, SNMP writes, exploit checks, or disruptive behavior.\n";
    out << "- Community strings or credentials should be stored by reference in Windows Credential Manager or an equivalent safe store.\n";
    return out.str();
}

std::string upnp_igd_counter_markdown(const UpnpIgdCounterReport& report) {
    std::ostringstream out;
    out << "# UPnP IGD Router Counter Bandwidth\n\n";
    out << "- Status: " << (report.success ? "ok" : "error") << "\n";
    out << "- Gateway: " << report.gateway << "\n";
    out << "- Read-only telemetry: " << (report.read_only ? "yes" : "no") << "\n";
    out << "- Mapping changes attempted: " << (report.mapping_changes_attempted ? "yes" : "no") << "\n";
    out << "- Counters available: " << (report.counters_available ? "yes" : "no") << "\n";
    out << "- Network poll started: " << (report.network_poll_started ? "yes" : "no") << "\n";
    out << "- Attribution level: " << (report.network_wide ? "network-wide" : "per-device") << "\n";
    out << "- RX delta bytes: " << report.rx_delta_bytes << "\n";
    out << "- TX delta bytes: " << report.tx_delta_bytes << "\n";
    out << "- RX rate bps: " << report.rx_rate_bps << "\n";
    out << "- TX rate bps: " << report.tx_rate_bps << "\n";
    out << "- Message: " << report.user_message << "\n";
    if (!report.success) {
        out << "- Error: " << to_string(report.error.code) << " " << report.error.user_message << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : report.limitations) {
        out << "- " << limitation << "\n";
    }
    out << "\n## Samples\n";
    for (const auto& sample : report.samples) {
        out << "- source=" << sample.source_name
            << " timestamp=" << sample.timestamp_utc
            << " rx_bytes=" << sample.rx_bytes
            << " tx_bytes=" << sample.tx_bytes
            << " confidence=" << to_string(sample.confidence)
            << " attribution=network-wide"
            << "\n";
    }
    out << "\n## Safety\n";
    out << "- Read-only UPnP/IGD telemetry only.\n";
    out << "- No port mapping changes are attempted in this stage.\n";
    out << "- If counters cannot be mapped per device, attribution stays network-wide.\n";
    return out.str();
}

std::string flow_collector_markdown(const FlowCollectorReport& report) {
    std::ostringstream out;
    out << "# Flow Export Collector\n\n";
    out << "- Status: " << (report.success ? "ok" : "error") << "\n";
    out << "- Bind address: " << report.bind_address << "\n";
    out << "- Port: " << report.port << "\n";
    out << "- Explicit enablement: " << (report.explicit_enablement ? "yes" : "no") << "\n";
    out << "- Listener started: " << (report.listener_started ? "yes" : "no") << "\n";
    out << "- Records: " << report.records.size() << "\n";
    out << "- Samples: " << report.samples.size() << "\n";
    out << "- Message: " << report.user_message << "\n";
    if (!report.success) {
        out << "- Error: " << to_string(report.error.code) << " " << report.error.user_message << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : report.limitations) {
        out << "- " << limitation << "\n";
    }
    out << "\n## Records\n";
    for (const auto& record : report.records) {
        out << "- protocol=" << to_string(record.protocol)
            << " exporter=" << record.exporter
            << " src=" << record.source_ip
            << " dst=" << record.destination_ip
            << " bytes=" << record.bytes
            << " packets=" << record.packets
            << " ingress=" << record.ingress_interface
            << " egress=" << record.egress_interface
            << "\n";
    }
    out << "\n## Safety\n";
    out << "- The collector is passive and only receives exports from authorized routers/firewalls.\n";
    out << "- Listening requires explicit enablement and a configured local port.\n";
    out << "- No active scan traffic is generated.\n";
    return out.str();
}

std::string router_plugin_capabilities_markdown(const std::vector<RouterPluginCapability>& capabilities) {
    std::ostringstream out;
    out << "# Router Plugin SDK Capabilities\n\n";
    out << "Plugins are bounded to documented APIs, safe credential references, read-only telemetry, and reversible access-control actions.\n\n";
    for (const auto& capability : capabilities) {
        out << "- " << capability.plugin_id
            << " display=\"" << capability.display_name << "\""
            << " vendor=\"" << capability.vendor_family << "\""
            << " implemented=" << (capability.implemented ? "yes" : "planned")
            << " read_only_telemetry=" << (capability.read_only_telemetry ? "yes" : "no")
            << " reversible_access_control=" << (capability.reversible_access_control ? "yes" : "no")
            << " documented_api_required=" << (capability.documented_api_required ? "yes" : "no")
            << " credential_reference_required=" << (capability.credential_reference_required ? "yes" : "no")
            << " planned_adapter=" << capability.planned_adapter
            << "\n";
        for (const auto& limitation : capability.limitations) {
            out << "  limitation: " << limitation << "\n";
        }
    }
    out << "\n## Safety\n";
    out << "- No password scraping, brute force, hidden APIs, or undocumented router behavior.\n";
    out << "- Real actions must be explicit, confirmed, logged, and reversible.\n";
    return out.str();
}

std::string router_plugin_result_markdown(const RouterPluginResult& result) {
    std::ostringstream out;
    out << "# Router Plugin Result\n\n";
    out << "- Status: " << (result.success ? "ok" : "error") << "\n";
    out << "- Plugin: " << result.plugin_id << "\n";
    out << "- Operation: " << result.operation << "\n";
    out << "- Applied: " << (result.applied ? "yes" : "no") << "\n";
    out << "- Reversible: " << (result.reversible ? "yes" : "no") << "\n";
    out << "- Requires confirmation: " << (result.requires_confirmation ? "yes" : "no") << "\n";
    out << "- Documented API used: " << (result.used_documented_api ? "yes" : "no") << "\n";
    out << "- Password scraping used: " << (result.password_scraping_used ? "yes" : "no") << "\n";
    out << "- Message: " << result.user_message << "\n";
    if (!result.success) {
        out << "- Error: " << to_string(result.error.code) << " " << result.error.user_message << "\n";
    }
    out << "\n## Telemetry samples\n";
    for (const auto& sample : result.telemetry_samples) {
        out << "- source=" << sample.source_name
            << " rx_bytes=" << sample.rx_bytes
            << " tx_bytes=" << sample.tx_bytes
            << " ip=" << sample.identity.ip_address
            << " mac=" << sample.identity.mac_address
            << " confidence=" << to_string(sample.confidence)
            << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : result.limitations) {
        out << "- " << limitation << "\n";
    }
    return out.str();
}

std::string bandwidth_limit_result_markdown(const BandwidthLimitResult& result) {
    std::ostringstream out;
    out << "# Safe Bandwidth Limit Backend\n\n";
    out << "- Status: " << (result.success ? "ok" : "error") << "\n";
    out << "- Backend: " << result.backend << "\n";
    out << "- Action: " << result.action << "\n";
    out << "- Dry run: " << (result.dry_run ? "yes" : "no") << "\n";
    out << "- Applied: " << (result.applied ? "yes" : "no") << "\n";
    out << "- Reversible: " << (result.reversible ? "yes" : "no") << "\n";
    out << "- Requires confirmation: " << (result.requires_confirmation ? "yes" : "no") << "\n";
    out << "- Documented API used: " << (result.documented_api_used ? "yes" : "no") << "\n";
    out << "- Unsafe method rejected: " << (result.unsafe_method_rejected ? "yes" : "no") << "\n";
    out << "- Logged: " << (result.logged ? "yes" : "no") << "\n";
    out << "- Rollback id: " << result.rollback_id << "\n";
    out << "- Message: " << result.user_message << "\n";
    if (!result.success) {
        out << "- Error: " << to_string(result.error.code) << " " << result.error.user_message << "\n";
    }
    out << "\n## Steps\n";
    for (const auto& step : result.steps) {
        out << "- backend=" << step.backend
            << " action=" << step.action
            << " target=" << step.target
            << " status=" << step.status
            << " reversible_action=" << step.reversible_action
            << "\n";
        out << "  detail: " << step.detail << "\n";
    }
    out << "\n## Audit log\n";
    for (const auto& entry : result.audit_log) {
        out << "- " << entry << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : result.limitations) {
        out << "- " << limitation << "\n";
    }
    out << "\n## Safety\n";
    out << "- No ARP spoofing, deauthentication, MITM, packet injection, exploit payloads, brute force, or stealth behavior.\n";
    out << "- Real OpenWrt writes are disabled in Prompt 67; the prototype is dry-run/mock only.\n";
    out << "- Apply requires `--confirm` unless a saved rule is already present.\n";
    return out.str();
}

std::string autoblock_policy_markdown(const AutoblockPolicyResult& result) {
    std::ostringstream out;
    out << "# Autoblock Unknown Devices Safe Mode\n\n";
    out << "- Status: " << (result.success ? "ok" : "error") << "\n";
    out << "- Alert only: " << (result.alert_only ? "yes" : "no") << "\n";
    out << "- Enforcement enabled: " << (result.enforcement_enabled ? "yes" : "no") << "\n";
    out << "- Rollback button available: " << (result.rollback_button_available ? "yes" : "no") << "\n";
    out << "- Alerts: " << result.alerts.size() << "\n";
    out << "- Decisions: " << result.decisions.size() << "\n";
    out << "- Message: " << result.user_message << "\n";
    out << "\n## Alerts\n";
    for (const auto& alert : result.alerts) {
        out << "- " << alert << "\n";
    }
    out << "\n## Decisions\n";
    for (const auto& decision : result.decisions) {
        out << "- device=" << decision.device_id
            << " ip=" << decision.ip_address
            << " mac=" << decision.mac_address
            << " unknown=" << (decision.unknown ? "yes" : "no")
            << " state=" << decision.state
            << " enforcement_attempted=" << (decision.enforcement_attempted ? "yes" : "no")
            << " rollback_available=" << (decision.rollback_available ? "yes" : "no")
            << " rollback_id=" << decision.rollback_id
            << "\n";
        out << "  detail: " << decision.detail << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : result.limitations) {
        out << "- " << limitation << "\n";
    }
    out << "\n## Safety\n";
    out << "- Default is alert-only.\n";
    out << "- Enforcement uses only configured safe backends and rollback-capable plans.\n";
    out << "- No ARP spoofing, deauthentication, jamming, MITM, packet injection, exploit payloads, brute force, or stealth behavior.\n";
    return out.str();
}

std::string openwrt_telemetry_markdown(const OpenWrtTelemetryReport& report) {
    std::ostringstream out;
    out << "# OpenWrt Read-only Bandwidth Plugin\n\n";
    out << "- Status: " << (report.success ? "ok" : "error") << "\n";
    out << "- Endpoint: " << report.endpoint << "\n";
    out << "- Transport: " << report.transport << "\n";
    out << "- Read-only: " << (report.read_only ? "yes" : "no") << "\n";
    out << "- Credential reference used: " << (report.credential_reference_used ? "yes" : "no") << "\n";
    out << "- Network request started: " << (report.network_request_started ? "yes" : "no") << "\n";
    out << "- Firmware supported: " << (report.firmware_supported ? "yes" : "no") << "\n";
    out << "- Firmware version: " << report.firmware_version << "\n";
    out << "- Devices: " << report.devices.size() << "\n";
    out << "- Samples: " << report.samples.size() << "\n";
    out << "- Message: " << report.user_message << "\n";
    if (!report.success) {
        out << "- Error: " << to_string(report.error.code) << " " << report.error.user_message << "\n";
    }
    out << "\n## Devices\n";
    for (const auto& device : report.devices) {
        out << "- hostname=" << device.hostname
            << " ip=" << device.ip_address
            << " mac=" << device.mac_address
            << " rx_bytes=" << device.rx_bytes
            << " tx_bytes=" << device.tx_bytes
            << " online=" << (device.online ? "yes" : "no")
            << "\n";
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : report.limitations) {
        out << "- " << limitation << "\n";
    }
    out << "\n## Safety\n";
    out << "- Documented OpenWrt RPC or SSH read-only paths only.\n";
    out << "- Never alter firewall/QoS in this stage.\n";
    out << "- Unsupported firmware is reported with a clear error.\n";
    return out.str();
}

std::string bandwidth_attribution_markdown(const BandwidthAttributionMergeReport& report) {
    std::ostringstream out;
    out << "# Per-device Bandwidth Attribution\n\n";
    out << "- Status: " << (report.success ? "ok" : "error") << "\n";
    out << "- Devices: " << report.devices.size() << "\n";
    out << "- Network-only RX bytes: " << report.network_only_rx_bytes << "\n";
    out << "- Network-only TX bytes: " << report.network_only_tx_bytes << "\n";
    out << "- Conflicts: " << report.conflicts.size() << "\n";
    out << "- Message: " << report.user_message << "\n";
    out << "\n## Devices\n";
    for (const auto& device : report.devices) {
        out << "- key=" << device.device_key
            << " ip=" << device.identity.ip_address
            << " mac=" << device.identity.mac_address
            << " hostname=" << device.identity.hostname
            << " rx_bytes=" << device.rx_bytes
            << " tx_bytes=" << device.tx_bytes
            << " confidence=" << device.confidence
            << " conflict=" << (device.conflict ? "yes" : "no")
            << "\n";
        for (const auto& detail : device.source_details) {
            out << "  source=" << detail.source_name
                << " rx=" << detail.rx_bytes
                << " tx=" << detail.tx_bytes
                << " confidence=" << detail.confidence
                << " note=" << detail.note
                << "\n";
        }
    }
    out << "\n## Limitations\n";
    for (const auto& limitation : report.limitations) {
        out << "- " << limitation << "\n";
    }
    out << "\n## Confidence levels\n";
    out << "- exact: router-exported flow records with source/destination metadata.\n";
    out << "- high: strong router/plugin source with device identity.\n";
    out << "- medium: useful but possibly interface-level or plugin-derived source.\n";
    out << "- low: partial visibility or heuristic source.\n";
    out << "- network-only: aggregate counters that cannot be mapped per device.\n";
    out << "- local-host-only: this Windows PC only.\n";
    return out.str();
}

std::string bandwidth_anomaly_report_markdown(const BandwidthAnomalyReport& report) {
    std::ostringstream out;
    out << "# Top Talkers And Bandwidth Anomaly Alerts\n\n";
    out << "- Status: " << (report.success ? "ok" : "error") << "\n";
    out << "- Top talkers: " << report.top_talkers.size() << "\n";
    out << "- Alerts: " << report.alerts.size() << "\n";
    out << "- Safety wording: unusual traffic pattern, not malware detection\n";
    out << "- Message: " << report.user_message << "\n";
    out << "\n## Top Talkers\n";
    for (const auto& talker : report.top_talkers) {
        out << "- device=" << talker.device_id
            << " total_bytes=" << talker.total_bytes
            << " rx_bytes=" << talker.rx_bytes
            << " tx_bytes=" << talker.tx_bytes
            << " confidence=" << talker.confidence
            << "\n";
        for (const auto& evidence : talker.evidence) {
            out << "  - evidence: " << evidence << "\n";
        }
    }
    out << "\n## Alerts\n";
    for (const auto& alert : report.alerts) {
        out << "- id=" << alert.alert_id
            << " device=" << alert.device_id
            << " kind=" << alert.kind
            << " severity=" << alert.severity
            << " malware_claim=" << (alert.malware_claim ? "yes" : "no")
            << "\n";
        out << "  - explanation: " << alert.explanation << "\n";
        for (const auto& evidence : alert.evidence) {
            out << "  - evidence: " << evidence << "\n";
        }
    }
    out << "\n## Tuning Notes\n";
    for (const auto& note : report.tuning_notes) {
        out << "- " << note << "\n";
    }
    return out.str();
}

std::string bandwidth_samples_markdown(const BandwidthSourceStatus& status) {
    std::ostringstream out;
    out << "# Bandwidth Samples\n\n";
    out << "- Source: " << status.capability.source_name << "\n";
    out << "- Status: " << (status.success ? "ok" : "error") << "\n";
    if (!status.success) {
        out << "- Error: " << to_string(status.error.code) << " " << status.error.user_message << "\n";
    }
    out << "- Samples: " << status.samples.size() << "\n";
    for (const auto& sample : status.samples) {
        out << "- sample source=" << sample.source_name
            << " timestamp=" << sample.timestamp_utc
            << " rx_bytes=" << sample.rx_bytes
            << " tx_bytes=" << sample.tx_bytes
            << " confidence=" << to_string(sample.confidence)
            << " device_id=" << sample.identity.device_id
            << " ip=" << sample.identity.ip_address
            << " mac=" << sample.identity.mac_address
            << " hostname=" << sample.identity.hostname
            << "\n";
    }
    return out.str();
}

} // namespace netsentinel::bandwidth
