#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace netsentinel::engine {

struct NetworkInterface {
    std::string interface_id;
    std::string name;
    std::optional<std::string> display_name;
    std::optional<std::string> mac_address;
    bool is_up = false;
    std::vector<std::string> ipv4_addresses;
    std::vector<std::string> ipv6_addresses;

    std::string to_json() const;
    static NetworkInterface from_json(const std::string& json);
};

struct NetworkScope {
    std::string scope_id;
    std::string cidr_or_range;
    std::string notes;
    bool local_only = true;
    bool authorized = true;
    int64_t created_epoch_ms = 0;

    std::string to_json() const;
    static NetworkScope from_json(const std::string& json);
};

struct DeviceIdentity {
    std::string device_id;
    std::string hostname;
    std::string hostname_source;
    int hostname_confidence = 0;
    std::optional<std::string> netbios_name;
    std::string netbios_workgroup;
    std::string netbios_source;
    int netbios_confidence = 0;
    std::optional<std::string> mac_address;
    std::vector<std::string> ipv4_addresses;
    std::optional<std::string> vendor_hint;
    int confidence = 0;

    std::string to_json() const;
    static DeviceIdentity from_json(const std::string& json);
};

struct ProbeResult {
    std::string probe_name;
    std::string target;
    bool success = false;
    int64_t response_time_ms = 0;
    std::string message;
    std::string error_code;

    std::string to_json() const;
    static ProbeResult from_json(const std::string& json);
};

struct ScanSession {
    std::string session_id;
    std::string profile_name;
    std::string started_at_utc;
    std::string ended_at_utc;
    bool completed = false;
    std::string status_text;
    std::vector<ProbeResult> probe_results;

    std::string to_json() const;
    static ScanSession from_json(const std::string& json);
};

struct ScanProfile {
    std::string profile_id;
    std::string name;
    NetworkScope scope;
    bool enabled = true;
    int32_t timeout_seconds = 30;
    int32_t retries = 1;

    std::string to_json() const;
    static ScanProfile from_json(const std::string& json);
};

enum class DeviceEventKind {
    Discovered = 0,
    Updated = 1,
    Offline = 2,
    SecurityFinding = 3,
    Recovered = 4
};

std::string to_string(DeviceEventKind kind);
DeviceEventKind device_event_kind_from_string(std::string_view value);

struct DeviceEvent {
    DeviceEventKind kind = DeviceEventKind::Discovered;
    std::string device_id;
    std::string at_utc;
    std::string summary;
    std::string details;

    std::string to_json() const;
    static DeviceEvent from_json(const std::string& json);
};

enum class Severity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
};

std::string to_string(Severity level);
Severity severity_from_string(std::string_view value);

struct SecurityFinding {
    std::string finding_id;
    std::string device_id;
    Severity severity = Severity::Low;
    std::string title;
    std::string details;
    std::string first_seen_utc;
    bool acknowledged = false;

    std::string to_json() const;
    static SecurityFinding from_json(const std::string& json);
};

struct ReportSummary {
    std::string report_id;
    std::string generated_at_utc;
    std::size_t total_devices = 0;
    std::size_t total_events = 0;
    std::size_t total_findings = 0;
    double health_score = 0.0;
    std::string warnings;

    std::string to_json() const;
    static ReportSummary from_json(const std::string& json);
};

bool validate_network_like(const std::string& value);

} // namespace netsentinel::engine
