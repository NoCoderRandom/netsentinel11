#include "netsentinel/storage/storage.h"

#include <algorithm>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <optional>
#include <chrono>
#include <ctime>
#include <cctype>
#include <unordered_map>
#include <unordered_set>

namespace {

constexpr std::size_t k_min_schema_version = 1;
constexpr std::size_t k_latest_schema_version = 2;
constexpr const char* k_schema_version_prefix = "SCHEMA_VERSION=";
constexpr const char* k_line_scan_session = "SCAN_SESSION";
constexpr const char* k_line_network = "NETWORK";
constexpr const char* k_line_adapter = "ADAPTER";
constexpr const char* k_line_device = "DEVICE";
constexpr const char* k_line_inventory_device = "INV_DEVICE";
constexpr const char* k_line_probe = "SCAN_PROBE";
constexpr const char* k_line_event = "EVENT";
constexpr const char* k_line_workspace = "WORKSPACE";
constexpr const char* k_line_workspace_scan = "WORKSPACE_SCAN";
constexpr const char* k_line_filter_template = "FILTER_TEMPLATE";
constexpr const char* k_line_bandwidth_rollup = "BANDWIDTH_ROLLUP";

constexpr std::size_t k_inventory_record_fields = 13;
constexpr std::size_t k_timeline_record_fields = 9;
constexpr std::size_t k_workspace_record_fields = 13;
constexpr std::size_t k_workspace_scan_record_fields = 6;
constexpr std::size_t k_filter_template_fields = 10;
constexpr std::size_t k_bandwidth_rollup_fields_v1 = 12;
constexpr std::size_t k_bandwidth_rollup_fields_v2 = 15;
constexpr int k_max_importance = 100;
constexpr int k_min_importance = 0;
constexpr int k_severity_join = 2;
constexpr int k_severity_leave = 2;
constexpr int k_severity_name_change = 3;
constexpr int k_severity_vendor_change = 2;
constexpr int k_severity_ip_change = 4;
constexpr int k_severity_open_port_change = 3;
constexpr const char* k_event_join = "join";
constexpr const char* k_event_leave = "leave";
constexpr const char* k_event_name_change = "name-change";
constexpr const char* k_event_vendor_change = "vendor-change";
constexpr const char* k_event_ip_change = "ip-change";
constexpr const char* k_event_open_port_change = "open-port-change";

std::string escape_field(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (const char ch : value) {
        if (ch == '\\') {
            out += "\\\\";
        } else if (ch == '|') {
            out += "\\|";
        } else if (ch == '\n') {
            out += "\\n";
        } else if (ch == '\r') {
            out += "\\r";
        } else {
            out += ch;
        }
    }
    return out;
}

std::string unescape_field(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        const char ch = value[i];
        if (ch != '\\') {
            out += ch;
            continue;
        }
        if (i + 1 >= value.size()) {
            out += ch;
            continue;
        }
        ++i;
        const char next = value[i];
        if (next == 'n') {
            out += '\n';
        } else if (next == 'r') {
            out += '\r';
        } else {
            out += next;
        }
    }
    return out;
}

std::vector<std::string> split_record(const std::string& line) {
    std::vector<std::string> fields;
    std::string current;
    bool escaped = false;
    for (char ch : line) {
        if (escaped) {
            current += ch;
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '|') {
            fields.push_back(current);
            current.clear();
            continue;
        }
        current += ch;
    }
    fields.push_back(current);
    for (auto& field : fields) {
        field = unescape_field(field);
    }
    return fields;
}

std::vector<std::string> read_lines(const std::string& path) {
    std::vector<std::string> out;
    std::ifstream in(path);
    if (!in.is_open()) {
        return out;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        out.push_back(line);
    }
    return out;
}

void write_lines(const std::string& path, const std::vector<std::string>& lines) {
    const auto parent = std::filesystem::path{path}.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent);
    }
    std::ofstream out(path, std::ios::trunc);
    for (std::size_t i = 0; i < lines.size(); ++i) {
        out << lines[i] << "\n";
    }
}

bool parse_bool_field(const std::string& value, bool fallback) {
    if (value == "1" || value == "true" || value == "yes") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no") {
        return false;
    }
    return fallback;
}

int parse_int_field(const std::string& value, int fallback) {
    try {
        return std::stoi(value);
    } catch (...) {
        return fallback;
    }
}

std::uint64_t parse_u64_field(const std::string& value, std::uint64_t fallback) {
    try {
        return static_cast<std::uint64_t>(std::stoull(value));
    } catch (...) {
        return fallback;
    }
}

double parse_double_field(const std::string& value, double fallback) {
    try {
        return std::stod(value);
    } catch (...) {
        return fallback;
    }
}

std::vector<std::string> split_csv_list(const std::string& value) {
    std::vector<std::string> out;
    std::string token;
    std::stringstream stream(value);
    while (std::getline(stream, token, ',')) {
        if (!token.empty()) {
            out.push_back(token);
        }
    }
    return out;
}

std::vector<std::string> normalize_csv_list(const std::vector<std::string>& values) {
    auto out = values;
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    out.erase(
        std::remove_if(out.begin(), out.end(), [](const std::string& value) {
            return value.empty();
        }),
        out.end()
    );
    return out;
}

std::string join_csv_list(const std::vector<std::string>& values);

std::string join_csv_list_sorted(const std::vector<std::string>& values) {
    return join_csv_list(normalize_csv_list(values));
}

std::vector<std::string> ports_to_strings(const std::vector<int>& ports) {
    std::vector<std::string> out;
    out.reserve(ports.size());
    for (const auto port : ports) {
        out.push_back(std::to_string(port));
    }
    return out;
}

std::string join_csv_list(const std::vector<std::string>& values) {
    if (values.empty()) {
        return {};
    }
    std::string out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            out.push_back(',');
        }
        out += values[i];
    }
    return out;
}

std::string lower_copy(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) {
        return true;
    }
    return lower_copy(haystack).find(lower_copy(needle)) != std::string::npos;
}

bool contains_any_ci(const std::string& haystack, const std::vector<std::string>& needles) {
    const auto lower = lower_copy(haystack);
    for (const auto& needle : needles) {
        if (!needle.empty() && lower.find(lower_copy(needle)) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool parse_iso_utc(const std::string& value, std::time_t& out) {
    if (value.size() < 19) {
        return false;
    }
    try {
        std::tm tm_snapshot{};
        tm_snapshot.tm_year = std::stoi(value.substr(0, 4)) - 1900;
        tm_snapshot.tm_mon = std::stoi(value.substr(5, 2)) - 1;
        tm_snapshot.tm_mday = std::stoi(value.substr(8, 2));
        tm_snapshot.tm_hour = std::stoi(value.substr(11, 2));
        tm_snapshot.tm_min = std::stoi(value.substr(14, 2));
        tm_snapshot.tm_sec = std::stoi(value.substr(17, 2));
#ifdef _WIN32
        out = _mkgmtime(&tm_snapshot);
#else
        out = timegm(&tm_snapshot);
#endif
        return out >= 0;
    } catch (...) {
        return false;
    }
}

std::string iso_utc_from_time(std::time_t value) {
    std::tm tm_snapshot{};
#ifdef _WIN32
    gmtime_s(&tm_snapshot, &value);
#else
    gmtime_r(&value, &tm_snapshot);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm_snapshot);
    return std::string(buffer);
}

std::uint64_t seconds_between_utc(const std::string& start_utc, const std::string& end_utc) {
    std::time_t start = 0;
    std::time_t end = 0;
    if (!parse_iso_utc(start_utc, start) || !parse_iso_utc(end_utc, end) || end <= start) {
        return 0;
    }
    return static_cast<std::uint64_t>(std::difftime(end, start));
}

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        if (ch == '\\') {
            out += "\\\\";
            continue;
        }
        if (ch == '\"') {
            out += "\\\"";
            continue;
        }
        if (ch == '\n') {
            out += "\\n";
            continue;
        }
        if (ch == '\r') {
            out += "\\r";
            continue;
        }
        out += ch;
    }
    return out;
}

std::string json_list(const std::vector<std::string>& values) {
    std::string out = "[";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        out += "\"";
        out += json_escape(values[i]);
        out += "\"";
    }
    out += "]";
    return out;
}

std::string timestamp_now_utc() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::system_clock::to_time_t(now);
    std::tm tm_snapshot{};
#ifdef _WIN32
    gmtime_s(&tm_snapshot, &seconds);
#else
    gmtime_r(&seconds, &tm_snapshot);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm_snapshot);
    return std::string(buffer);
}

std::size_t parse_schema_version(const std::vector<std::string>& lines) {
    if (lines.empty()) {
        return k_min_schema_version;
    }
    if (lines[0].rfind(k_schema_version_prefix, 0) != 0) {
        return k_min_schema_version;
    }
    const auto value = lines[0].substr(std::string(k_schema_version_prefix).size());
    if (value.empty()) {
        return k_min_schema_version;
    }
    try {
        return static_cast<std::size_t>(std::stoul(value));
    } catch (...) {
        return k_min_schema_version;
    }
}

std::vector<std::string> ensure_header(std::vector<std::string> lines) {
    if (lines.empty()) {
        return {
            std::string(k_schema_version_prefix) + std::to_string(k_latest_schema_version),
            std::string(k_line_network) + "|",
            std::string(k_line_adapter) + "|",
            std::string(k_line_device) + "|",
            std::string(k_line_probe) + "|",
            std::string(k_line_event) + "|"
        };
    }
    if (lines[0].rfind(k_schema_version_prefix, 0) != 0) {
        lines.insert(lines.begin(), std::string(k_schema_version_prefix) + std::to_string(k_latest_schema_version));
    }
    if (lines.size() < 6) {
        return lines;
    }
    return lines;
}

struct ScanSessionLine {
    std::int64_t id = 0;
    std::string profile_json;
    std::string session_json;
};

bool is_scan_line(const std::string& line, ScanSessionLine& parsed) {
    if (line.rfind(k_line_scan_session, 0) != 0) {
        return false;
    }
    const auto parts = split_record(line);
    if (parts.size() != 4) {
        return false;
    }
    if (parts[0] != k_line_scan_session) {
        return false;
    }
    try {
        parsed.id = static_cast<std::int64_t>(std::stoll(parts[1]));
    } catch (...) {
        return false;
    }
    parsed.profile_json = parts[2];
    parsed.session_json = parts[3];
    return true;
}

std::vector<ScanSessionLine> list_scan_lines(const std::vector<std::string>& lines) {
    std::vector<ScanSessionLine> out;
    for (const auto& line : lines) {
        ScanSessionLine parsed;
        if (is_scan_line(line, parsed)) {
            out.push_back(std::move(parsed));
        }
    }
    return out;
}

void append_inventory_headers(std::vector<std::string>& lines) {
    if (std::find(lines.begin(), lines.end(), std::string(k_line_inventory_device) + "|") == lines.end()) {
        lines.push_back(std::string(k_line_inventory_device) + "|");
    }
}

netsentinel::storage::DeviceInventoryRecord parse_inventory_record(const std::vector<std::string>& fields) {
    using netsentinel::storage::DeviceInventoryRecord;
    DeviceInventoryRecord out{};
    out.device_id = fields[1];
    out.hostname = fields[2];
    out.ip_addresses = split_csv_list(fields[3]);
    out.mac_address = fields[4];
    out.vendor_hint = fields[5];
    out.device_type = fields[6];
    out.importance = parse_int_field(fields[7], 0);
    if (out.importance < k_min_importance) {
        out.importance = k_min_importance;
    }
    if (out.importance > k_max_importance) {
        out.importance = k_max_importance;
    }
    out.hidden = parse_bool_field(fields[8], false);
    out.stale = parse_bool_field(fields[9], false);
    out.user_labels = split_csv_list(fields[10]);
    out.details = fields[11];
    out.last_seen_utc = fields[12];
    return out;
}

netsentinel::storage::DeviceTimelineRecord parse_timeline_record(const std::vector<std::string>& fields) {
    using netsentinel::storage::DeviceTimelineRecord;
    DeviceTimelineRecord out{};
    out.network_id = fields[1];
    out.device_id = fields[2];
    out.event_type = fields[3];
    out.source = fields[4];
    out.severity = parse_int_field(fields[5], 0);
    if (out.severity < 0) {
        out.severity = 0;
    }
    out.old_value = fields[6];
    out.new_value = fields[7];
    out.at_utc = fields[8];
    if (out.at_utc.empty()) {
        out.at_utc = timestamp_now_utc();
    }
    return out;
}

bool is_inventory_record(const std::string& line, std::vector<std::string>& parsed_fields) {
    if (line.rfind(std::string(k_line_inventory_device), 0) != 0) {
        return false;
    }
    parsed_fields = split_record(line);
    return parsed_fields.size() == k_inventory_record_fields;
}

bool is_timeline_record(const std::string& line, std::vector<std::string>& parsed_fields) {
    if (line.rfind(std::string(k_line_event), 0) != 0) {
        return false;
    }
    parsed_fields = split_record(line);
    return parsed_fields.size() == k_timeline_record_fields;
}

bool is_bandwidth_rollup_record(const std::string& line, std::vector<std::string>& parsed_fields) {
    if (line.rfind(std::string(k_line_bandwidth_rollup), 0) != 0) {
        return false;
    }
    parsed_fields = split_record(line);
    return parsed_fields.size() == k_bandwidth_rollup_fields_v1 || parsed_fields.size() == k_bandwidth_rollup_fields_v2;
}

std::string format_inventory_record(const netsentinel::storage::DeviceInventoryRecord& record) {
    return std::string(k_line_inventory_device) + "|" +
        escape_field(record.device_id) + "|" +
        escape_field(record.hostname) + "|" +
        escape_field(join_csv_list(record.ip_addresses)) + "|" +
        escape_field(record.mac_address) + "|" +
        escape_field(record.vendor_hint) + "|" +
        escape_field(record.device_type) + "|" +
        std::to_string(std::max(k_min_importance, std::min(k_max_importance, record.importance))) + "|" +
        (record.hidden ? "1" : "0") + "|" +
        (record.stale ? "1" : "0") + "|" +
        escape_field(join_csv_list(record.user_labels)) + "|" +
        escape_field(record.details) + "|" +
        escape_field(record.last_seen_utc.empty() ? timestamp_now_utc() : record.last_seen_utc);
}

std::string format_timeline_record(const netsentinel::storage::DeviceTimelineRecord& record) {
    return std::string(k_line_event) + "|" +
        escape_field(record.network_id) + "|" +
        escape_field(record.device_id) + "|" +
        escape_field(record.event_type) + "|" +
        escape_field(record.source) + "|" +
        std::to_string(std::max(0, record.severity)) + "|" +
        escape_field(record.old_value) + "|" +
        escape_field(record.new_value) + "|" +
        escape_field(record.at_utc.empty() ? timestamp_now_utc() : record.at_utc);
}

netsentinel::storage::BandwidthRollupRecord parse_bandwidth_rollup_record(const std::vector<std::string>& fields) {
    netsentinel::storage::BandwidthRollupRecord record{};
    if (fields.size() != k_bandwidth_rollup_fields_v1 && fields.size() != k_bandwidth_rollup_fields_v2) {
        return record;
    }
    record.source_name = fields[1];
    record.device_id = fields[2];
    record.adapter_id = fields[3];
    record.timestamp_utc = fields[4];
    record.rx_total_bytes = parse_u64_field(fields[5], 0);
    record.tx_total_bytes = parse_u64_field(fields[6], 0);
    record.rx_rate_bps = parse_double_field(fields[7], 0.0);
    record.tx_rate_bps = parse_double_field(fields[8], 0.0);
    record.scope = fields[9];
    record.confidence = fields[10];
    record.notes = fields[11];
    if (fields.size() >= k_bandwidth_rollup_fields_v2) {
        record.rollup_granularity = fields[12].empty() ? std::string{"minute"} : fields[12];
        record.source_metadata = fields[13];
        record.privacy_redacted = parse_bool_field(fields[14], false);
    }
    return record;
}

std::string format_bandwidth_rollup_record(const netsentinel::storage::BandwidthRollupRecord& record) {
    return std::string(k_line_bandwidth_rollup) + "|" +
        escape_field(record.source_name) + "|" +
        escape_field(record.device_id) + "|" +
        escape_field(record.adapter_id) + "|" +
        escape_field(record.timestamp_utc.empty() ? timestamp_now_utc() : record.timestamp_utc) + "|" +
        std::to_string(record.rx_total_bytes) + "|" +
        std::to_string(record.tx_total_bytes) + "|" +
        std::to_string(record.rx_rate_bps) + "|" +
        std::to_string(record.tx_rate_bps) + "|" +
        escape_field(record.scope.empty() ? std::string{"local-machine"} : record.scope) + "|" +
        escape_field(record.confidence) + "|" +
        escape_field(record.notes) + "|" +
        escape_field(record.rollup_granularity.empty() ? std::string{"minute"} : record.rollup_granularity) + "|" +
        escape_field(record.source_metadata) + "|" +
        (record.privacy_redacted ? "1" : "0");
}

bool has_label_with_prefix_ci(const std::vector<std::string>& labels, const std::string& prefix) {
    const auto lower_prefix = lower_copy(prefix);
    for (const auto& label : labels) {
        if (lower_copy(label).rfind(lower_prefix, 0) == 0) {
            return true;
        }
    }
    return false;
}

bool has_any_user_label(const netsentinel::storage::DeviceInventoryRecord& record) {
    return !record.user_labels.empty();
}

std::string presence_label_for_device(const netsentinel::storage::DeviceInventoryRecord& record) {
    if (!record.user_labels.empty()) {
        return record.user_labels.front();
    }
    if (!record.hostname.empty()) {
        return record.hostname;
    }
    return record.device_id;
}

bool presence_event_matches_network(const netsentinel::storage::DeviceTimelineRecord& event, const std::string& network_id) {
    return network_id.empty() || event.network_id == network_id;
}

bool is_presence_event_type(const std::string& event_type) {
    return event_type == k_event_join || event_type == k_event_leave;
}

std::string presence_cutoff_utc(const netsentinel::storage::DevicePresenceHistoryConfig& presence_config) {
    if (!presence_config.cutoff_utc.empty()) {
        return presence_config.cutoff_utc;
    }
    if (presence_config.now_utc.empty() || presence_config.retention_days == 0) {
        return {};
    }
    std::time_t now = 0;
    if (!parse_iso_utc(presence_config.now_utc, now)) {
        return {};
    }
    const auto seconds = static_cast<std::time_t>(presence_config.retention_days * 24ULL * 60ULL * 60ULL);
    return iso_utc_from_time(now - seconds);
}

std::string normalize_workspace_token(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        const unsigned char uch = static_cast<unsigned char>(ch);
        if (std::isalnum(uch)) {
            out.push_back(static_cast<char>(std::tolower(uch)));
            continue;
        }
        if (ch == '.' || ch == '-' || ch == '_') {
            out.push_back(ch);
            continue;
        }
        if (!out.empty() && out.back() != '-') {
            out.push_back('-');
        }
    }
    while (!out.empty() && out.back() == '-') {
        out.pop_back();
    }
    return out.empty() ? std::string{"workspace"} : out;
}

std::string generated_workspace_id(const netsentinel::storage::NetworkWorkspaceRecord& record) {
    if (!record.workspace_id.empty()) {
        return normalize_workspace_token(record.workspace_id);
    }
    const auto label = !record.key.user_label.empty() ? record.key.user_label : record.key.ssid;
    const auto gateway = !record.key.gateway_mac.empty() ? record.key.gateway_mac : "gateway";
    const auto subnet = !record.key.subnet.empty() ? record.key.subnet : "subnet";
    return normalize_workspace_token(label + "-" + gateway + "-" + subnet);
}

netsentinel::storage::NetworkWorkspaceRecord parse_workspace_record(const std::vector<std::string>& fields) {
    using netsentinel::storage::NetworkWorkspaceRecord;
    NetworkWorkspaceRecord out{};
    out.workspace_id = fields[1];
    out.key.gateway_mac = fields[2];
    out.key.subnet = fields[3];
    out.key.ssid = fields[4];
    out.key.user_label = fields[5];
    out.settings.monitoring_enabled = parse_bool_field(fields[6], true);
    try {
        out.settings.monitored_network_limit = static_cast<std::size_t>(std::stoull(fields[7]));
    } catch (...) {
        out.settings.monitored_network_limit = 16;
    }
    out.settings.scan_profile = fields[8].empty() ? std::string{"standard"} : fields[8];
    out.settings.notes = fields[9];
    out.active = parse_bool_field(fields[10], false);
    out.created_utc = fields[11];
    out.updated_utc = fields[12];
    return out;
}

netsentinel::storage::WorkspaceScanHistoryRecord parse_workspace_scan_record(const std::vector<std::string>& fields) {
    using netsentinel::storage::WorkspaceScanHistoryRecord;
    WorkspaceScanHistoryRecord out{};
    out.workspace_id = fields[1];
    try {
        out.scan_id = static_cast<std::int64_t>(std::stoll(fields[2]));
    } catch (...) {
        out.scan_id = 0;
    }
    out.status = fields[3];
    out.summary = fields[4];
    out.at_utc = fields[5].empty() ? timestamp_now_utc() : fields[5];
    return out;
}

netsentinel::storage::SavedFilterTemplate parse_filter_template_record(const std::vector<std::string>& fields) {
    using netsentinel::storage::SavedFilterTemplate;
    SavedFilterTemplate out{};
    out.filter_id = fields[1];
    out.name = fields[2];
    out.query.preset = fields[3].empty() ? std::string{"all"} : fields[3];
    out.query.vendor = fields[4];
    out.query.os_guess = fields[5];
    out.query.text = fields[6];
    out.query.network_id = fields[7];
    for (const auto& port_text : split_csv_list(fields[8])) {
        try {
            out.query.risky_ports.push_back(std::stoi(port_text));
        } catch (...) {
        }
    }
    out.created_utc = fields[9];
    return out;
}

bool is_workspace_record(const std::string& line, std::vector<std::string>& parsed_fields) {
    if (line.rfind(std::string(k_line_workspace), 0) != 0 || line.rfind(std::string(k_line_workspace_scan), 0) == 0) {
        return false;
    }
    parsed_fields = split_record(line);
    return parsed_fields.size() == k_workspace_record_fields;
}

bool is_workspace_scan_record(const std::string& line, std::vector<std::string>& parsed_fields) {
    if (line.rfind(std::string(k_line_workspace_scan), 0) != 0) {
        return false;
    }
    parsed_fields = split_record(line);
    return parsed_fields.size() == k_workspace_scan_record_fields;
}

bool is_filter_template_record(const std::string& line, std::vector<std::string>& parsed_fields) {
    if (line.rfind(std::string(k_line_filter_template), 0) != 0) {
        return false;
    }
    parsed_fields = split_record(line);
    return parsed_fields.size() == k_filter_template_fields;
}

std::string format_workspace_record(const netsentinel::storage::NetworkWorkspaceRecord& record) {
    return std::string(k_line_workspace) + "|" +
        escape_field(record.workspace_id) + "|" +
        escape_field(record.key.gateway_mac) + "|" +
        escape_field(record.key.subnet) + "|" +
        escape_field(record.key.ssid) + "|" +
        escape_field(record.key.user_label) + "|" +
        (record.settings.monitoring_enabled ? "1" : "0") + "|" +
        std::to_string(record.settings.monitored_network_limit) + "|" +
        escape_field(record.settings.scan_profile.empty() ? std::string{"standard"} : record.settings.scan_profile) + "|" +
        escape_field(record.settings.notes) + "|" +
        (record.active ? "1" : "0") + "|" +
        escape_field(record.created_utc.empty() ? timestamp_now_utc() : record.created_utc) + "|" +
        escape_field(record.updated_utc.empty() ? timestamp_now_utc() : record.updated_utc);
}

std::string format_workspace_scan_record(const netsentinel::storage::WorkspaceScanHistoryRecord& record) {
    return std::string(k_line_workspace_scan) + "|" +
        escape_field(record.workspace_id) + "|" +
        std::to_string(record.scan_id) + "|" +
        escape_field(record.status) + "|" +
        escape_field(record.summary) + "|" +
        escape_field(record.at_utc.empty() ? timestamp_now_utc() : record.at_utc);
}

std::string format_filter_template_record(const netsentinel::storage::SavedFilterTemplate& filter) {
    return std::string(k_line_filter_template) + "|" +
        escape_field(filter.filter_id) + "|" +
        escape_field(filter.name) + "|" +
        escape_field(filter.query.preset.empty() ? std::string{"all"} : filter.query.preset) + "|" +
        escape_field(filter.query.vendor) + "|" +
        escape_field(filter.query.os_guess) + "|" +
        escape_field(filter.query.text) + "|" +
        escape_field(filter.query.network_id) + "|" +
        escape_field(join_csv_list(ports_to_strings(filter.query.risky_ports))) + "|" +
        escape_field(filter.created_utc.empty() ? timestamp_now_utc() : filter.created_utc);
}

std::vector<netsentinel::storage::DeviceInventoryRecord> list_inventory_records_internal(const std::vector<std::string>& lines) {
    std::vector<netsentinel::storage::DeviceInventoryRecord> out;
    std::vector<std::string> fields;
    for (const auto& line : lines) {
        if (!is_inventory_record(line, fields)) {
            continue;
        }
        out.push_back(parse_inventory_record(fields));
    }
    return out;
}

std::vector<netsentinel::storage::DeviceTimelineRecord> list_timeline_records_internal(const std::vector<std::string>& lines) {
    std::vector<netsentinel::storage::DeviceTimelineRecord> out;
    std::vector<std::string> fields;
    for (const auto& line : lines) {
        if (!is_timeline_record(line, fields)) {
            continue;
        }
        out.push_back(parse_timeline_record(fields));
    }
    return out;
}

std::vector<netsentinel::storage::BandwidthRollupRecord> list_bandwidth_rollup_records_internal(const std::vector<std::string>& lines) {
    std::vector<netsentinel::storage::BandwidthRollupRecord> out;
    std::vector<std::string> fields;
    for (const auto& line : lines) {
        if (!is_bandwidth_rollup_record(line, fields)) {
            continue;
        }
        out.push_back(parse_bandwidth_rollup_record(fields));
    }
    return out;
}

std::vector<netsentinel::storage::NetworkWorkspaceRecord> list_workspace_records_internal(const std::vector<std::string>& lines) {
    std::vector<netsentinel::storage::NetworkWorkspaceRecord> out;
    std::vector<std::string> fields;
    for (const auto& line : lines) {
        if (!is_workspace_record(line, fields)) {
            continue;
        }
        out.push_back(parse_workspace_record(fields));
    }
    return out;
}

std::vector<netsentinel::storage::WorkspaceScanHistoryRecord> list_workspace_scan_records_internal(const std::vector<std::string>& lines) {
    std::vector<netsentinel::storage::WorkspaceScanHistoryRecord> out;
    std::vector<std::string> fields;
    for (const auto& line : lines) {
        if (!is_workspace_scan_record(line, fields)) {
            continue;
        }
        out.push_back(parse_workspace_scan_record(fields));
    }
    return out;
}

std::vector<netsentinel::storage::SavedFilterTemplate> list_filter_template_records_internal(const std::vector<std::string>& lines) {
    std::vector<netsentinel::storage::SavedFilterTemplate> out;
    std::vector<std::string> fields;
    for (const auto& line : lines) {
        if (!is_filter_template_record(line, fields)) {
            continue;
        }
        out.push_back(parse_filter_template_record(fields));
    }
    return out;
}

std::vector<std::string> replace_inventory_line(
    const std::vector<std::string>& lines,
    const netsentinel::storage::DeviceInventoryRecord& replacement
) {
    std::vector<std::string> out;
    out.reserve(lines.size() + 1);

    const std::string serialized = format_inventory_record(replacement);
    bool replaced = false;
    std::vector<std::string> fields;

    for (const auto& line : lines) {
        if (!is_inventory_record(line, fields) || fields[1] != replacement.device_id) {
            out.push_back(line);
            continue;
        }
        out.push_back(serialized);
        replaced = true;
    }

    if (!replaced) {
        out.push_back(serialized);
    }
    return out;
}

void append_event_if_changed(
    std::vector<netsentinel::storage::DeviceTimelineRecord>& out,
    const std::string& network_id,
    const std::string& device_id,
    const std::string& event_type,
    const std::string& source,
    int severity,
    const std::string& old_value,
    const std::string& new_value
) {
    if (old_value == new_value) {
        return;
    }
    netsentinel::storage::DeviceTimelineRecord event{
        .device_id = device_id,
        .network_id = network_id,
        .event_type = event_type,
        .source = source.empty() ? "manual" : source,
        .severity = std::max(0, severity),
        .old_value = old_value,
        .new_value = new_value
    };
    out.push_back(std::move(event));
}

std::int64_t next_session_id(const std::vector<ScanSessionLine>& scans) {
    std::int64_t out = 0;
    for (const auto& scan : scans) {
        if (scan.id >= out) {
            out = scan.id + 1;
        }
    }
    return out;
}

std::string timestamp_hours_ago_utc(int hours) {
    const auto now = std::chrono::system_clock::now();
    const auto cutoff = now - std::chrono::hours(hours);
    const auto seconds = std::chrono::system_clock::to_time_t(cutoff);
    std::tm tm_snapshot{};
#ifdef _WIN32
    gmtime_s(&tm_snapshot, &seconds);
#else
    gmtime_r(&seconds, &tm_snapshot);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm_snapshot);
    return std::string(buffer);
}

std::string device_search_blob(const netsentinel::storage::DeviceInventoryRecord& device) {
    return device.device_id + " " +
        device.hostname + " " +
        join_csv_list(device.ip_addresses) + " " +
        device.mac_address + " " +
        device.vendor_hint + " " +
        device.device_type + " " +
        join_csv_list(device.user_labels) + " " +
        device.details;
}

std::vector<int> default_risky_ports() {
    return {21, 23, 3389, 554, 8554, 37777, 7547};
}

bool device_has_any_port(const netsentinel::storage::DeviceInventoryRecord& device, const std::vector<int>& ports) {
    for (const auto port : device.open_tcp_ports) {
        if (std::find(ports.begin(), ports.end(), port) != ports.end()) {
            return true;
        }
    }
    return false;
}

std::unordered_map<std::string, std::string> latest_network_by_device(const std::vector<netsentinel::storage::DeviceTimelineRecord>& timeline) {
    std::unordered_map<std::string, std::string> out;
    for (const auto& event : timeline) {
        if (!event.device_id.empty() && !event.network_id.empty()) {
            out[event.device_id] = event.network_id;
        }
    }
    return out;
}

std::unordered_set<std::string> devices_with_security_findings(const std::vector<netsentinel::storage::DeviceTimelineRecord>& timeline) {
    std::unordered_set<std::string> out;
    for (const auto& event : timeline) {
        if (!event.device_id.empty() && contains_any_ci(event.event_type + " " + event.source + " " + event.new_value, {"security", "risk", "cve", "vulnerable", "insecure"})) {
            out.insert(event.device_id);
        }
    }
    return out;
}

void add_match_reason(std::vector<std::string>& reasons, const std::string& reason) {
    if (std::find(reasons.begin(), reasons.end(), reason) == reasons.end()) {
        reasons.push_back(reason);
    }
}

bool match_device_search_preset(
    const netsentinel::storage::DeviceInventoryRecord& device,
    const std::string& network_id,
    const std::unordered_set<std::string>& security_devices,
    const netsentinel::storage::DeviceSearchQuery& query,
    std::vector<std::string>& reasons
) {
    const auto preset = lower_copy(query.preset.empty() ? std::string{"all"} : query.preset);
    const auto blob = device_search_blob(device);
    if (preset == "all") {
        add_match_reason(reasons, "all-devices");
        return true;
    }
    if (preset == "unknown") {
        const bool matched = device.device_type.empty() ||
            contains_any_ci(device.device_type, {"unknown", "generic"}) ||
            (device.vendor_hint.empty() && device.hostname.empty());
        if (matched) {
            add_match_reason(reasons, "unknown-device");
        }
        return matched;
    }
    if (preset == "new-24h") {
        const auto cutoff = timestamp_hours_ago_utc(24);
        const bool matched = !device.last_seen_utc.empty() && device.last_seen_utc >= cutoff;
        if (matched) {
            add_match_reason(reasons, "new-in-last-24h");
        }
        return matched;
    }
    if (preset == "cameras" || preset == "camera") {
        const bool matched = contains_any_ci(blob, {"camera", "rtsp", "onvif", "hikvision", "dahua"}) ||
            device_has_any_port(device, {554, 8554, 37777});
        if (matched) {
            add_match_reason(reasons, "camera-hint");
        }
        return matched;
    }
    if (preset == "routers" || preset == "router") {
        const bool matched = contains_any_ci(blob, {"router", "gateway", "openwrt", "fritz", "asuswrt"}) ||
            device_has_any_port(device, {1900, 5351, 7547});
        if (matched) {
            add_match_reason(reasons, "router-hint");
        }
        return matched;
    }
    if (preset == "iot") {
        const bool matched = contains_any_ci(blob, {"iot", "smart", "bulb", "thermostat", "plug", "camera", "speaker", "sensor"});
        if (matched) {
            add_match_reason(reasons, "iot-hint");
        }
        return matched;
    }
    if (preset == "risky-ports" || preset == "open-risky-ports") {
        const auto ports = query.risky_ports.empty() ? default_risky_ports() : query.risky_ports;
        const bool matched = device_has_any_port(device, ports);
        if (matched) {
            add_match_reason(reasons, "open-risky-port");
        }
        return matched;
    }
    if (preset == "offline-important") {
        const bool matched = device.importance >= 70 &&
            (device.stale || contains_any_ci(device.details, {"offline", "down", "stale", "unreachable"}));
        if (matched) {
            add_match_reason(reasons, "offline-important");
        }
        return matched;
    }
    if (preset == "security-findings") {
        const bool matched = security_devices.find(device.device_id) != security_devices.end() ||
            contains_any_ci(blob, {"security", "risk", "cve", "vulnerable", "insecure"});
        if (matched) {
            add_match_reason(reasons, "security-finding");
        }
        return matched;
    }
    if (preset == "network") {
        const bool matched = query.network_id.empty() || network_id == query.network_id;
        if (matched) {
            add_match_reason(reasons, "network-match");
        }
        return matched;
    }
    return false;
}

} // namespace

namespace netsentinel::storage {

Result<std::size_t> current_schema_version(const StorageConfig& config) {
    const auto lines = read_lines(config.database_path);
    const auto version = parse_schema_version(lines);
    return Result<std::size_t>::ok(version);
}

Result<std::size_t> migrate_schema(const StorageConfig& config) {
    auto lines = read_lines(config.database_path);
    const auto current = parse_schema_version(lines);
    if (current == 0) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::internal,
            "storage schema migration failed",
            "invalid schema header in storage file"
        );
    }

    auto out = ensure_header(lines);
    auto effective = parse_schema_version(out);
    while (effective < config.target_schema_version && effective < k_latest_schema_version) {
        ++effective;
        if (out.empty() || out[0].rfind(k_schema_version_prefix, 0) != 0) {
            out.insert(out.begin(), std::string(k_schema_version_prefix) + std::to_string(effective));
        } else {
            out[0] = std::string(k_schema_version_prefix) + std::to_string(effective);
        }
    }
    write_lines(config.database_path, out);
    return Result<std::size_t>::ok(effective);
}

Result<std::int64_t> save_scan_session(
    const netsentinel::engine::ScanProfile& profile,
    const netsentinel::engine::ScanSession& session,
    const StorageConfig& config
) {
    if (config.target_schema_version < k_min_schema_version || config.target_schema_version > k_latest_schema_version) {
        return Result<std::int64_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "invalid storage schema target",
            "storage target version is outside supported window"
        );
    }

    auto lines = read_lines(config.database_path);
        lines = ensure_header(read_lines(config.database_path));

    const std::size_t old_schema = parse_schema_version(lines);
    if (old_schema > config.target_schema_version) {
        return Result<std::int64_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "unsupported storage downgrade",
            "storage data was created with a newer schema"
        );
    }

    if (old_schema < config.target_schema_version) {
        auto migration = migrate_schema(config);
        if (!migration) {
            return Result<std::int64_t>::fail(migration.error().code, migration.error().context, migration.error().details);
        }
        lines = read_lines(config.database_path);
    }

    const auto entries = list_scan_lines(lines);
    const auto id = next_session_id(entries);

    const auto profile_json = profile.to_json();
    const auto session_json = session.to_json();

    lines.push_back(
        std::string(k_line_scan_session) + "|" +
        std::to_string(id) + "|" +
        escape_field(profile_json) + "|" +
        escape_field(session_json)
    );
    lines.push_back(
        std::string(k_line_network) + "|" +
        std::to_string(id) + "|" +
        escape_field(profile.scope.cidr_or_range)
    );
    lines.push_back(
        std::string(k_line_adapter) + "|" +
        std::to_string(id) + "|" +
        escape_field(session.profile_name)
    );
    lines.push_back(
        std::string(k_line_device) + "|" +
        std::to_string(id) + "|" +
        escape_field(std::to_string(session.probe_results.size()))
    );

    for (std::size_t i = 0; i < session.probe_results.size(); ++i) {
        const auto& probe = session.probe_results[i];
        lines.push_back(
            std::string(k_line_probe) + "|" +
            std::to_string(id) + "|" +
            std::to_string(i) + "|" +
            escape_field(probe.probe_name) + "|" +
            escape_field(probe.target) + "|" +
            (probe.success ? "1" : "0") + "|" +
            std::to_string(probe.response_time_ms) + "|" +
            escape_field(probe.message) + "|" +
            escape_field(probe.error_code)
        );
    }

    lines.push_back(
        std::string(k_line_event) + "|" +
        std::to_string(id) + "|" +
        "scan-session-saved"
    );

    write_lines(config.database_path, lines);

    return Result<std::int64_t>::ok(id);
}

Result<netsentinel::engine::ScanSession> load_scan_session(std::int64_t session_id, const StorageConfig& config) {
    auto lines = read_lines(config.database_path);
    const auto entries = list_scan_lines(lines);
    for (const auto& entry : entries) {
        if (entry.id != session_id) {
            continue;
        }
        try {
            return Result<netsentinel::engine::ScanSession>::ok(netsentinel::engine::ScanSession::from_json(entry.session_json));
        } catch (const std::exception& ex) {
            return Result<netsentinel::engine::ScanSession>::fail(
                netsentinel::engine::ErrorCode::internal,
                "scan session parse failed",
                ex.what()
            );
        }
    }

    return Result<netsentinel::engine::ScanSession>::fail(
        netsentinel::engine::ErrorCode::invalid_input,
        "scan session not found",
        "no stored session with the requested id"
    );
}

Result<std::string> export_scan_session_json(std::int64_t session_id, const StorageConfig& config) {
    const auto session = load_scan_session(session_id, config);
    if (!session) {
        return Result<std::string>::fail(
            session.error().code,
            session.error().context,
            session.error().details
        );
    }
    return Result<std::string>::ok(session.value().to_json());
}

Result<std::vector<netsentinel::storage::DeviceInventoryRecord>> list_inventory_records(
    const StorageConfig& config,
    bool include_hidden
) {
    auto lines = read_lines(config.database_path);
    const auto records = list_inventory_records_internal(lines);
    if (include_hidden) {
        return Result<std::vector<DeviceInventoryRecord>>::ok(records);
    }
    std::vector<DeviceInventoryRecord> out;
    for (const auto& record : records) {
        if (!record.hidden) {
            out.push_back(record);
        }
    }
    return Result<std::vector<DeviceInventoryRecord>>::ok(std::move(out));
}

Result<DeviceInventoryRecord> get_inventory_record(
    const std::string& device_id,
    const StorageConfig& config
) {
    const auto records = list_inventory_records(config, true);
    if (!records) {
        return Result<DeviceInventoryRecord>::fail(records.error().code, records.error().context, records.error().details);
    }
    for (const auto& record : records.value()) {
        if (record.device_id == device_id) {
            return Result<DeviceInventoryRecord>::ok(record);
        }
    }
    return Result<DeviceInventoryRecord>::fail(
        netsentinel::engine::ErrorCode::invalid_input,
        "device inventory missing",
        "no inventory device with id: " + device_id
    );
}

Result<std::size_t> upsert_inventory_record(
    const DeviceInventoryRecord& record,
    const StorageConfig& config
) {
    if (record.device_id.empty()) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "device inventory save blocked",
            "device id must be non-empty"
        );
    }
    if (record.importance < k_min_importance || record.importance > k_max_importance) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "invalid importance value",
            "importance must be between 0 and 100"
        );
    }

    auto lines = read_lines(config.database_path);
    if (lines.empty()) {
        lines = ensure_header(lines);
    }
    append_inventory_headers(lines);

    lines = replace_inventory_line(lines, record);
    write_lines(config.database_path, lines);

    return Result<std::size_t>::ok(1);
}

Result<std::size_t> patch_inventory_record(
    const std::string& device_id,
    const DeviceInventoryPatch& patch,
    const StorageConfig& config
) {
    if (device_id.empty()) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "device inventory patch blocked",
            "device id must be non-empty"
        );
    }

    const auto existing_result = get_inventory_record(device_id, config);
    if (!existing_result) {
        return Result<std::size_t>::fail(
            existing_result.error().code,
            existing_result.error().context,
            existing_result.error().details
        );
    }

    auto record = existing_result.value();
    if (patch.device_type) {
        record.device_type = *patch.device_type;
    }
    if (patch.user_labels) {
        record.user_labels = *patch.user_labels;
    }
    if (patch.importance) {
        record.importance = *patch.importance;
    }
    if (patch.hidden) {
        record.hidden = *patch.hidden;
    }
    if (patch.stale) {
        record.stale = *patch.stale;
    }

    if (record.importance < k_min_importance || record.importance > k_max_importance) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "invalid importance value",
            "importance must be between 0 and 100"
        );
    }
    record.last_seen_utc = timestamp_now_utc();

    const auto upserted = upsert_inventory_record(record, config);
    if (!upserted) {
        return Result<std::size_t>::fail(upserted.error().code, upserted.error().context, upserted.error().details);
    }
    return Result<std::size_t>::ok(1);
}

Result<std::size_t> hide_stale_inventory_records(const StorageConfig& config) {
    auto lines = read_lines(config.database_path);
    if (lines.empty()) {
        return Result<std::size_t>::ok(0);
    }
    append_inventory_headers(lines);

    std::vector<std::string> fields;
    std::size_t changed = 0;
    std::vector<std::string> out;
    out.reserve(lines.size());

    for (const auto& line : lines) {
        if (!is_inventory_record(line, fields)) {
            out.push_back(line);
            continue;
        }
        auto record = parse_inventory_record(fields);
        if (record.stale && !record.hidden) {
            record.hidden = true;
            out.push_back(format_inventory_record(record));
            ++changed;
            continue;
        }
        out.push_back(line);
    }

    write_lines(config.database_path, out);
    return Result<std::size_t>::ok(changed);
}

Result<std::string> export_inventory_records_json(const StorageConfig& config) {
    const auto records = list_inventory_records(config, true);
    if (!records) {
        return Result<std::string>::fail(records.error().code, records.error().context, records.error().details);
    }

    std::string out = "[";
    for (std::size_t i = 0; i < records.value().size(); ++i) {
        const auto& record = records.value()[i];
        if (i > 0) {
            out.push_back(',');
        }
        out += "{";
        out += "\"device_id\":\"" + json_escape(record.device_id) + "\",";
        out += "\"hostname\":\"" + json_escape(record.hostname) + "\",";
        out += "\"ip_addresses\":" + json_list(record.ip_addresses) + ",";
        out += "\"mac_address\":\"" + json_escape(record.mac_address) + "\",";
        out += "\"vendor_hint\":\"" + json_escape(record.vendor_hint) + "\",";
        out += "\"device_type\":\"" + json_escape(record.device_type) + "\",";
        out += "\"user_labels\":" + json_list(record.user_labels) + ",";
        out += "\"importance\":" + std::to_string(record.importance) + ",";
        out += "\"hidden\":" + std::string(record.hidden ? "true" : "false") + ",";
        out += "\"stale\":" + std::string(record.stale ? "true" : "false") + ",";
        out += "\"details\":\"" + json_escape(record.details) + "\",";
        out += "\"last_seen_utc\":\"" + json_escape(record.last_seen_utc) + "\"";
        out += "}";
    }
    out += "]";
    return Result<std::string>::ok(std::move(out));
}

Result<std::size_t> append_timeline_record(const DeviceTimelineRecord& record, const StorageConfig& config) {
    auto lines = read_lines(config.database_path);
    if (lines.empty()) {
        lines = ensure_header(lines);
    }
    lines.push_back(format_timeline_record(record));
    write_lines(config.database_path, lines);
    return Result<std::size_t>::ok(1);
}

Result<std::vector<DeviceTimelineRecord>> list_timeline_records(
    const StorageConfig& config,
    const TimelineFilter& filter
) {
    auto lines = read_lines(config.database_path);
    const auto records = list_timeline_records_internal(lines);
    std::vector<DeviceTimelineRecord> out;

    for (const auto& record : records) {
        if (filter.network_id && record.network_id != *filter.network_id) {
            continue;
        }
        if (filter.device_id && record.device_id != *filter.device_id) {
            continue;
        }
        if (filter.event_type && record.event_type != *filter.event_type) {
            continue;
        }
        if (filter.from_utc && !filter.from_utc->empty() && !record.at_utc.empty() && record.at_utc < *filter.from_utc) {
            continue;
        }
        if (filter.to_utc && !filter.to_utc->empty() && !record.at_utc.empty() && record.at_utc > *filter.to_utc) {
            continue;
        }
        out.push_back(record);
    }
    return Result<std::vector<DeviceTimelineRecord>>::ok(std::move(out));
}

Result<std::size_t> append_bandwidth_rollup(
    const BandwidthRollupRecord& record,
    const StorageConfig& config
) {
    if (record.source_name.empty()) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "bandwidth rollup append blocked",
            "source name is required"
        );
    }
    if (record.device_id.empty()) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "bandwidth rollup append blocked",
            "device id is required"
        );
    }
    auto lines = ensure_header(read_lines(config.database_path));
    lines.push_back(format_bandwidth_rollup_record(record));
    write_lines(config.database_path, lines);
    return Result<std::size_t>::ok(1);
}

Result<std::size_t> append_bandwidth_rollup_with_privacy(
    const BandwidthRollupRecord& record,
    const BandwidthPrivacySettings& privacy,
    const StorageConfig& config
) {
    auto sanitized = record;
    if (privacy.redact_device_identifiers) {
        sanitized.device_id = sanitized.device_id.empty() ? std::string{"redacted-device"} : std::string{"redacted-device"};
        sanitized.adapter_id = sanitized.adapter_id.empty() ? std::string{"redacted-adapter"} : std::string{"redacted-adapter"};
        sanitized.privacy_redacted = true;
        sanitized.notes = sanitized.notes.empty()
            ? "Device identifiers redacted by bandwidth privacy settings."
            : sanitized.notes + " Device identifiers redacted by bandwidth privacy settings.";
    }
    if (!privacy.store_source_metadata) {
        sanitized.source_metadata.clear();
    }
    return append_bandwidth_rollup(sanitized, config);
}

Result<std::vector<BandwidthRollupRecord>> list_bandwidth_rollups(
    const StorageConfig& config,
    const BandwidthRollupFilter& filter
) {
    const auto records = list_bandwidth_rollup_records_internal(read_lines(config.database_path));
    std::vector<BandwidthRollupRecord> out;
    for (const auto& record : records) {
        if (filter.source_name && record.source_name != *filter.source_name) {
            continue;
        }
        if (filter.device_id && record.device_id != *filter.device_id) {
            continue;
        }
        if (filter.rollup_granularity && record.rollup_granularity != *filter.rollup_granularity) {
            continue;
        }
        if (filter.from_utc && !filter.from_utc->empty() && !record.timestamp_utc.empty() && record.timestamp_utc < *filter.from_utc) {
            continue;
        }
        if (filter.to_utc && !filter.to_utc->empty() && !record.timestamp_utc.empty() && record.timestamp_utc > *filter.to_utc) {
            continue;
        }
        out.push_back(record);
    }
    return Result<std::vector<BandwidthRollupRecord>>::ok(std::move(out));
}

Result<BandwidthRetentionResult> apply_bandwidth_retention(
    const BandwidthRetentionPolicy& policy,
    const StorageConfig& config
) {
    if (policy.rollup_granularity.empty()) {
        return Result<BandwidthRetentionResult>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "bandwidth retention blocked",
            "rollup granularity is required"
        );
    }
    if (policy.cutoff_utc.empty()) {
        BandwidthRetentionResult result{};
        const auto records = list_bandwidth_rollup_records_internal(read_lines(config.database_path));
        result.before_count = records.size();
        result.after_count = records.size();
        result.removed_count = 0;
        result.message = "Retention policy has no cutoff; no records removed.";
        return Result<BandwidthRetentionResult>::ok(result);
    }

    auto lines = ensure_header(read_lines(config.database_path));
    const auto before = list_bandwidth_rollup_records_internal(lines).size();
    std::vector<std::string> out;
    out.reserve(lines.size());
    std::vector<std::string> fields;
    for (const auto& line : lines) {
        if (!is_bandwidth_rollup_record(line, fields)) {
            out.push_back(line);
            continue;
        }
        const auto record = parse_bandwidth_rollup_record(fields);
        if (record.rollup_granularity == policy.rollup_granularity &&
            !record.timestamp_utc.empty() &&
            record.timestamp_utc < policy.cutoff_utc) {
            continue;
        }
        out.push_back(line);
    }
    write_lines(config.database_path, out);
    const auto after = list_bandwidth_rollup_records_internal(out).size();
    BandwidthRetentionResult result{};
    result.before_count = before;
    result.after_count = after;
    result.removed_count = before >= after ? before - after : 0;
    result.message = "Bandwidth retention applied for " + policy.rollup_granularity + " rollups.";
    return Result<BandwidthRetentionResult>::ok(result);
}

Result<std::vector<DeviceTimelineRecord>> generate_timeline_events(
    const std::vector<DeviceInventoryRecord>& previous_snapshot,
    const std::vector<DeviceInventoryRecord>& current_snapshot,
    const std::string& network_id,
    const std::string& source
) {
    if (network_id.empty()) {
        return Result<std::vector<DeviceTimelineRecord>>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "timeline event generation blocked",
            "network id must be non-empty"
        );
    }

    std::unordered_map<std::string, const DeviceInventoryRecord*> prev_by_id;
    prev_by_id.reserve(previous_snapshot.size() + 1);
    for (const auto& record : previous_snapshot) {
        prev_by_id[record.device_id] = &record;
    }

    std::vector<DeviceTimelineRecord> out;
    std::unordered_set<std::string> seen_ids;
    seen_ids.reserve(current_snapshot.size() + 1);

    for (const auto& current : current_snapshot) {
        if (current.device_id.empty()) {
            return Result<std::vector<DeviceTimelineRecord>>::fail(
                netsentinel::engine::ErrorCode::invalid_input,
                "timeline event generation blocked",
                "current snapshot contains an empty device id"
            );
        }
        seen_ids.insert(current.device_id);
        const auto previous_iter = prev_by_id.find(current.device_id);
        if (previous_iter == prev_by_id.end()) {
            out.push_back({
                .device_id = current.device_id,
                .network_id = network_id,
                .event_type = k_event_join,
                .source = source.empty() ? "manual" : source,
                .severity = k_severity_join,
                .old_value = "",
                .new_value = current.hostname,
                .at_utc = timestamp_now_utc()
            });
            continue;
        }
        const auto& previous = *previous_iter->second;
        const auto previous_hostname = previous.hostname;
        if (previous_hostname != current.hostname) {
            append_event_if_changed(out, network_id, current.device_id, k_event_name_change, source, k_severity_name_change, previous_hostname, current.hostname);
        }

        const auto previous_vendor = previous.vendor_hint;
        if (previous_vendor != current.vendor_hint) {
            append_event_if_changed(out, network_id, current.device_id, k_event_vendor_change, source, k_severity_vendor_change, previous_vendor, current.vendor_hint);
        }

        const auto previous_ips = join_csv_list_sorted(previous.ip_addresses);
        const auto current_ips = join_csv_list_sorted(current.ip_addresses);
        append_event_if_changed(out, network_id, current.device_id, k_event_ip_change, source, k_severity_ip_change, previous_ips, current_ips);

        const auto previous_ports = join_csv_list_sorted(ports_to_strings(previous.open_tcp_ports));
        const auto current_ports = join_csv_list_sorted(ports_to_strings(current.open_tcp_ports));
        append_event_if_changed(out, network_id, current.device_id, k_event_open_port_change, source, k_severity_open_port_change, previous_ports, current_ports);
    }

    for (const auto& previous : previous_snapshot) {
        if (previous.device_id.empty()) {
            return Result<std::vector<DeviceTimelineRecord>>::fail(
                netsentinel::engine::ErrorCode::invalid_input,
                "timeline event generation blocked",
                "previous snapshot contains an empty device id"
            );
        }
        if (seen_ids.find(previous.device_id) == seen_ids.end()) {
            out.push_back({
                .device_id = previous.device_id,
                .network_id = network_id,
                .event_type = k_event_leave,
                .source = source.empty() ? "manual" : source,
                .severity = k_severity_leave,
                .old_value = previous.hostname,
                .new_value = "",
                .at_utc = timestamp_now_utc()
            });
        }
    }

    return Result<std::vector<DeviceTimelineRecord>>::ok(std::move(out));
}

Result<std::vector<DevicePresenceRecord>> build_device_presence_history(
    const DevicePresenceHistoryConfig& presence_config,
    const StorageConfig& config
) {
    const auto lines = read_lines(config.database_path);
    const auto inventory = list_inventory_records_internal(lines);
    const auto timeline = list_timeline_records_internal(lines);

    std::unordered_map<std::string, DeviceInventoryRecord> inventory_by_id;
    for (const auto& device : inventory) {
        inventory_by_id[device.device_id] = device;
    }

    struct PresenceAccumulator {
        DevicePresenceRecord record{};
        std::optional<std::string> open_join_utc{};
    };

    std::vector<DeviceTimelineRecord> events;
    for (const auto& event : timeline) {
        if (!is_presence_event_type(event.event_type) || !presence_event_matches_network(event, presence_config.network_id)) {
            continue;
        }
        events.push_back(event);
    }
    std::sort(
        events.begin(),
        events.end(),
        [](const DeviceTimelineRecord& lhs, const DeviceTimelineRecord& rhs) {
            return lhs.at_utc < rhs.at_utc;
        }
    );

    std::unordered_map<std::string, PresenceAccumulator> by_device;
    for (const auto& event : events) {
        const auto inventory_iter = inventory_by_id.find(event.device_id);
        const bool has_inventory = inventory_iter != inventory_by_id.end();
        if (!presence_config.include_unlabeled_devices && (!has_inventory || !has_any_user_label(inventory_iter->second))) {
            continue;
        }

        auto& accumulator = by_device[event.device_id];
        if (accumulator.record.device_id.empty()) {
            accumulator.record.device_id = event.device_id;
            accumulator.record.network_id = event.network_id;
            if (has_inventory) {
                accumulator.record.device_label = presence_label_for_device(inventory_iter->second);
                accumulator.record.user_assigned_person =
                    has_label_with_prefix_ci(inventory_iter->second.user_labels, "person:") ||
                    has_label_with_prefix_ci(inventory_iter->second.user_labels, "member:");
            } else {
                accumulator.record.device_label = event.device_id;
                accumulator.record.user_assigned_person = false;
            }
            accumulator.record.privacy_notice = accumulator.record.user_assigned_person
                ? "Device is associated with a user-assigned household member label."
                : "Presence is device-based only; NetSentinel does not infer a person from this device.";
        }

        if (accumulator.record.first_seen_utc.empty() || event.at_utc < accumulator.record.first_seen_utc) {
            accumulator.record.first_seen_utc = event.at_utc;
        }
        if (accumulator.record.last_seen_utc.empty() || event.at_utc > accumulator.record.last_seen_utc) {
            accumulator.record.last_seen_utc = event.at_utc;
        }

        if (event.event_type == k_event_join) {
            accumulator.open_join_utc = event.at_utc;
            accumulator.record.currently_present = true;
            continue;
        }
        if (event.event_type == k_event_leave) {
            if (accumulator.open_join_utc.has_value()) {
                accumulator.record.dwell_seconds += seconds_between_utc(accumulator.open_join_utc.value(), event.at_utc);
                accumulator.open_join_utc.reset();
            }
            accumulator.record.currently_present = false;
        }
    }

    if (!presence_config.now_utc.empty()) {
        for (auto& item : by_device) {
            auto& accumulator = item.second;
            if (accumulator.open_join_utc.has_value()) {
                accumulator.record.dwell_seconds += seconds_between_utc(accumulator.open_join_utc.value(), presence_config.now_utc);
            }
        }
    }

    std::vector<DevicePresenceRecord> out;
    out.reserve(by_device.size());
    for (auto& item : by_device) {
        out.push_back(std::move(item.second.record));
    }
    std::sort(
        out.begin(),
        out.end(),
        [](const DevicePresenceRecord& lhs, const DevicePresenceRecord& rhs) {
            if (lhs.last_seen_utc != rhs.last_seen_utc) {
                return lhs.last_seen_utc > rhs.last_seen_utc;
            }
            return lhs.device_id < rhs.device_id;
        }
    );
    return Result<std::vector<DevicePresenceRecord>>::ok(std::move(out));
}

Result<DevicePresenceRetentionResult> apply_device_presence_retention(
    const DevicePresenceHistoryConfig& presence_config,
    const StorageConfig& config
) {
    const auto cutoff = presence_cutoff_utc(presence_config);
    DevicePresenceRetentionResult result{};
    result.cutoff_utc = cutoff;
    if (cutoff.empty()) {
        result.message = "Presence retention has no cutoff; no records removed.";
        return Result<DevicePresenceRetentionResult>::ok(result);
    }

    auto lines = ensure_header(read_lines(config.database_path));
    std::vector<std::string> out;
    out.reserve(lines.size());
    std::vector<std::string> fields;
    for (const auto& line : lines) {
        if (!is_timeline_record(line, fields)) {
            out.push_back(line);
            continue;
        }
        const auto event = parse_timeline_record(fields);
        if (!is_presence_event_type(event.event_type) || !presence_event_matches_network(event, presence_config.network_id)) {
            out.push_back(line);
            continue;
        }
        ++result.before_count;
        if (!event.at_utc.empty() && event.at_utc < cutoff) {
            continue;
        }
        ++result.after_count;
        out.push_back(line);
    }
    result.removed_count = result.before_count >= result.after_count ? result.before_count - result.after_count : 0;
    result.message = "Presence retention applied to join/leave device events only.";
    write_lines(config.database_path, out);
    return Result<DevicePresenceRetentionResult>::ok(result);
}

Result<NetworkWorkspaceRecord> upsert_network_workspace(
    const NetworkWorkspaceRecord& workspace,
    const StorageConfig& config
) {
    NetworkWorkspaceRecord normalized = workspace;
    normalized.workspace_id = generated_workspace_id(normalized);
    if (normalized.key.gateway_mac.empty() && normalized.key.subnet.empty() && normalized.key.ssid.empty() && normalized.key.user_label.empty()) {
        return Result<NetworkWorkspaceRecord>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "workspace save blocked",
            "gateway MAC, subnet, SSID, or user label must be provided"
        );
    }
    if (normalized.settings.monitored_network_limit == 0) {
        normalized.settings.monitored_network_limit = config.monitored_network_limit == 0 ? 16 : config.monitored_network_limit;
    }
    if (normalized.settings.scan_profile.empty()) {
        normalized.settings.scan_profile = "standard";
    }

    auto lines = read_lines(config.database_path);
    if (lines.empty()) {
        lines = ensure_header(lines);
    }

    const auto existing = list_workspace_records_internal(lines);
    const bool replacing = std::any_of(
        existing.begin(),
        existing.end(),
        [&](const NetworkWorkspaceRecord& record) {
            return record.workspace_id == normalized.workspace_id;
        }
    );
    const std::size_t effective_limit = config.monitored_network_limit == 0 ? normalized.settings.monitored_network_limit : config.monitored_network_limit;
    if (!replacing && effective_limit > 0 && existing.size() >= effective_limit) {
        return Result<NetworkWorkspaceRecord>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "workspace limit reached",
            "open-source monitored network limit reached; adjust StorageConfig::monitored_network_limit or reuse an existing workspace"
        );
    }

    const auto now = timestamp_now_utc();
    if (normalized.created_utc.empty()) {
        auto found = std::find_if(
            existing.begin(),
            existing.end(),
            [&](const NetworkWorkspaceRecord& record) {
                return record.workspace_id == normalized.workspace_id;
            }
        );
        normalized.created_utc = found == existing.end() ? now : found->created_utc;
    }
    normalized.updated_utc = now;

    std::vector<std::string> out;
    out.reserve(lines.size() + 1);
    std::vector<std::string> fields;
    bool wrote = false;
    for (const auto& line : lines) {
        if (!is_workspace_record(line, fields)) {
            out.push_back(line);
            continue;
        }
        auto current = parse_workspace_record(fields);
        if (current.workspace_id == normalized.workspace_id) {
            out.push_back(format_workspace_record(normalized));
            wrote = true;
        } else {
            out.push_back(line);
        }
    }
    if (!wrote) {
        out.push_back(format_workspace_record(normalized));
    }
    write_lines(config.database_path, out);
    return Result<NetworkWorkspaceRecord>::ok(normalized);
}

Result<std::vector<NetworkWorkspaceRecord>> list_network_workspaces(const StorageConfig& config) {
    auto records = list_workspace_records_internal(read_lines(config.database_path));
    std::sort(
        records.begin(),
        records.end(),
        [](const NetworkWorkspaceRecord& lhs, const NetworkWorkspaceRecord& rhs) {
            if (lhs.active != rhs.active) {
                return lhs.active > rhs.active;
            }
            return lhs.workspace_id < rhs.workspace_id;
        }
    );
    return Result<std::vector<NetworkWorkspaceRecord>>::ok(std::move(records));
}

Result<NetworkWorkspaceRecord> switch_active_network_workspace(
    const std::string& workspace_id,
    const StorageConfig& config
) {
    if (workspace_id.empty()) {
        return Result<NetworkWorkspaceRecord>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "workspace switch blocked",
            "workspace id must be non-empty"
        );
    }

    auto lines = read_lines(config.database_path);
    if (lines.empty()) {
        return Result<NetworkWorkspaceRecord>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "workspace switch blocked",
            "no workspaces are stored"
        );
    }

    const auto now = timestamp_now_utc();
    std::vector<std::string> out;
    out.reserve(lines.size());
    std::vector<std::string> fields;
    bool found = false;
    NetworkWorkspaceRecord active{};
    for (const auto& line : lines) {
        if (!is_workspace_record(line, fields)) {
            out.push_back(line);
            continue;
        }
        auto current = parse_workspace_record(fields);
        current.active = current.workspace_id == workspace_id;
        if (current.active) {
            current.updated_utc = now;
            active = current;
            found = true;
        }
        out.push_back(format_workspace_record(current));
    }

    if (!found) {
        return Result<NetworkWorkspaceRecord>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "workspace switch blocked",
            "workspace id not found: " + workspace_id
        );
    }

    write_lines(config.database_path, out);
    return Result<NetworkWorkspaceRecord>::ok(active);
}

Result<NetworkWorkspaceRecord> get_active_network_workspace(const StorageConfig& config) {
    const auto records = list_workspace_records_internal(read_lines(config.database_path));
    for (const auto& record : records) {
        if (record.active) {
            return Result<NetworkWorkspaceRecord>::ok(record);
        }
    }
    return Result<NetworkWorkspaceRecord>::fail(
        netsentinel::engine::ErrorCode::invalid_input,
        "active workspace missing",
        "no active network workspace is selected"
    );
}

Result<std::size_t> append_workspace_scan_history(
    const WorkspaceScanHistoryRecord& record,
    const StorageConfig& config
) {
    if (record.workspace_id.empty()) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "workspace scan history blocked",
            "workspace id must be non-empty"
        );
    }

    auto lines = read_lines(config.database_path);
    if (lines.empty()) {
        lines = ensure_header(lines);
    }
    const auto workspaces = list_workspace_records_internal(lines);
    const bool exists = std::any_of(
        workspaces.begin(),
        workspaces.end(),
        [&](const NetworkWorkspaceRecord& workspace) {
            return workspace.workspace_id == record.workspace_id;
        }
    );
    if (!exists) {
        return Result<std::size_t>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "workspace scan history blocked",
            "workspace id not found: " + record.workspace_id
        );
    }

    WorkspaceScanHistoryRecord normalized = record;
    if (normalized.status.empty()) {
        normalized.status = "unknown";
    }
    if (normalized.at_utc.empty()) {
        normalized.at_utc = timestamp_now_utc();
    }
    lines.push_back(format_workspace_scan_record(normalized));
    write_lines(config.database_path, lines);
    return Result<std::size_t>::ok(1);
}

Result<std::vector<WorkspaceScanHistoryRecord>> list_workspace_scan_history(
    const std::string& workspace_id,
    const StorageConfig& config
) {
    const auto records = list_workspace_scan_records_internal(read_lines(config.database_path));
    std::vector<WorkspaceScanHistoryRecord> out;
    for (const auto& record : records) {
        if (!workspace_id.empty() && record.workspace_id != workspace_id) {
            continue;
        }
        out.push_back(record);
    }
    std::sort(
        out.begin(),
        out.end(),
        [](const WorkspaceScanHistoryRecord& lhs, const WorkspaceScanHistoryRecord& rhs) {
            return lhs.at_utc < rhs.at_utc;
        }
    );
    return Result<std::vector<WorkspaceScanHistoryRecord>>::ok(std::move(out));
}

Result<std::vector<DeviceSearchResult>> search_inventory_devices(
    const DeviceSearchQuery& query,
    const StorageConfig& config
) {
    const auto inventory_result = list_inventory_records(config, query.include_hidden);
    if (!inventory_result) {
        return Result<std::vector<DeviceSearchResult>>::fail(
            inventory_result.error().code,
            inventory_result.error().context,
            inventory_result.error().details
        );
    }
    const auto timeline = list_timeline_records_internal(read_lines(config.database_path));
    const auto network_by_device = latest_network_by_device(timeline);
    const auto security_devices = devices_with_security_findings(timeline);

    std::vector<DeviceSearchResult> out;
    for (const auto& device : inventory_result.value()) {
        std::vector<std::string> reasons;
        std::string network_id;
        const auto network_iter = network_by_device.find(device.device_id);
        if (network_iter != network_by_device.end()) {
            network_id = network_iter->second;
        }

        if (!query.network_id.empty() && network_id != query.network_id) {
            continue;
        }

        if (!match_device_search_preset(device, network_id, security_devices, query, reasons)) {
            continue;
        }

        if (!query.vendor.empty() && !contains_ci(device.vendor_hint, query.vendor)) {
            continue;
        }
        if (!query.vendor.empty()) {
            add_match_reason(reasons, "vendor-match");
        }

        if (!query.os_guess.empty() && !contains_ci(device.details, query.os_guess)) {
            continue;
        }
        if (!query.os_guess.empty()) {
            add_match_reason(reasons, "os-guess-match");
        }

        if (!query.text.empty() && !contains_ci(device_search_blob(device), query.text)) {
            continue;
        }
        if (!query.text.empty()) {
            add_match_reason(reasons, "text-match");
        }

        out.push_back({
            .device = device,
            .network_id = network_id,
            .matched_reasons = reasons,
            .relevance = static_cast<int>(reasons.size() * 10 + device.importance)
        });
    }

    std::sort(
        out.begin(),
        out.end(),
        [](const DeviceSearchResult& lhs, const DeviceSearchResult& rhs) {
            if (lhs.relevance != rhs.relevance) {
                return lhs.relevance > rhs.relevance;
            }
            return lhs.device.device_id < rhs.device.device_id;
        }
    );
    return Result<std::vector<DeviceSearchResult>>::ok(std::move(out));
}

Result<SavedFilterTemplate> save_filter_template(
    const SavedFilterTemplate& filter,
    const StorageConfig& config
) {
    if (filter.filter_id.empty()) {
        return Result<SavedFilterTemplate>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "filter template save blocked",
            "filter id must be non-empty"
        );
    }

    SavedFilterTemplate normalized = filter;
    if (normalized.name.empty()) {
        normalized.name = normalized.filter_id;
    }
    if (normalized.query.preset.empty()) {
        normalized.query.preset = "all";
    }
    if (normalized.created_utc.empty()) {
        normalized.created_utc = timestamp_now_utc();
    }

    auto lines = read_lines(config.database_path);
    if (lines.empty()) {
        lines = ensure_header(lines);
    }

    std::vector<std::string> out;
    out.reserve(lines.size() + 1);
    std::vector<std::string> fields;
    bool replaced = false;
    for (const auto& line : lines) {
        if (!is_filter_template_record(line, fields)) {
            out.push_back(line);
            continue;
        }
        auto existing = parse_filter_template_record(fields);
        if (existing.filter_id == normalized.filter_id) {
            if (normalized.created_utc.empty()) {
                normalized.created_utc = existing.created_utc;
            }
            out.push_back(format_filter_template_record(normalized));
            replaced = true;
        } else {
            out.push_back(line);
        }
    }
    if (!replaced) {
        out.push_back(format_filter_template_record(normalized));
    }
    write_lines(config.database_path, out);
    return Result<SavedFilterTemplate>::ok(normalized);
}

Result<std::vector<SavedFilterTemplate>> list_filter_templates(const StorageConfig& config) {
    auto filters = list_filter_template_records_internal(read_lines(config.database_path));
    std::sort(
        filters.begin(),
        filters.end(),
        [](const SavedFilterTemplate& lhs, const SavedFilterTemplate& rhs) {
            return lhs.filter_id < rhs.filter_id;
        }
    );
    return Result<std::vector<SavedFilterTemplate>>::ok(std::move(filters));
}

Result<std::vector<DeviceSearchResult>> run_saved_filter_template(
    const std::string& filter_id,
    const StorageConfig& config
) {
    if (filter_id.empty()) {
        return Result<std::vector<DeviceSearchResult>>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "filter template run blocked",
            "filter id must be non-empty"
        );
    }
    const auto filters = list_filter_templates(config);
    if (!filters) {
        return Result<std::vector<DeviceSearchResult>>::fail(filters.error().code, filters.error().context, filters.error().details);
    }
    for (const auto& filter : filters.value()) {
        if (filter.filter_id == filter_id) {
            return search_inventory_devices(filter.query, config);
        }
    }
    return Result<std::vector<DeviceSearchResult>>::fail(
        netsentinel::engine::ErrorCode::invalid_input,
        "filter template missing",
        "no saved filter template with id: " + filter_id
    );
}

} // namespace netsentinel::storage
