#include "netsentinel/engine/domain_model.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace {

std::string escape_json(std::string_view value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (const unsigned char ch : value) {
        switch (ch) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (ch < 0x20) {
                    std::ostringstream escaped;
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch);
                    out += escaped.str();
                } else {
                    out += static_cast<char>(ch);
                }
        }
    }
    return out;
}

void skip_ws(const std::string& text, std::size_t& pos) {
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
        ++pos;
    }
}

std::size_t find_matching(std::string_view text, std::size_t open_pos, char open_c, char close_c) {
    if (open_c == close_c) {
        bool escaped = false;
        for (std::size_t i = open_pos + 1; i < text.size(); ++i) {
            const char ch = text[i];
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == close_c) {
                return i;
            }
        }
        throw std::runtime_error("malformed json: unmatched delimiter");
    }

    std::size_t depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (std::size_t i = open_pos; i < text.size(); ++i) {
        const char ch = text[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (in_string) {
            if (ch == '\\') {
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
        if (ch == open_c) {
            ++depth;
        } else if (ch == close_c) {
            --depth;
            if (depth == 0) {
                return i;
            }
        }
    }
    throw std::runtime_error("malformed json: unmatched delimiter");
}

std::string extract_raw_value(std::string_view text, std::string_view key) {
    const auto pattern = std::string("\"") + std::string(key) + "\"";
    const auto key_pos = text.find(pattern);
    if (key_pos == std::string_view::npos) {
        throw std::invalid_argument("missing key: " + std::string(key));
    }
    std::size_t pos = key_pos + key.size() + 2;
    skip_ws(std::string(text), pos);
    if (pos >= text.size() || text[pos] != ':') {
        throw std::invalid_argument("malformed key/value for " + std::string(key));
    }
    ++pos;
    skip_ws(std::string(text), pos);
    if (pos >= text.size()) {
        throw std::invalid_argument("empty value for " + std::string(key));
    }

    if (text[pos] == '"') {
        const auto end_quote = find_matching(text, pos, '\"', '\"');
        return std::string(text.substr(pos, end_quote - pos + 1));
    }
    if (text[pos] == '{' || text[pos] == '[') {
        const char close = text[pos] == '{' ? '}' : ']';
        const auto end = find_matching(text, pos, text[pos], close);
        return std::string(text.substr(pos, end - pos + 1));
    }
    const auto start = pos;
    while (pos < text.size() && text[pos] != ',' && text[pos] != '}') {
        ++pos;
    }
    return std::string(text.substr(start, pos - start));
}

std::string parse_json_string_value(std::string_view raw) {
    if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"') {
        throw std::invalid_argument("expected quoted string");
    }
    std::string value = std::string(raw.substr(1, raw.size() - 2));
    std::string out;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) {
            ++i;
            switch (value[i]) {
                case '"':
                    out += '"';
                    break;
                case '\\':
                    out += '\\';
                    break;
                case 'n':
                    out += '\n';
                    break;
                case 'r':
                    out += '\r';
                    break;
                case 't':
                    out += '\t';
                    break;
                default:
                    out += value[i];
                    break;
            }
        } else {
            out += value[i];
        }
    }
    return out;
}

std::string extract_or_empty_raw(const std::string& text, std::string_view key) {
    try {
        return extract_raw_value(text, key);
    } catch (const std::exception&) {
        return "";
    }
}

std::string read_bool(std::string_view raw) {
    std::string v = std::string(raw);
    v.erase(std::remove_if(v.begin(), v.end(), [](char c) { return std::isspace((unsigned char)c); }), v.end());
    if (v != "true" && v != "false") {
        throw std::invalid_argument("expected bool");
    }
    return v;
}

std::string read_number(std::string_view raw) {
    std::string v = std::string(raw);
    v.erase(std::remove_if(v.begin(), v.end(), [](char c) { return std::isspace((unsigned char)c); }), v.end());
    if (v.empty()) {
        throw std::invalid_argument("expected number");
    }
    return v;
}

std::vector<std::string> split_top_level_array(std::string_view array_raw) {
    if (array_raw.empty() || array_raw.front() != '[' || array_raw.back() != ']') {
        throw std::invalid_argument("expected json array");
    }
    std::vector<std::string> out;
    std::size_t pos = 1;
    while (pos < array_raw.size() - 1) {
        skip_ws(std::string(array_raw), pos);
        if (pos >= array_raw.size() - 1) {
            break;
        }
        if (array_raw[pos] == '{') {
            const auto end = find_matching(array_raw, pos, '{', '}');
            out.push_back(std::string(array_raw.substr(pos, end - pos + 1)));
            pos = end + 1;
        } else if (array_raw[pos] == ',') {
            ++pos;
        } else if (array_raw[pos] == ']') {
            break;
        } else {
            auto start = pos;
            while (pos < array_raw.size() - 1 && array_raw[pos] != ',' && array_raw[pos] != ']') {
                ++pos;
            }
            out.push_back(std::string(array_raw.substr(start, pos - start)));
        }
        if (array_raw[pos] == ',') {
            ++pos;
        }
    }
    return out;
}

template <typename Container>
void append_array(std::string& out, const char* key, const Container& values) {
    out += "\"";
    out += key;
    out += "\":[";
    bool first = true;
    for (const auto& value : values) {
        if (!first) {
            out += ",";
        }
        first = false;
        out += value.to_json();
    }
    out += "]";
}

std::vector<std::string> read_json_array(std::string_view raw, std::string_view key) {
    const auto raw_value = extract_raw_value(raw, key);
    auto values = split_top_level_array(raw_value);
    return values;
}

std::string optional_or_empty(std::string_view value) {
    if (value.empty()) {
        return "";
    }
    return std::string(value);
}

} // namespace

namespace netsentinel::engine {

bool validate_network_like(const std::string& value) {
    if (value.empty() || value.size() > 45) {
        return false;
    }
    bool has_digit = false;
    bool has_dot_or_colon = false;
    for (const unsigned char ch : value) {
        if (std::isdigit(ch)) {
            has_digit = true;
            continue;
        }
        if (ch == '.' || ch == ':' || ch == '/' || ch == '-') {
            has_dot_or_colon = true;
            continue;
        }
        if (ch == '*') {
            return false;
        }
        return false;
    }
    return has_digit && has_dot_or_colon;
}

std::string to_string(DeviceEventKind kind) {
    switch (kind) {
        case DeviceEventKind::Discovered:
            return "discovered";
        case DeviceEventKind::Updated:
            return "updated";
        case DeviceEventKind::Offline:
            return "offline";
        case DeviceEventKind::SecurityFinding:
            return "security_finding";
        case DeviceEventKind::Recovered:
            return "recovered";
    }
    return "unknown";
}

DeviceEventKind device_event_kind_from_string(std::string_view value) {
    if (value == "discovered") {
        return DeviceEventKind::Discovered;
    }
    if (value == "updated") {
        return DeviceEventKind::Updated;
    }
    if (value == "offline") {
        return DeviceEventKind::Offline;
    }
    if (value == "security_finding") {
        return DeviceEventKind::SecurityFinding;
    }
    if (value == "recovered") {
        return DeviceEventKind::Recovered;
    }
    return DeviceEventKind::Discovered;
}

std::string to_string(Severity level) {
    switch (level) {
        case Severity::Low:
            return "low";
        case Severity::Medium:
            return "medium";
        case Severity::High:
            return "high";
        case Severity::Critical:
            return "critical";
    }
    return "low";
}

Severity severity_from_string(std::string_view value) {
    if (value == "low") {
        return Severity::Low;
    }
    if (value == "medium") {
        return Severity::Medium;
    }
    if (value == "high") {
        return Severity::High;
    }
    if (value == "critical") {
        return Severity::Critical;
    }
    return Severity::Low;
}

std::string NetworkInterface::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"interface_id\":\"" << escape_json(interface_id) << "\","
       << "\"name\":\"" << escape_json(name) << "\","
       << "\"display_name\":" << (display_name ? "\"" + escape_json(*display_name) + "\"" : "null") << ","
       << "\"mac_address\":" << (mac_address ? "\"" + escape_json(*mac_address) + "\"" : "null") << ","
       << "\"is_up\":" << (is_up ? "true" : "false") << ","
       << "\"ipv4_addresses\":[";
    for (std::size_t i = 0; i < ipv4_addresses.size(); ++i) {
        if (i) os << ",";
        os << "\"" << escape_json(ipv4_addresses[i]) << "\"";
    }
    os << "],\"ipv6_addresses\":[";
    for (std::size_t i = 0; i < ipv6_addresses.size(); ++i) {
        if (i) os << ",";
        os << "\"" << escape_json(ipv6_addresses[i]) << "\"";
    }
    os << "]"
       << "}";
    return os.str();
}

NetworkInterface NetworkInterface::from_json(const std::string& json) {
    NetworkInterface out;
    out.interface_id = parse_json_string_value(extract_raw_value(json, "interface_id"));
    out.name = parse_json_string_value(extract_raw_value(json, "name"));
    auto display_name_raw = extract_raw_value(json, "display_name");
    auto mac_raw = extract_raw_value(json, "mac_address");
    if (display_name_raw != "null") {
        out.display_name = parse_json_string_value(display_name_raw);
    }
    if (mac_raw != "null") {
        out.mac_address = parse_json_string_value(mac_raw);
    }
    out.is_up = read_bool(extract_raw_value(json, "is_up")) == "true";
    for (const auto& value : read_json_array(json, "ipv4_addresses")) {
        if (value.front() == '\"') {
            out.ipv4_addresses.push_back(parse_json_string_value(value));
        }
    }
    for (const auto& value : read_json_array(json, "ipv6_addresses")) {
        if (value.front() == '\"') {
            out.ipv6_addresses.push_back(parse_json_string_value(value));
        }
    }
    return out;
}

std::string NetworkScope::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"scope_id\":\"" << escape_json(scope_id) << "\","
       << "\"cidr_or_range\":\"" << escape_json(cidr_or_range) << "\","
       << "\"notes\":\"" << escape_json(notes) << "\","
       << "\"local_only\":" << (local_only ? "true" : "false") << ","
       << "\"authorized\":" << (authorized ? "true" : "false") << ","
       << "\"created_epoch_ms\":" << created_epoch_ms
       << "}";
    return os.str();
}

NetworkScope NetworkScope::from_json(const std::string& json) {
    NetworkScope out;
    out.scope_id = parse_json_string_value(extract_raw_value(json, "scope_id"));
    out.cidr_or_range = parse_json_string_value(extract_raw_value(json, "cidr_or_range"));
    out.notes = parse_json_string_value(extract_raw_value(json, "notes"));
    out.local_only = read_bool(extract_raw_value(json, "local_only")) == "true";
    out.authorized = read_bool(extract_raw_value(json, "authorized")) == "true";
    out.created_epoch_ms = std::stoll(read_number(extract_raw_value(json, "created_epoch_ms")));
    return out;
}

std::string DeviceIdentity::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"device_id\":\"" << escape_json(device_id) << "\","
        << "\"hostname\":\"" << escape_json(hostname) << "\","
        << "\"hostname_source\":\"" << escape_json(hostname_source) << "\","
        << "\"hostname_confidence\":" << hostname_confidence << ","
       << "\"netbios_name\":" << (netbios_name ? "\"" + escape_json(*netbios_name) + "\"" : "null") << ","
       << "\"netbios_workgroup\":\"" << escape_json(netbios_workgroup) << "\","
       << "\"netbios_source\":\"" << escape_json(netbios_source) << "\","
       << "\"netbios_confidence\":" << netbios_confidence << ","
        << "\"mac_address\":" << (mac_address ? "\"" + escape_json(*mac_address) + "\"" : "null") << ","
       << "\"ipv4_addresses\":[";
    for (std::size_t i = 0; i < ipv4_addresses.size(); ++i) {
        if (i) os << ",";
        os << "\"" << escape_json(ipv4_addresses[i]) << "\"";
    }
    os << "],"
       << "\"vendor_hint\":" << (vendor_hint ? "\"" + escape_json(*vendor_hint) + "\"" : "null") << ","
       << "\"confidence\":" << confidence
       << "}";
    return os.str();
}

DeviceIdentity DeviceIdentity::from_json(const std::string& json) {
    DeviceIdentity out;
    out.device_id = parse_json_string_value(extract_raw_value(json, "device_id"));
    out.hostname = parse_json_string_value(extract_raw_value(json, "hostname"));
    const auto raw_hostname_source = extract_or_empty_raw(json, "hostname_source");
    if (!raw_hostname_source.empty()) {
        out.hostname_source = parse_json_string_value(raw_hostname_source);
    }
    const auto raw_hostname_confidence = extract_or_empty_raw(json, "hostname_confidence");
    if (!raw_hostname_confidence.empty()) {
        out.hostname_confidence = std::stoi(read_number(raw_hostname_confidence));
    }
    const auto raw_netbios_name = extract_or_empty_raw(json, "netbios_name");
    if (!raw_netbios_name.empty() && raw_netbios_name != "null") {
        out.netbios_name = parse_json_string_value(raw_netbios_name);
    }
    out.netbios_workgroup = parse_json_string_value(
        extract_or_empty_raw(json, "netbios_workgroup").empty() ? "\"\"" : extract_raw_value(json, "netbios_workgroup")
    );
    const auto raw_netbios_source = extract_or_empty_raw(json, "netbios_source");
    if (!raw_netbios_source.empty()) {
        out.netbios_source = parse_json_string_value(raw_netbios_source);
    }
    const auto raw_netbios_confidence = extract_or_empty_raw(json, "netbios_confidence");
    if (!raw_netbios_confidence.empty()) {
        out.netbios_confidence = std::stoi(read_number(raw_netbios_confidence));
    }
    auto mac_raw = extract_raw_value(json, "mac_address");
    if (mac_raw != "null") {
        out.mac_address = parse_json_string_value(mac_raw);
    }
    for (const auto& value : read_json_array(json, "ipv4_addresses")) {
        if (value.front() == '\"') {
            out.ipv4_addresses.push_back(parse_json_string_value(value));
        }
    }
    auto vendor_raw = extract_raw_value(json, "vendor_hint");
    if (vendor_raw != "null") {
        out.vendor_hint = parse_json_string_value(vendor_raw);
    }
    out.confidence = std::stoi(read_number(extract_raw_value(json, "confidence")));
    return out;
}

std::string ProbeResult::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"probe_name\":\"" << escape_json(probe_name) << "\","
       << "\"target\":\"" << escape_json(target) << "\","
       << "\"success\":" << (success ? "true" : "false") << ","
       << "\"response_time_ms\":" << response_time_ms << ","
       << "\"message\":\"" << escape_json(message) << "\","
       << "\"error_code\":\"" << escape_json(error_code) << "\""
       << "}";
    return os.str();
}

ProbeResult ProbeResult::from_json(const std::string& json) {
    ProbeResult out;
    out.probe_name = parse_json_string_value(extract_raw_value(json, "probe_name"));
    out.target = parse_json_string_value(extract_raw_value(json, "target"));
    out.success = read_bool(extract_raw_value(json, "success")) == "true";
    out.response_time_ms = std::stoll(read_number(extract_raw_value(json, "response_time_ms")));
    out.message = parse_json_string_value(extract_raw_value(json, "message"));
    out.error_code = parse_json_string_value(extract_raw_value(json, "error_code"));
    return out;
}

std::string ScanSession::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"session_id\":\"" << escape_json(session_id) << "\","
       << "\"profile_name\":\"" << escape_json(profile_name) << "\","
       << "\"started_at_utc\":\"" << escape_json(started_at_utc) << "\","
       << "\"ended_at_utc\":\"" << escape_json(ended_at_utc) << "\","
       << "\"completed\":" << (completed ? "true" : "false") << ","
       << "\"status_text\":\"" << escape_json(status_text) << "\","
       << "\"probe_results\":[";
    for (std::size_t i = 0; i < probe_results.size(); ++i) {
        if (i) {
            os << ",";
        }
        os << probe_results[i].to_json();
    }
    os << "]";
    os << "}";
    return os.str();
}

ScanSession ScanSession::from_json(const std::string& json) {
    ScanSession out;
    out.session_id = parse_json_string_value(extract_raw_value(json, "session_id"));
    out.profile_name = parse_json_string_value(extract_raw_value(json, "profile_name"));
    out.started_at_utc = parse_json_string_value(extract_raw_value(json, "started_at_utc"));
    out.ended_at_utc = parse_json_string_value(extract_raw_value(json, "ended_at_utc"));
    out.completed = read_bool(extract_raw_value(json, "completed")) == "true";
    out.status_text = parse_json_string_value(extract_raw_value(json, "status_text"));
    for (const auto& value : read_json_array(json, "probe_results")) {
        out.probe_results.push_back(ProbeResult::from_json(value));
    }
    return out;
}

std::string ScanProfile::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"profile_id\":\"" << escape_json(profile_id) << "\","
       << "\"name\":\"" << escape_json(name) << "\","
       << "\"scope\":" << scope.to_json() << ","
       << "\"enabled\":" << (enabled ? "true" : "false") << ","
       << "\"timeout_seconds\":" << timeout_seconds << ","
       << "\"retries\":" << retries
       << "}";
    return os.str();
}

ScanProfile ScanProfile::from_json(const std::string& json) {
    ScanProfile out;
    out.profile_id = parse_json_string_value(extract_raw_value(json, "profile_id"));
    out.name = parse_json_string_value(extract_raw_value(json, "name"));
    out.scope = NetworkScope::from_json(extract_raw_value(json, "scope"));
    out.enabled = read_bool(extract_raw_value(json, "enabled")) == "true";
    out.timeout_seconds = std::stoi(read_number(extract_raw_value(json, "timeout_seconds")));
    out.retries = std::stoi(read_number(extract_raw_value(json, "retries")));
    return out;
}

std::string DeviceEvent::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"kind\":\"" << to_string(kind) << "\","
       << "\"device_id\":\"" << escape_json(device_id) << "\","
       << "\"at_utc\":\"" << escape_json(at_utc) << "\","
       << "\"summary\":\"" << escape_json(summary) << "\","
       << "\"details\":\"" << escape_json(details) << "\""
       << "}";
    return os.str();
}

DeviceEvent DeviceEvent::from_json(const std::string& json) {
    DeviceEvent out;
    out.kind = device_event_kind_from_string(parse_json_string_value(extract_raw_value(json, "kind")));
    out.device_id = parse_json_string_value(extract_raw_value(json, "device_id"));
    out.at_utc = parse_json_string_value(extract_raw_value(json, "at_utc"));
    out.summary = parse_json_string_value(extract_raw_value(json, "summary"));
    out.details = parse_json_string_value(extract_raw_value(json, "details"));
    return out;
}

std::string SecurityFinding::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"finding_id\":\"" << escape_json(finding_id) << "\","
       << "\"device_id\":\"" << escape_json(device_id) << "\","
       << "\"severity\":\"" << to_string(severity) << "\","
       << "\"title\":\"" << escape_json(title) << "\","
       << "\"details\":\"" << escape_json(details) << "\","
       << "\"first_seen_utc\":\"" << escape_json(first_seen_utc) << "\","
       << "\"acknowledged\":" << (acknowledged ? "true" : "false")
       << "}";
    return os.str();
}

SecurityFinding SecurityFinding::from_json(const std::string& json) {
    SecurityFinding out;
    out.finding_id = parse_json_string_value(extract_raw_value(json, "finding_id"));
    out.device_id = parse_json_string_value(extract_raw_value(json, "device_id"));
    out.severity = severity_from_string(parse_json_string_value(extract_raw_value(json, "severity")));
    out.title = parse_json_string_value(extract_raw_value(json, "title"));
    out.details = parse_json_string_value(extract_raw_value(json, "details"));
    out.first_seen_utc = parse_json_string_value(extract_raw_value(json, "first_seen_utc"));
    out.acknowledged = read_bool(extract_raw_value(json, "acknowledged")) == "true";
    return out;
}

std::string ReportSummary::to_json() const {
    std::ostringstream os;
    os << "{"
       << "\"report_id\":\"" << escape_json(report_id) << "\","
       << "\"generated_at_utc\":\"" << escape_json(generated_at_utc) << "\","
       << "\"total_devices\":" << total_devices << ","
       << "\"total_events\":" << total_events << ","
       << "\"total_findings\":" << total_findings << ","
       << "\"health_score\":" << std::fixed << std::setprecision(2) << health_score << ","
       << "\"warnings\":\"" << escape_json(warnings) << "\""
       << "}";
    return os.str();
}

ReportSummary ReportSummary::from_json(const std::string& json) {
    ReportSummary out;
    out.report_id = parse_json_string_value(extract_raw_value(json, "report_id"));
    out.generated_at_utc = parse_json_string_value(extract_raw_value(json, "generated_at_utc"));
    out.total_devices = static_cast<std::size_t>(std::stoull(read_number(extract_raw_value(json, "total_devices"))));
    out.total_events = static_cast<std::size_t>(std::stoull(read_number(extract_raw_value(json, "total_events"))));
    out.total_findings = static_cast<std::size_t>(std::stoull(read_number(extract_raw_value(json, "total_findings"))));
    out.health_score = std::stod(read_number(extract_raw_value(json, "health_score")));
    out.warnings = parse_json_string_value(extract_raw_value(json, "warnings"));
    return out;
}

} // namespace netsentinel::engine
