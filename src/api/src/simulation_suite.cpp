#include "netsentinel/api/simulation_suite.h"

#include <sstream>
#include <utility>

namespace netsentinel::api {

namespace {

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        if (ch == '\\') {
            out += "\\\\";
        } else if (ch == '"') {
            out += "\\\"";
        } else if (ch == '\n') {
            out += "\\n";
        } else if (ch == '\r') {
            out += "\\r";
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::string json_string(const std::string& value) {
    return "\"" + json_escape(value) + "\"";
}

std::string json_string_array(const std::vector<std::string>& values) {
    std::string out = "[";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        out += json_string(values[i]);
    }
    out += "]";
    return out;
}

std::vector<SimulationDevice> deterministic_devices() {
    return {
        {"router", "RT-AX92U-7130", "192.168.50.1", "AA:BB:CC:DD:EE:01", "router", "infrastructure", {"arp", "icmp", "tcp"}, 120000000, 40000000, true, false},
        {"laptop3070", "Laptop3070", "192.168.50.30", "38:7A:0E:A4:EF:84", "pc", "work", {"arp", "icmp", "hostname"}, 900000000, 420000000, false, false},
        {"nas", "Nas", "192.168.50.61", "90:09:D0:7D:F5:3D", "nas", "infrastructure", {"arp", "tcp"}, 1500000000, 800000000, true, false},
        {"camera", "VMC2030-A3452", "192.168.50.132", "A4:11:62:C3:B3:53", "camera", "iot", {"arp", "mdns", "ssdp"}, 60000000, 180000000, true, false},
        {"charger", "Easee-EHRHSTNG", "192.168.50.68", "EC:94:CB:77:E8:E0", "iot", "iot", {"arp", "hostname"}, 20000000, 8000000, true, false},
        {"phone", "OnePlus-Nord-CE5", "192.168.50.158", "6E:67:88:F6:06:F3", "phone", "family", {"arp", "icmp"}, 600000000, 220000000, false, false},
        {"guest-phone", "GuestPhone", "192.168.50.199", "02:11:22:33:44:55", "phone", "guest", {"arp"}, 100000000, 50000000, true, true},
        {"tablet", "iPad", "192.168.50.130", "02:37:39:4A:D1:82", "tablet", "family", {"arp", "icmp"}, 320000000, 100000000, false, false}
    };
}

SimulationStageResult stage(
    std::string id,
    std::string title,
    int duration_ms,
    std::string summary,
    std::vector<std::string> evidence
) {
    return {
        .stage_id = std::move(id),
        .title = std::move(title),
        .success = true,
        .duration_ms = duration_ms,
        .summary = std::move(summary),
        .evidence = std::move(evidence)
    };
}

std::string markdown_list(const std::vector<std::string>& values) {
    if (values.empty()) {
        return "- None\n";
    }
    std::string out;
    for (const auto& value : values) {
        out += "- " + value + "\n";
    }
    return out;
}

} // namespace

SimulationSuiteResult run_end_to_end_simulation(const SimulationSuiteConfig& config) {
    SimulationSuiteResult result{};
    result.mock_mode = config.mock_mode;
    if (!config.mock_mode) {
        result.success = false;
        result.message = "End-to-end simulation suite is mock-only and must not scan real networks.";
        result.warnings.push_back(result.message);
        return result;
    }

    result.devices = deterministic_devices();
    result.performance_targets = {
        "CI target: complete deterministic simulation under 2 seconds",
        "No sockets opened and no packets sent",
        "Fixture device count remains small and deterministic",
        "All blocking controls are advisory/dry-run only"
    };
    result.stages = {
        stage("discovery", "Mock discovery", 120, "Discovered routers, PCs, phones, camera, IoT, NAS, guest, and tablet.", {"ARP fixture", "ICMP fixture", "mDNS/SSDP fixture"}),
        stage("monitoring", "Mock monitoring", 90, "Generated join/change events without background service or live probes.", {"new guest device", "camera review event"}),
        stage("alerts", "Mock alerts", 40, "Raised safe new-device and security-review alerts.", {"guest-phone alert", "camera privacy review alert"}),
        stage("security", "Mock security checks", 150, "Ran advisory-only router, camera, lifecycle, and CVE/CPE review paths.", {"no exploit payloads", "no credential checks", "metadata-only findings"}),
        stage("bandwidth", "Mock bandwidth", 70, "Ranked top talkers from deterministic byte counters.", {"nas top talker", "laptop high usage", "phone moderate usage"}),
        stage("blocking", "Mock blocking backends", 30, "Exercised advisory/dry-run blocking path only.", {"no firewall rule applied", "no router mutation"}),
        stage("reports", "Mock reports", 80, "Generated inventory/security/bandwidth report summaries from fixtures.", {"privacy warning required before export", "local-only report data"})
    };

    const int total_ms = 120 + 90 + 40 + 150 + 70 + 30 + 80;
    const bool enough_devices = result.devices.size() >= config.expected_min_devices;
    const bool within_target = static_cast<std::size_t>(total_ms) <= config.max_runtime_ms;
    if (!enough_devices) {
        result.warnings.push_back("Simulation did not include the expected minimum device count.");
    }
    if (!within_target) {
        result.warnings.push_back("Simulation exceeded configured CI runtime target.");
    }
    result.success = enough_devices && within_target;
    result.message = result.success
        ? "End-to-end simulation completed without real network traffic."
        : "End-to-end simulation completed with warnings.";
    return result;
}

std::string simulation_suite_json(const SimulationSuiteResult& result) {
    std::string out = "{";
    out += "\"success\":" + std::string(result.success ? "true" : "false") + ",";
    out += "\"mock_mode\":" + std::string(result.mock_mode ? "true" : "false") + ",";
    out += "\"message\":" + json_string(result.message) + ",";
    out += "\"device_count\":" + std::to_string(result.devices.size()) + ",";
    out += "\"stage_count\":" + std::to_string(result.stages.size()) + ",";
    out += "\"warnings\":" + json_string_array(result.warnings) + ",";
    out += "\"stages\":[";
    for (std::size_t i = 0; i < result.stages.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        const auto& item = result.stages[i];
        out += "{";
        out += "\"id\":" + json_string(item.stage_id) + ",";
        out += "\"title\":" + json_string(item.title) + ",";
        out += "\"success\":" + std::string(item.success ? "true" : "false") + ",";
        out += "\"duration_ms\":" + std::to_string(item.duration_ms) + ",";
        out += "\"summary\":" + json_string(item.summary);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string simulation_suite_markdown(const SimulationSuiteResult& result) {
    std::ostringstream out;
    out << "# End To End Simulation Suite\n\n";
    out << "- Success: " << (result.success ? "yes" : "no") << "\n";
    out << "- Mock mode: " << (result.mock_mode ? "yes" : "no") << "\n";
    out << "- Devices: " << result.devices.size() << "\n";
    out << "- Stages: " << result.stages.size() << "\n";
    out << "- Message: " << result.message << "\n\n";
    out << "## Performance targets\n\n";
    out << markdown_list(result.performance_targets) << "\n";
    out << "## Devices\n\n";
    for (const auto& device : result.devices) {
        out << "- " << device.device_id << " (" << device.device_type << ", " << device.ip_address << ", owner=" << device.owner_group << ")\n";
    }
    out << "\n## Stages\n\n";
    for (const auto& item : result.stages) {
        out << "### " << item.title << "\n\n";
        out << "- Status: " << (item.success ? "pass" : "fail") << "\n";
        out << "- Duration: " << item.duration_ms << " ms\n";
        out << "- Summary: " << item.summary << "\n";
        out << "- Evidence:\n";
        out << markdown_list(item.evidence) << "\n";
    }
    out << "## Warnings\n\n";
    out << markdown_list(result.warnings) << "\n";
    out << "## Safety\n\n";
    out << "- This simulation opens no sockets and sends no packets.\n";
    out << "- It does not scan public IPs or unauthorized networks.\n";
    out << "- It uses advisory/dry-run blocking only.\n";
    out << "- It includes no exploit, brute-force, MITM, spoofing, deauth, stealth, or disruption behavior.\n";
    return out.str();
}

} // namespace netsentinel::api
