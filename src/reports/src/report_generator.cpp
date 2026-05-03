#include "netsentinel/reports/report_generator.h"

#include "netsentinel/diagnostics/diagnostic_tools.h"
#include "netsentinel/bandwidth/bandwidth_source.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace netsentinel::reports {

namespace {

std::string lower_copy(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        }
    );
    return value;
}

std::string csv_escape(const std::string& value) {
    bool needs_quotes = false;
    for (const char ch : value) {
        if (ch == ',' || ch == '"' || ch == '\n' || ch == '\r') {
            needs_quotes = true;
            break;
        }
    }
    if (!needs_quotes) {
        return value;
    }
    std::string out = "\"";
    for (const char ch : value) {
        if (ch == '"') {
            out += "\"\"";
        } else {
            out.push_back(ch);
        }
    }
    out += "\"";
    return out;
}

std::string html_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        if (ch == '&') {
            out += "&amp;";
        } else if (ch == '<') {
            out += "&lt;";
        } else if (ch == '>') {
            out += "&gt;";
        } else if (ch == '"') {
            out += "&quot;";
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

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

std::string join_csv(const std::vector<std::string>& values) {
    std::string out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            out += ";";
        }
        out += values[i];
    }
    return out;
}

std::string ports_csv(const std::vector<int>& ports) {
    std::string out;
    for (std::size_t i = 0; i < ports.size(); ++i) {
        if (i > 0) {
            out += ";";
        }
        out += std::to_string(ports[i]);
    }
    return out;
}

std::string normalize_report_type(const std::string& value) {
    const auto lower = lower_copy(value);
    if (lower == "summary") {
        return "executive";
    }
    if (lower == "security-assessment") {
        return "security";
    }
    if (lower == "wifi") {
        return "wi-fi";
    }
    return lower.empty() ? std::string{"executive"} : lower;
}

std::string normalize_report_format(const std::string& value) {
    const auto lower = lower_copy(value);
    if (lower.empty()) {
        return "html";
    }
    return lower;
}

std::vector<netsentinel::storage::DeviceInventoryRecord> read_inventory(const ReportConfig& config, std::vector<std::string>& warnings) {
    const auto records = netsentinel::storage::list_inventory_records(config.storage, true);
    if (!records) {
        warnings.push_back("inventory could not be loaded");
        return {};
    }
    return records.value();
}

std::vector<netsentinel::storage::DeviceTimelineRecord> read_events(const ReportConfig& config, std::vector<std::string>& warnings) {
    const auto events = netsentinel::storage::list_timeline_records(config.storage);
    if (!events) {
        warnings.push_back("timeline events could not be loaded");
        return {};
    }
    return events.value();
}

std::string render_inventory_csv(const std::vector<netsentinel::storage::DeviceInventoryRecord>& devices) {
    std::ostringstream out;
    out << "device_id,hostname,ip_addresses,mac_address,vendor,type,importance,hidden,stale,labels,open_tcp_ports,last_seen_utc\n";
    for (const auto& device : devices) {
        out << csv_escape(device.device_id) << ","
            << csv_escape(device.hostname) << ","
            << csv_escape(join_csv(device.ip_addresses)) << ","
            << csv_escape(device.mac_address) << ","
            << csv_escape(device.vendor_hint) << ","
            << csv_escape(device.device_type) << ","
            << device.importance << ","
            << (device.hidden ? "true" : "false") << ","
            << (device.stale ? "true" : "false") << ","
            << csv_escape(join_csv(device.user_labels)) << ","
            << csv_escape(ports_csv(device.open_tcp_ports)) << ","
            << csv_escape(device.last_seen_utc) << "\n";
    }
    return out.str();
}

std::string render_inventory_json(const std::vector<netsentinel::storage::DeviceInventoryRecord>& devices) {
    std::string out = "{\"report\":\"inventory\",\"devices\":[";
    for (std::size_t i = 0; i < devices.size(); ++i) {
        const auto& device = devices[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"device_id\":" + json_string(device.device_id) + ",";
        out += "\"hostname\":" + json_string(device.hostname) + ",";
        out += "\"vendor\":" + json_string(device.vendor_hint) + ",";
        out += "\"type\":" + json_string(device.device_type) + ",";
        out += "\"importance\":" + std::to_string(device.importance) + ",";
        out += "\"hidden\":" + std::string(device.hidden ? "true" : "false") + ",";
        out += "\"stale\":" + std::string(device.stale ? "true" : "false");
        out += "}";
    }
    out += "]}";
    return out;
}

std::string render_inventory_html(const std::vector<netsentinel::storage::DeviceInventoryRecord>& devices) {
    std::ostringstream out;
    out << "<section><h2>Inventory</h2><table><thead><tr><th>Device</th><th>Host</th><th>Vendor</th><th>Type</th><th>Importance</th></tr></thead><tbody>";
    for (const auto& device : devices) {
        out << "<tr><td>" << html_escape(device.device_id)
            << "</td><td>" << html_escape(device.hostname)
            << "</td><td>" << html_escape(device.vendor_hint)
            << "</td><td>" << html_escape(device.device_type)
            << "</td><td>" << device.importance << "</td></tr>";
    }
    out << "</tbody></table></section>";
    return out.str();
}

std::string render_security_csv(const diagnostics::SecurityHealthCheckResult& security) {
    std::ostringstream out;
    out << "component,penalty,max_penalty,status,detail\n";
    for (const auto& component : security.components) {
        out << csv_escape(component.name) << ","
            << component.penalty << ","
            << component.max_penalty << ","
            << csv_escape(component.status) << ","
            << csv_escape(component.detail) << "\n";
    }
    return out.str();
}

std::string render_security_json(const diagnostics::SecurityHealthCheckResult& security) {
    std::string out = "{\"report\":\"security\",\"score\":" + std::to_string(security.score) + ",\"grade\":" + json_string(security.grade) + ",\"components\":[";
    for (std::size_t i = 0; i < security.components.size(); ++i) {
        const auto& component = security.components[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"name\":" + json_string(component.name) + ",";
        out += "\"penalty\":" + std::to_string(component.penalty) + ",";
        out += "\"status\":" + json_string(component.status) + ",";
        out += "\"detail\":" + json_string(component.detail);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string render_security_html(const diagnostics::SecurityHealthCheckResult& security) {
    std::ostringstream out;
    out << "<section><h2>Security Assessment</h2><p>Score: <strong>" << security.score
        << "</strong> Grade: <strong>" << html_escape(security.grade) << "</strong></p><ul>";
    for (const auto& component : security.components) {
        out << "<li><strong>" << html_escape(component.name) << "</strong>: "
            << html_escape(component.status) << " (" << component.penalty << "/"
            << component.max_penalty << ") - " << html_escape(component.detail) << "</li>";
    }
    out << "</ul></section>";
    return out.str();
}

std::string render_wifi_csv(const diagnostics::WifiChannelAnalysisResult& wifi) {
    std::ostringstream out;
    out << "metric,value\n";
    out << "total_networks," << wifi.total_networks << "\n";
    out << "crowded_channels," << wifi.crowded_channels << "\n";
    out << "weak_signal_count," << wifi.weak_signal_count << "\n";
    out << "insecure_network_count," << wifi.insecure_network_count << "\n";
    return out.str();
}

std::string render_wifi_json(const diagnostics::WifiChannelAnalysisResult& wifi) {
    return "{\"report\":\"wi-fi\",\"total_networks\":" + std::to_string(wifi.total_networks) +
        ",\"crowded_channels\":" + std::to_string(wifi.crowded_channels) +
        ",\"weak_signal_count\":" + std::to_string(wifi.weak_signal_count) +
        ",\"insecure_network_count\":" + std::to_string(wifi.insecure_network_count) + "}";
}

std::string render_wifi_html(const diagnostics::WifiChannelAnalysisResult& wifi) {
    std::ostringstream out;
    out << "<section><h2>Wi-Fi Environment</h2><p>Total networks: " << wifi.total_networks
        << ", crowded channels: " << wifi.crowded_channels
        << ", weak signals: " << wifi.weak_signal_count
        << ", insecure networks: " << wifi.insecure_network_count << "</p></section>";
    return out.str();
}

std::string render_events_csv(const std::vector<netsentinel::storage::DeviceTimelineRecord>& events, const std::string& report_name) {
    std::ostringstream out;
    out << "report,network_id,device_id,event_type,severity,source,old_value,new_value,at_utc\n";
    for (const auto& event : events) {
        out << csv_escape(report_name) << ","
            << csv_escape(event.network_id) << ","
            << csv_escape(event.device_id) << ","
            << csv_escape(event.event_type) << ","
            << event.severity << ","
            << csv_escape(event.source) << ","
            << csv_escape(event.old_value) << ","
            << csv_escape(event.new_value) << ","
            << csv_escape(event.at_utc) << "\n";
    }
    return out.str();
}

std::string render_events_json(const std::vector<netsentinel::storage::DeviceTimelineRecord>& events, const std::string& report_name) {
    std::string out = "{\"report\":" + json_string(report_name) + ",\"events\":[";
    for (std::size_t i = 0; i < events.size(); ++i) {
        const auto& event = events[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"network_id\":" + json_string(event.network_id) + ",";
        out += "\"device_id\":" + json_string(event.device_id) + ",";
        out += "\"event_type\":" + json_string(event.event_type) + ",";
        out += "\"severity\":" + std::to_string(event.severity) + ",";
        out += "\"at_utc\":" + json_string(event.at_utc);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string render_events_html(const std::vector<netsentinel::storage::DeviceTimelineRecord>& events, const std::string& title) {
    std::ostringstream out;
    out << "<section><h2>" << html_escape(title) << "</h2><ul>";
    for (const auto& event : events) {
        out << "<li>" << html_escape(event.at_utc) << " "
            << html_escape(event.network_id) << " / "
            << html_escape(event.device_id) << ": "
            << html_escape(event.event_type) << "</li>";
    }
    out << "</ul></section>";
    return out.str();
}

std::string render_bandwidth_csv(const netsentinel::bandwidth::BandwidthAnomalyReport& anomalies) {
    std::ostringstream out;
    out << "section,device_id,rx_bytes,tx_bytes,total_bytes,confidence,source,measurement_note\n";
    for (const auto& talker : anomalies.top_talkers) {
        const auto estimated = talker.confidence == "low" || talker.confidence == "network-only";
        out << "top_talker,"
            << csv_escape(talker.device_id) << ","
            << talker.rx_bytes << ","
            << talker.tx_bytes << ","
            << talker.total_bytes << ","
            << csv_escape(talker.confidence) << ","
            << "mock-bandwidth-attribution,"
            << csv_escape(estimated ? "estimated-or-incomplete" : "measured-or-attributed")
            << "\n";
    }
    out << "\nalert_id,device_id,kind,severity,explanation,malware_claim\n";
    for (const auto& alert : anomalies.alerts) {
        out << csv_escape(alert.alert_id) << ","
            << csv_escape(alert.device_id) << ","
            << csv_escape(alert.kind) << ","
            << csv_escape(alert.severity) << ","
            << csv_escape(alert.explanation) << ","
            << (alert.malware_claim ? "true" : "false") << "\n";
    }
    return out.str();
}

std::string render_bandwidth_json(const netsentinel::bandwidth::BandwidthAnomalyReport& anomalies) {
    std::string out = "{\"report\":\"bandwidth\",";
    out += "\"active_source\":\"mock-bandwidth-attribution\",";
    out += "\"limitations\":[\"mock data only\",\"source confidence is shown so estimated data is not presented as measured\",\"no live network traffic is generated\"],";
    out += "\"top_talkers\":[";
    for (std::size_t i = 0; i < anomalies.top_talkers.size(); ++i) {
        const auto& talker = anomalies.top_talkers[i];
        if (i > 0) {
            out += ",";
        }
        const auto estimated = talker.confidence == "low" || talker.confidence == "network-only";
        out += "{";
        out += "\"device_id\":" + json_string(talker.device_id) + ",";
        out += "\"rx_bytes\":" + std::to_string(talker.rx_bytes) + ",";
        out += "\"tx_bytes\":" + std::to_string(talker.tx_bytes) + ",";
        out += "\"total_bytes\":" + std::to_string(talker.total_bytes) + ",";
        out += "\"confidence\":" + json_string(talker.confidence) + ",";
        out += "\"measurement_note\":" + json_string(estimated ? "estimated-or-incomplete" : "measured-or-attributed");
        out += "}";
    }
    out += "],\"alerts\":[";
    for (std::size_t i = 0; i < anomalies.alerts.size(); ++i) {
        const auto& alert = anomalies.alerts[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"alert_id\":" + json_string(alert.alert_id) + ",";
        out += "\"device_id\":" + json_string(alert.device_id) + ",";
        out += "\"kind\":" + json_string(alert.kind) + ",";
        out += "\"severity\":" + json_string(alert.severity) + ",";
        out += "\"explanation\":" + json_string(alert.explanation) + ",";
        out += "\"malware_claim\":" + std::string(alert.malware_claim ? "true" : "false");
        out += "}";
    }
    out += "]}";
    return out;
}

std::string render_bandwidth_html(const netsentinel::bandwidth::BandwidthAnomalyReport& anomalies) {
    std::ostringstream out;
    out << "<section><h2>Bandwidth Report</h2>";
    out << "<p><strong>Active source:</strong> mock-bandwidth-attribution. "
        << "This sample uses deterministic mock data and sends no network traffic.</p>";
    out << "<p>Measurements distinguish measured or attributed data from estimated or incomplete data.</p>";
    out << "<table><thead><tr><th>Device</th><th>RX bytes</th><th>TX bytes</th><th>Total bytes</th><th>Confidence</th><th>Measurement note</th></tr></thead><tbody>";
    for (const auto& talker : anomalies.top_talkers) {
        const auto estimated = talker.confidence == "low" || talker.confidence == "network-only";
        out << "<tr><td>" << html_escape(talker.device_id)
            << "</td><td>" << talker.rx_bytes
            << "</td><td>" << talker.tx_bytes
            << "</td><td>" << talker.total_bytes
            << "</td><td>" << html_escape(talker.confidence)
            << "</td><td>" << (estimated ? "estimated or incomplete" : "measured or attributed")
            << "</td></tr>";
    }
    out << "</tbody></table>";
    out << "<h3>Alerts</h3><ul>";
    for (const auto& alert : anomalies.alerts) {
        out << "<li><strong>" << html_escape(alert.kind) << "</strong> "
            << html_escape(alert.device_id) << ": "
            << html_escape(alert.explanation)
            << " Malware claim: " << (alert.malware_claim ? "yes" : "no")
            << "</li>";
    }
    out << "</ul><h3>Limitations</h3><ul>"
        << "<li>Mock sample data only.</li>"
        << "<li>Source confidence is included so incomplete estimates are not misleading.</li>"
        << "<li>Router/capture support may be unavailable; empty states remain valid.</li>"
        << "</ul></section>";
    return out.str();
}

std::string wrap_html_report(const std::string& title, const std::string& body) {
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>" +
        html_escape(title) +
        "</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#14213d}table{border-collapse:collapse;width:100%}td,th{border:1px solid #d8dee9;padding:6px;text-align:left}section{margin-bottom:24px}</style></head><body><h1>" +
        html_escape(title) +
        "</h1>" + body + "</body></html>";
}

GeneratedReport make_failure(const ReportConfig& config, const std::string& message) {
    return {
        .success = false,
        .written = false,
        .report_type = normalize_report_type(config.report_type),
        .format = normalize_report_format(config.format),
        .output_path = config.output_path,
        .content = "",
        .warnings = {},
        .message = message
    };
}

} // namespace

GeneratedReport generate_report(const ReportConfig& config) {
    const auto report_type = normalize_report_type(config.report_type);
    const auto format = normalize_report_format(config.format);
    if (format != "csv" && format != "json" && format != "html") {
        return make_failure(config, "Unsupported report format. Use csv, json, or html.");
    }

    GeneratedReport report{};
    report.success = true;
    report.report_type = report_type;
    report.format = format;
    report.output_path = config.output_path;

    auto inventory = read_inventory(config, report.warnings);
    auto events = read_events(config, report.warnings);

    diagnostics::SecurityHealthCheckConfig security_config{};
    security_config.mock_mode = true;
    security_config.storage_db_path = config.storage.database_path;
    security_config.gateway = config.gateway;
    const auto security = diagnostics::run_security_health_check(security_config);
    if (!security.success) {
        report.warnings.push_back("security health check unavailable: " + security.message);
    }

    diagnostics::WifiScanConfig wifi_config{};
    wifi_config.mock_mode = true;
    wifi_config.include_hidden = true;
    const auto wifi = diagnostics::run_wifi_channel_analysis(wifi_config);
    if (!wifi.success) {
        report.warnings.push_back("wi-fi analysis unavailable: " + wifi.message);
    }

    if (report_type == "inventory") {
        if (format == "csv") {
            report.content = render_inventory_csv(inventory);
        } else if (format == "json") {
            report.content = render_inventory_json(inventory);
        } else {
            report.content = wrap_html_report("NetSentinel Inventory Report", render_inventory_html(inventory));
        }
    } else if (report_type == "security") {
        if (format == "csv") {
            report.content = security.success ? render_security_csv(security) : "component,penalty,max_penalty,status,detail\n";
        } else if (format == "json") {
            report.content = security.success ? render_security_json(security) : "{\"report\":\"security\",\"components\":[]}";
        } else {
            report.content = wrap_html_report("NetSentinel Security Assessment", security.success ? render_security_html(security) : "<section><h2>Security Assessment</h2><p>Unavailable</p></section>");
        }
    } else if (report_type == "wi-fi") {
        if (format == "csv") {
            report.content = wifi.success ? render_wifi_csv(wifi) : "metric,value\n";
        } else if (format == "json") {
            report.content = wifi.success ? render_wifi_json(wifi) : "{\"report\":\"wi-fi\"}";
        } else {
            report.content = wrap_html_report("NetSentinel Wi-Fi Environment", wifi.success ? render_wifi_html(wifi) : "<section><h2>Wi-Fi Environment</h2><p>Unavailable</p></section>");
        }
    } else if (report_type == "outage") {
        if (format == "csv") {
            report.content = render_events_csv(events, "outage");
        } else if (format == "json") {
            report.content = render_events_json(events, "outage");
        } else {
            report.content = wrap_html_report("NetSentinel Outage Report", render_events_html(events, "Outage and timeline events"));
        }
        report.warnings.push_back("Outage report currently uses local timeline events until persistent outage history is expanded.");
    } else if (report_type == "speed") {
        if (format == "csv") {
            report.content = "metric,value\nhistory_status,no persistent speed history yet\n";
        } else if (format == "json") {
            report.content = "{\"report\":\"speed\",\"history\":[],\"message\":\"persistent speed history is planned\"}";
        } else {
            report.content = wrap_html_report("NetSentinel Speed History", "<section><h2>Speed History</h2><p>No persistent speed history is available yet.</p></section>");
        }
        report.warnings.push_back("Speed history endpoint is prepared; persistence arrives in a later reporting/storage expansion.");
    } else if (report_type == "bandwidth") {
        const auto bandwidth = netsentinel::bandwidth::mock_bandwidth_anomaly_report();
        report.warnings.push_back("Bandwidth report uses deterministic mock data until live source orchestration is configured.");
        if (format == "csv") {
            report.content = render_bandwidth_csv(bandwidth);
        } else if (format == "json") {
            report.content = render_bandwidth_json(bandwidth);
        } else {
            report.content = wrap_html_report("NetSentinel Bandwidth Report", render_bandwidth_html(bandwidth));
        }
    } else if (report_type == "executive") {
        if (format == "csv") {
            std::ostringstream out;
            out << "metric,value\n";
            out << "device_count," << inventory.size() << "\n";
            out << "event_count," << events.size() << "\n";
            out << "security_score," << (security.success ? security.score : 0) << "\n";
            out << "wifi_networks," << (wifi.success ? wifi.total_networks : 0) << "\n";
            report.content = out.str();
        } else if (format == "json") {
            report.content = "{\"report\":\"executive\",\"device_count\":" + std::to_string(inventory.size()) +
                ",\"event_count\":" + std::to_string(events.size()) +
                ",\"security_score\":" + std::to_string(security.success ? security.score : 0) +
                ",\"wifi_networks\":" + std::to_string(wifi.success ? wifi.total_networks : 0) + "}";
        } else {
            std::ostringstream body;
            body << "<section><h2>Executive Summary</h2><p>Devices: " << inventory.size()
                 << "</p><p>Events: " << events.size()
                 << "</p><p>Security score: " << (security.success ? security.score : 0)
                 << "</p><p>Wi-Fi networks: " << (wifi.success ? wifi.total_networks : 0) << "</p></section>";
            body << render_inventory_html(inventory);
            if (security.success) {
                body << render_security_html(security);
            }
            if (wifi.success) {
                body << render_wifi_html(wifi);
            }
            report.content = wrap_html_report("NetSentinel Executive Summary", body.str());
        }
    } else {
        return make_failure(config, "Unsupported report type. Use inventory, security, outage, speed, wi-fi, bandwidth, or executive.");
    }

    report.message = "Report generated.";
    return report;
}

GeneratedReport write_report(const ReportConfig& config) {
    auto report = generate_report(config);
    if (!report.success) {
        return report;
    }
    if (config.output_path.empty()) {
        report.message = "Report generated without output file.";
        return report;
    }
    const auto path = std::filesystem::path{config.output_path};
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }
    std::ofstream out{path, std::ios::trunc};
    if (!out.is_open()) {
        report.success = false;
        report.message = "Could not open report output path.";
        return report;
    }
    out << report.content;
    report.written = true;
    report.message = "Report generated and written.";
    return report;
}

} // namespace netsentinel::reports
