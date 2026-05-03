#include "netsentinel/ui/gui_shell.h"

#include "netsentinel/diagnostics/diagnostic_tools.h"
#include "netsentinel/reports/report_generator.h"
#include "netsentinel/alerts/alert_router.h"
#include "netsentinel/api/local_rest_api.h"
#include "netsentinel/service/tray_service.h"
#include "netsentinel/speedtest/speed_test.h"
#include "netsentinel/bandwidth/bandwidth_source.h"
#include "netsentinel/engine/arp_discovery.h"
#include "netsentinel/engine/icmp_discovery.h"
#include "netsentinel/outage/outage_detector.h"

#include <algorithm>
#include <sstream>

namespace netsentinel::ui {

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

std::string default_gui_scan_scope() {
    return "192.168.50.0/24";
}

bool is_authorized_gui_scan_scope(const std::string& target) {
    return target == "192.168.50.0/24" ||
        target == "192.168.50.*" ||
        target.rfind("192.168.50.", 0) == 0 ||
        target == "192.168.1.0/24" ||
        target == "192.168.1.*" ||
        target.rfind("192.168.1.", 0) == 0 ||
        target == "localhost" ||
        target == "127.0.0.1" ||
        target.rfind("127.", 0) == 0;
}

std::string icon_for_device(const netsentinel::storage::DeviceInventoryRecord& device) {
    const auto blob = device.device_type + " " + device.vendor_hint + " " + device.hostname + " " + device.details;
    const auto contains = [&](const std::string& token) {
        return blob.find(token) != std::string::npos;
    };
    if (contains("router") || contains("gateway") || contains("OpenWrt")) {
        return "network-router";
    }
    if (contains("camera") || contains("rtsp") || contains("onvif")) {
        return "camera";
    }
    if (contains("printer")) {
        return "printer";
    }
    if (contains("phone") || contains("android") || contains("ios")) {
        return "phone";
    }
    if (contains("tv") || contains("chromecast")) {
        return "media";
    }
    if (contains("iot") || contains("smart")) {
        return "iot";
    }
    return "device";
}

std::string service_for_port(int port) {
    switch (port) {
        case 21:
            return "ftp";
        case 22:
            return "ssh";
        case 23:
            return "telnet";
        case 53:
            return "dns";
        case 80:
            return "http";
        case 443:
            return "https";
        case 445:
            return "smb";
        case 554:
        case 8554:
            return "rtsp";
        case 1900:
            return "upnp";
        case 3389:
            return "rdp";
        case 37777:
            return "camera-vendor";
        default:
            return "tcp-open";
    }
}

std::string status_badge_for_device(const netsentinel::storage::DeviceInventoryRecord& device) {
    if (device.hidden) {
        return "hidden";
    }
    if (device.stale) {
        return device.importance >= 70 ? "important-offline" : "offline";
    }
    if (device.device_type.empty() || device.device_type == "unknown") {
        return "unknown";
    }
    return "online";
}

bool text_contains(const std::string& text, const std::string& token) {
    return text.find(token) != std::string::npos;
}

int confidence_for_device(const netsentinel::storage::DeviceInventoryRecord& device) {
    int confidence = 25;
    if (!device.hostname.empty()) {
        confidence += 15;
    }
    if (!device.vendor_hint.empty()) {
        confidence += 20;
    }
    if (!device.device_type.empty() && device.device_type != "unknown") {
        confidence += 25;
    }
    if (!device.open_tcp_ports.empty()) {
        confidence += 10;
    }
    if (!device.user_labels.empty()) {
        confidence += 5;
    }
    return std::min(100, confidence);
}

GuiDeviceRow make_device_row(const netsentinel::storage::DeviceSearchResult& result) {
    const auto& device = result.device;
    return {
        .device_id = device.device_id,
        .hostname = device.hostname,
        .primary_ip = device.ip_addresses.empty() ? std::string{} : device.ip_addresses.front(),
        .vendor = device.vendor_hint,
        .device_type = device.device_type.empty() ? std::string{"unknown"} : device.device_type,
        .icon = icon_for_device(device),
        .status_badge = status_badge_for_device(device),
        .network_id = result.network_id,
        .importance = device.importance,
        .confidence_percent = confidence_for_device(device),
        .labels = device.user_labels,
        .matched_reasons = result.matched_reasons
    };
}

void add_view(
    std::vector<GuiViewSummary>& views,
    const std::string& id,
    const std::string& title,
    const std::string& description,
    const std::string& badge,
    bool enabled = true
) {
    views.push_back({
        .id = id,
        .title = title,
        .description = description,
        .badge = badge,
        .enabled = enabled
    });
}

} // namespace

GuiShellModel build_gui_shell_model(const GuiShellConfig& config) {
    GuiShellModel model{};
    model.qt_available = NETSENTINEL_UI_HAS_QT != 0;
    model.demo_mode = config.demo_mode;
    model.visual_direction = "Windows 11 polished shell with calm blue-gray surfaces, crisp cards, status badges, and safety-first confirmation flows.";

    const auto devices = netsentinel::storage::list_inventory_records(config.storage, true);
    const auto events = netsentinel::storage::list_timeline_records(config.storage);
    const auto workspaces = netsentinel::storage::list_network_workspaces(config.storage);
    const auto filters = netsentinel::storage::list_filter_templates(config.storage);

    std::size_t device_count = 0;
    std::size_t event_count = 0;
    std::size_t workspace_count = 0;
    std::size_t filter_count = 0;

    if (devices) {
        device_count = devices.value().size();
    } else {
        model.warnings.push_back("Device inventory could not be loaded.");
    }
    if (events) {
        event_count = events.value().size();
    } else {
        model.warnings.push_back("Timeline events could not be loaded.");
    }
    if (workspaces) {
        workspace_count = workspaces.value().size();
    } else {
        model.warnings.push_back("Network workspaces could not be loaded.");
    }
    if (filters) {
        filter_count = filters.value().size();
    } else {
        model.warnings.push_back("Saved filters could not be loaded.");
    }

    diagnostics::SecurityHealthCheckConfig security_config{};
    security_config.mock_mode = true;
    security_config.storage_db_path = config.storage.database_path;
    security_config.gateway = config.gateway;
    const auto security = diagnostics::run_security_health_check(security_config);
    if (!security.success) {
        model.warnings.push_back("Security health summary unavailable: " + security.message);
    }

    diagnostics::WifiScanConfig wifi_config{};
    wifi_config.mock_mode = true;
    wifi_config.include_hidden = true;
    const auto wifi = diagnostics::run_wifi_channel_analysis(wifi_config);
    if (!wifi.success) {
        model.warnings.push_back("Wi-Fi summary unavailable: " + wifi.message);
    }

    reports::ReportConfig report_config{};
    report_config.report_type = "executive";
    report_config.format = "html";
    report_config.storage = config.storage;
    const auto report = reports::generate_report(report_config);
    if (!report.success) {
        model.warnings.push_back("Executive report preview unavailable: " + report.message);
    }

    if (config.demo_mode && device_count == 0) {
        device_count = 4;
        event_count = 9;
        workspace_count = 2;
        filter_count = 3;
    }

    add_view(model.views, "dashboard", "Dashboard", "At-a-glance network health, active workspace, security score, and recent events.", std::to_string(workspace_count) + " workspace(s)");
    add_view(model.views, "bandwidth", "Bandwidth", "Per-device bandwidth, top talkers, source confidence, and measured-vs-estimated history charts.", "source-aware");
    add_view(model.views, "devices", "Devices", "Searchable device inventory with identity, vendor, type, and status badges.", std::to_string(device_count) + " device(s)");
    add_view(model.views, "device-details", "Device Details", "Selected-device profile with protocol observations, labels, importance, and history.", device_count == 0 ? "select a device" : "ready");
    add_view(model.views, "timeline", "Timeline", "Cross-network event stream for joins, leaves, changes, and findings.", std::to_string(event_count) + " event(s)");
    add_view(model.views, "security", "Security", "Router exposure, security score, camera heuristics, and safe control actions.", security.success ? ("score " + std::to_string(security.score)) : "unavailable");
    add_view(model.views, "diagnostics", "Diagnostics", "Ping, traceroute, DNS, DHCP, ports, outage, and troubleshooting tools.", "mock-safe tools");
    add_view(model.views, "wi-fi", "Wi-Fi", "Nearby Wi-Fi scan, channel quality, security warnings, and environment analysis.", wifi.success ? (std::to_string(wifi.total_networks) + " network(s)") : "unavailable");
    add_view(model.views, "reports", "Reports", "CSV, JSON, and HTML exports for inventory, security, Wi-Fi, speed, outage, and executive summaries.", report.success ? "templates ready" : "unavailable");
    add_view(model.views, "settings", "Settings", "Local API, workspaces, monitoring limits, privacy, low-resource mode, and update preferences.", std::to_string(filter_count) + " filter(s)");

    model.message = model.qt_available
        ? "Qt 6 GUI shell model is ready and native Qt build support is available."
        : "Qt 6 GUI shell model is ready; native Qt executable is skipped because Qt 6 Widgets is not installed.";
    return model;
}

GuiBandwidthDashboardModel build_gui_bandwidth_dashboard_model(const GuiBandwidthDashboardConfig& config) {
    GuiBandwidthDashboardModel model{};
    model.success = true;

    if (!config.demo_mode && !config.mock_mode) {
        model.empty_state = true;
        model.active_source = "none configured";
        model.source_limitations = {
            "No router plugin, capture source, or stored bandwidth history is configured for this dashboard yet.",
            "Use demo/mock mode to preview the dashboard without network traffic.",
            "Measured and estimated data will be separated once real bandwidth sources are configured."
        };
        model.source_confidence_summary = {
            "No active source.",
            "Dashboard is ready but has no samples to chart."
        };
        model.message = "Bandwidth dashboard empty state: configure a source or run demo/mock preview.";
        return model;
    }

    model.active_source = config.mock_mode ? "mock bandwidth attribution engine" : "demo bandwidth attribution engine";
    model.source_limitations = {
        "Demo/mock data is deterministic and does not send network traffic.",
        "Low-confidence rows are shown as estimated or incomplete.",
        "UPnP aggregate-only data is not claimed as per-device precision."
    };
    model.source_confidence_summary = {
        "exact/high: router or flow metadata with strong device identity.",
        "medium/low: useful but incomplete or partially inferred.",
        "local-host-only: measured on this Windows PC only, not full-network traffic."
    };

    const auto samples = netsentinel::bandwidth::mock_bandwidth_attribution_samples();
    netsentinel::bandwidth::BandwidthAttributionMergeConfig merge_config{};
    merge_config.elapsed_seconds = 30.0;
    const auto attribution = netsentinel::bandwidth::attribute_bandwidth_per_device(samples, merge_config);
    const auto anomalies = netsentinel::bandwidth::mock_bandwidth_anomaly_report();

    for (const auto& talker : anomalies.top_talkers) {
        GuiBandwidthTopTalkerRow row{};
        row.device_id = talker.device_id;
        row.display_name = talker.device_id;
        row.confidence = talker.confidence;
        row.source_label = "attribution-engine";
        row.rx_bytes = talker.rx_bytes;
        row.tx_bytes = talker.tx_bytes;
        row.total_bytes = talker.total_bytes;
        row.incomplete_or_estimated = talker.confidence == "low" || talker.confidence == "network-only";
        model.top_talkers.push_back(std::move(row));
    }

    const std::vector<std::string> timestamps{
        "2026-05-02T16:00:00Z",
        "2026-05-02T16:05:00Z",
        "2026-05-02T16:10:00Z",
        "2026-05-02T16:15:00Z"
    };
    for (const auto& device : attribution.devices) {
        const auto measurement_kind =
            (device.confidence == "exact" || device.confidence == "high" || device.confidence == "local-host-only")
                ? std::string{"measured"}
                : std::string{"estimated-or-incomplete"};
        for (std::size_t i = 0; i < timestamps.size(); ++i) {
            const auto divisor = static_cast<std::uint64_t>(timestamps.size() - i);
            model.history_chart.push_back({
                .timestamp_utc = timestamps[i],
                .device_id = device.device_key,
                .rx_bytes = divisor == 0 ? device.rx_bytes : device.rx_bytes / divisor,
                .tx_bytes = divisor == 0 ? device.tx_bytes : device.tx_bytes / divisor,
                .measurement_kind = measurement_kind
            });
        }
    }

    for (const auto& alert : anomalies.alerts) {
        model.alerts.push_back(
            alert.kind + " on " + alert.device_id + ": " + alert.explanation
        );
    }

    model.empty_state = model.top_talkers.empty();
    model.message = model.empty_state
        ? "Bandwidth dashboard has no samples."
        : "Bandwidth dashboard model populated with top talkers, confidence, charts, and explainable alerts.";
    return model;
}

std::string gui_bandwidth_dashboard_json(const GuiBandwidthDashboardModel& model) {
    std::string out = "{";
    out += "\"success\":" + std::string(model.success ? "true" : "false") + ",";
    out += "\"empty_state\":" + std::string(model.empty_state ? "true" : "false") + ",";
    out += "\"active_source\":" + json_string(model.active_source) + ",";
    out += "\"message\":" + json_string(model.message) + ",";
    out += "\"source_limitations\":" + json_string_array(model.source_limitations) + ",";
    out += "\"source_confidence_summary\":" + json_string_array(model.source_confidence_summary) + ",";
    out += "\"top_talkers\":[";
    for (std::size_t i = 0; i < model.top_talkers.size(); ++i) {
        const auto& row = model.top_talkers[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"device_id\":" + json_string(row.device_id) + ",";
        out += "\"display_name\":" + json_string(row.display_name) + ",";
        out += "\"confidence\":" + json_string(row.confidence) + ",";
        out += "\"source_label\":" + json_string(row.source_label) + ",";
        out += "\"rx_bytes\":" + std::to_string(row.rx_bytes) + ",";
        out += "\"tx_bytes\":" + std::to_string(row.tx_bytes) + ",";
        out += "\"total_bytes\":" + std::to_string(row.total_bytes) + ",";
        out += "\"incomplete_or_estimated\":" + std::string(row.incomplete_or_estimated ? "true" : "false");
        out += "}";
    }
    out += "],\"history_chart\":[";
    for (std::size_t i = 0; i < model.history_chart.size(); ++i) {
        const auto& point = model.history_chart[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"timestamp_utc\":" + json_string(point.timestamp_utc) + ",";
        out += "\"device_id\":" + json_string(point.device_id) + ",";
        out += "\"rx_bytes\":" + std::to_string(point.rx_bytes) + ",";
        out += "\"tx_bytes\":" + std::to_string(point.tx_bytes) + ",";
        out += "\"measurement_kind\":" + json_string(point.measurement_kind);
        out += "}";
    }
    out += "],\"alerts\":" + json_string_array(model.alerts);
    out += "}";
    return out;
}

std::string gui_shell_model_json(const GuiShellModel& model) {
    std::string out = "{";
    out += "\"qt_available\":" + std::string(model.qt_available ? "true" : "false") + ",";
    out += "\"demo_mode\":" + std::string(model.demo_mode ? "true" : "false") + ",";
    out += "\"visual_direction\":" + json_string(model.visual_direction) + ",";
    out += "\"message\":" + json_string(model.message) + ",";
    out += "\"views\":[";
    for (std::size_t i = 0; i < model.views.size(); ++i) {
        const auto& view = model.views[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"id\":" + json_string(view.id) + ",";
        out += "\"title\":" + json_string(view.title) + ",";
        out += "\"description\":" + json_string(view.description) + ",";
        out += "\"badge\":" + json_string(view.badge) + ",";
        out += "\"enabled\":" + std::string(view.enabled ? "true" : "false");
        out += "}";
    }
    out += "],\"warnings\":[";
    for (std::size_t i = 0; i < model.warnings.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        out += json_string(model.warnings[i]);
    }
    out += "]}";
    return out;
}

GuiDeviceListModel build_gui_device_list_model(const GuiDeviceListConfig& config) {
    netsentinel::storage::DeviceSearchQuery query{};
    query.preset = config.preset.empty() ? std::string{"all"} : config.preset;
    query.text = config.search_text;
    query.vendor = config.vendor;
    query.network_id = config.network_id;
    query.include_hidden = config.include_hidden;

    GuiDeviceListModel model{};
    model.sort_by = config.sort_by.empty() ? std::string{"relevance"} : config.sort_by;
    model.available_filters = {
        "all",
        "unknown",
        "new-24h",
        "cameras",
        "routers",
        "iot",
        "risky-ports",
        "offline-important",
        "security-findings"
    };

    const auto results = netsentinel::storage::search_inventory_devices(query, config.storage);
    if (!results) {
        model.message = "Device search failed: " + results.error().user_message;
        return model;
    }

    for (const auto& result : results.value()) {
        model.rows.push_back(make_device_row(result));
    }

    if (model.sort_by == "hostname") {
        std::sort(model.rows.begin(), model.rows.end(), [](const GuiDeviceRow& lhs, const GuiDeviceRow& rhs) {
            return lhs.hostname < rhs.hostname;
        });
    } else if (model.sort_by == "vendor") {
        std::sort(model.rows.begin(), model.rows.end(), [](const GuiDeviceRow& lhs, const GuiDeviceRow& rhs) {
            return lhs.vendor < rhs.vendor;
        });
    } else if (model.sort_by == "importance") {
        std::sort(model.rows.begin(), model.rows.end(), [](const GuiDeviceRow& lhs, const GuiDeviceRow& rhs) {
            return lhs.importance > rhs.importance;
        });
    } else if (model.sort_by == "status") {
        std::sort(model.rows.begin(), model.rows.end(), [](const GuiDeviceRow& lhs, const GuiDeviceRow& rhs) {
            return lhs.status_badge < rhs.status_badge;
        });
    }

    model.message = "GUI device list populated from storage/search APIs.";
    return model;
}

GuiDeviceDetail build_gui_device_detail_model(
    const netsentinel::storage::StorageConfig& storage,
    const std::string& device_id
) {
    GuiDeviceDetail detail{};
    const auto device = netsentinel::storage::get_inventory_record(device_id, storage);
    if (!device) {
        detail.found = false;
        detail.message = "Device not found: " + device_id;
        return detail;
    }

    netsentinel::storage::DeviceSearchResult search_result{};
    search_result.device = device.value();
    search_result.matched_reasons = {"selected-device"};
    detail.summary = make_device_row(search_result);
    detail.found = true;
    detail.manual_labels = device.value().user_labels;

    for (const auto port : device.value().open_tcp_ports) {
        const auto service = service_for_port(port);
        detail.protocols.push_back({
            .port = port,
            .protocol = "tcp",
            .service = service,
            .confidence = service == "tcp-open" ? "port-only" : "well-known-port"
        });
    }
    if (detail.protocols.empty()) {
        const auto metadata = device.value().details + " " + device.value().device_type + " " + device.value().hostname;
        if (text_contains(metadata, "onvif") || text_contains(metadata, "camera")) {
            detail.protocols.push_back({
                .port = 80,
                .protocol = "tcp",
                .service = "http/onvif",
                .confidence = "metadata-inferred"
            });
        }
        if (text_contains(metadata, "rtsp")) {
            detail.protocols.push_back({
                .port = 554,
                .protocol = "tcp",
                .service = "rtsp",
                .confidence = "metadata-inferred"
            });
        }
    }

    detail.confidence_explanations.push_back("Identity confidence starts from observed inventory fields.");
    if (!device.value().hostname.empty()) {
        detail.confidence_explanations.push_back("Hostname is present.");
    }
    if (!device.value().vendor_hint.empty()) {
        detail.confidence_explanations.push_back("Vendor hint is present.");
    }
    if (!device.value().device_type.empty() && device.value().device_type != "unknown") {
        detail.confidence_explanations.push_back("Manual or inferred device type is present.");
    }
    if (!device.value().open_tcp_ports.empty()) {
        detail.confidence_explanations.push_back("Protocol observations are available from open port metadata.");
    }
    if (!device.value().user_labels.empty()) {
        detail.confidence_explanations.push_back("Manual labels improve operator confidence.");
    }

    netsentinel::storage::TimelineFilter filter{};
    filter.device_id = device_id;
    const auto history = netsentinel::storage::list_timeline_records(storage, filter);
    if (history) {
        detail.history = history.value();
    }
    detail.message = "GUI device detail populated from inventory and timeline APIs.";
    return detail;
}

std::string gui_device_list_model_json(const GuiDeviceListModel& model) {
    std::string out = "{";
    out += "\"sort_by\":" + json_string(model.sort_by) + ",";
    out += "\"message\":" + json_string(model.message) + ",";
    out += "\"available_filters\":" + json_string_array(model.available_filters) + ",";
    out += "\"rows\":[";
    for (std::size_t i = 0; i < model.rows.size(); ++i) {
        const auto& row = model.rows[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"device_id\":" + json_string(row.device_id) + ",";
        out += "\"hostname\":" + json_string(row.hostname) + ",";
        out += "\"primary_ip\":" + json_string(row.primary_ip) + ",";
        out += "\"vendor\":" + json_string(row.vendor) + ",";
        out += "\"device_type\":" + json_string(row.device_type) + ",";
        out += "\"icon\":" + json_string(row.icon) + ",";
        out += "\"status_badge\":" + json_string(row.status_badge) + ",";
        out += "\"network_id\":" + json_string(row.network_id) + ",";
        out += "\"importance\":" + std::to_string(row.importance) + ",";
        out += "\"confidence_percent\":" + std::to_string(row.confidence_percent) + ",";
        out += "\"labels\":" + json_string_array(row.labels) + ",";
        out += "\"matched_reasons\":" + json_string_array(row.matched_reasons);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string gui_device_detail_json(const GuiDeviceDetail& detail) {
    std::string out = "{";
    out += "\"found\":" + std::string(detail.found ? "true" : "false") + ",";
    out += "\"message\":" + json_string(detail.message) + ",";
    out += "\"summary\":{";
    out += "\"device_id\":" + json_string(detail.summary.device_id) + ",";
    out += "\"hostname\":" + json_string(detail.summary.hostname) + ",";
    out += "\"icon\":" + json_string(detail.summary.icon) + ",";
    out += "\"status_badge\":" + json_string(detail.summary.status_badge) + ",";
    out += "\"confidence_percent\":" + std::to_string(detail.summary.confidence_percent);
    out += "},\"protocols\":[";
    for (std::size_t i = 0; i < detail.protocols.size(); ++i) {
        const auto& protocol = detail.protocols[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"port\":" + std::to_string(protocol.port) + ",";
        out += "\"protocol\":" + json_string(protocol.protocol) + ",";
        out += "\"service\":" + json_string(protocol.service) + ",";
        out += "\"confidence\":" + json_string(protocol.confidence);
        out += "}";
    }
    out += "],\"confidence_explanations\":" + json_string_array(detail.confidence_explanations) + ",";
    out += "\"manual_labels\":" + json_string_array(detail.manual_labels) + ",";
    out += "\"history_count\":" + std::to_string(detail.history.size());
    out += "}";
    return out;
}

void add_progress(GuiActionResult& result, const std::string& stage, int percent, const std::string& state) {
    result.progress.push_back({
        .stage = stage,
        .percent = percent,
        .state = state
    });
}

std::vector<GuiActionDescriptor> build_gui_action_catalog() {
    return {
        {
            .id = "monitoring.start",
            .title = "Start monitoring",
            .area = "Monitoring",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Starts the local background monitoring controller in mock-safe mode unless real service orchestration is enabled later."
        },
        {
            .id = "monitoring.stop",
            .title = "Stop monitoring",
            .area = "Monitoring",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Stops the local monitoring controller."
        },
        {
            .id = "alert.test",
            .title = "Send test alert",
            .area = "Alerts",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Routes a mock-safe alert through the configured alert router."
        },
        {
            .id = "diagnostics.ping",
            .title = "Run ping diagnostic",
            .area = "Diagnostics",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Runs a mock-safe ping diagnostic for the selected target."
        },
        {
            .id = "diagnostics.traceroute",
            .title = "Run traceroute diagnostic",
            .area = "Diagnostics",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Runs the traceroute workflow in mock-safe mode until live traceroute is enabled."
        },
        {
            .id = "diagnostics.dns",
            .title = "Run DNS lookup",
            .area = "Diagnostics",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Runs the DNS lookup workflow in mock-safe mode until live DNS diagnostics are enabled."
        },
        {
            .id = "diagnostics.dhcp",
            .title = "Run DHCP check",
            .area = "Diagnostics",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Checks DHCP workflow output through the diagnostics layer."
        },
        {
            .id = "diagnostics.service",
            .title = "Identify local services",
            .area = "Diagnostics",
            .requires_confirmation = true,
            .dry_run_supported = true,
            .description = "Runs safe service identification against authorized local LAN targets only."
        },
        {
            .id = "diagnostics.wifi",
            .title = "Analyze Wi-Fi",
            .area = "Wi-Fi",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Runs Wi-Fi environment analysis through the diagnostics layer."
        },
        {
            .id = "speed.run",
            .title = "Run speed test",
            .area = "Speed",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Runs the speed-test module in mock-safe mode by default."
        },
        {
            .id = "report.generate",
            .title = "Generate report",
            .area = "Reports",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Generates a CSV, JSON, or HTML report preview."
        },
        {
            .id = "api.status",
            .title = "Check local API settings",
            .area = "Settings",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Validates localhost binding and token-auth settings for the local REST API."
        },
        {
            .id = "scan.trigger",
            .title = "Trigger scan",
            .area = "Diagnostics",
            .requires_confirmation = true,
            .dry_run_supported = true,
            .description = "Runs safe desktop discovery on authorized local LAN scopes after explicit confirmation."
        },
        {
            .id = "security.control",
            .title = "Safe internet control",
            .area = "Security",
            .requires_confirmation = true,
            .dry_run_supported = true,
            .description = "Plans or confirms safe control actions through advisory/local-firewall/router-plugin abstractions."
        },
        {
            .id = "outage.check",
            .title = "Check outage status",
            .area = "Diagnostics",
            .requires_confirmation = false,
            .dry_run_supported = true,
            .description = "Runs the outage workflow in mock-safe mode until live outage checks are enabled."
        }
    };
}

bool action_requires_confirmation(const std::string& action_id) {
    for (const auto& action : build_gui_action_catalog()) {
        if (action.id == action_id) {
            return action.requires_confirmation;
        }
    }
    return false;
}

GuiActionResult run_gui_action(const GuiActionRequest& request) {
    GuiActionResult result{};
    result.action_id = request.action_id;
    add_progress(result, "queued", 0, "pending");

    const bool needs_confirmation = action_requires_confirmation(request.action_id) && !request.dry_run;
    if (needs_confirmation && !request.confirmed) {
        result.success = false;
        result.requires_confirmation = true;
        result.severity = "warning";
        result.message = "Confirmation required before running this non-dry-run GUI action.";
        add_progress(result, "confirmation", 10, "blocked");
        return result;
    }

    add_progress(result, "started", 25, "running");

    if (request.action_id == "monitoring.start") {
        netsentinel::service::TrayMonitorConfig config{};
        config.mock_mode = request.mock_mode;
        config.scope = request.target.empty() ? std::string{"192.168.50.0/24"} : request.target;
        const auto op = netsentinel::service::start_tray_monitoring(config, request.mock_mode);
        result.success = op.success;
        result.output = op.message;
        result.message = op.success ? "Monitoring start action completed." : "Monitoring start action failed.";
    } else if (request.action_id == "monitoring.stop") {
        const auto op = netsentinel::service::stop_tray_monitoring(request.mock_mode);
        result.success = op.success;
        result.output = op.message;
        result.message = op.success ? "Monitoring stop action completed." : "Monitoring stop action failed.";
    } else if (request.action_id == "alert.test") {
        netsentinel::alerts::AlertRoutingConfig config{};
        config.mock_mode = request.mock_mode;
        config.enable_toast = true;
        netsentinel::alerts::AlertEvent event{};
        event.kind = netsentinel::alerts::AlertKind::security_finding;
        event.target_id = request.target.empty() ? "gui" : request.target;
        event.message = "GUI test alert";
        const auto op = netsentinel::alerts::send_alert(config, event);
        result.success = op.success;
        result.output = op.message;
        result.message = op.success ? "Alert test action completed." : "Alert test action failed.";
    } else if (request.action_id == "diagnostics.ping") {
        diagnostics::PingConfig config{};
        config.mock_mode = request.mock_mode;
        config.target = request.target.empty() ? std::string{"127.0.0.1"} : request.target;
        const auto op = diagnostics::run_ping(config);
        result.success = op.success;
        result.output = op.result.message;
        result.message = op.message;
    } else if (request.action_id == "diagnostics.traceroute") {
        diagnostics::TracerouteConfig config{};
        config.mock_mode = request.mock_mode;
        config.destination = request.target.empty() ? std::string{"192.168.50.1"} : request.target;
        config.max_hops = 8;
        const auto op = diagnostics::run_traceroute(config);
        result.success = op.success;
        result.output = "hops=" + std::to_string(op.result.hops.size()) +
            ", reached=" + std::string(op.result.destination_reached ? "true" : "false") +
            ", mode=" + std::string(config.mock_mode ? "mock-safe" : "live-local-traceroute");
        result.message = op.message;
    } else if (request.action_id == "diagnostics.dns") {
        diagnostics::DnsLookupConfig config{};
        config.mock_mode = request.mock_mode;
        config.target = request.target.empty() ? std::string{"localhost"} : request.target;
        config.resolver = "192.168.50.1";
        config.max_records = 5;
        const auto op = diagnostics::run_dns_lookup(config);
        result.success = op.success;
        result.output = "resolved=" + std::string(op.result.resolved ? "true" : "false") +
            ", answers=" + std::to_string(op.result.answers.size()) +
            ", mode=" + std::string(config.mock_mode ? "mock-safe" : "live-windows-resolver");
        result.message = op.message;
    } else if (request.action_id == "diagnostics.dhcp") {
        diagnostics::DhcpDiscoveryConfig config{};
        config.mock_mode = request.mock_mode;
        config.allow_multiple_reply_check = true;
        const auto op = diagnostics::run_dhcp_discovery(config);
        result.success = op.success;
        result.output = "adapters=" + std::to_string(op.adapters.size()) +
            ", multiple_reply=" + std::string(op.multiple_reply_detected ? "true" : "false") +
            ", mode=" + std::string(config.mock_mode ? "mock-safe" : "live-windows-adapter-data");
        result.message = op.message;
    } else if (request.action_id == "diagnostics.service") {
        const std::string target = request.target.empty() ? std::string{"192.168.50.1"} : request.target;
        if (!request.mock_mode && !request.dry_run && !is_authorized_gui_scan_scope(target)) {
            result.success = false;
            result.severity = "warning";
            result.output = "{\"ok\":false,\"accepted\":false,\"error\":\"service target is not in the authorized local LAN allow-list\"}";
            result.message = "Blocked service identification outside authorized local LAN scope.";
        } else {
            diagnostics::PortScanConfig config{};
            config.mock_mode = request.mock_mode || request.dry_run;
            config.targets = {target};
            config.concurrency = 2;
            config.banner = false;
            const auto op = diagnostics::run_service_identification(config, "top", {});
            result.success = op.success;
            result.output = "{\"ok\":" + std::string(op.success ? "true" : "false") +
                ",\"target\":" + json_string(target) +
                ",\"dry_run\":" + std::string(config.mock_mode ? "true" : "false") +
                ",\"observations\":" + std::to_string(op.observations.size()) +
                ",\"hints\":" + std::to_string(op.device_hints.size()) + "}";
            result.message = op.message;
        }
    } else if (request.action_id == "diagnostics.wifi") {
        diagnostics::WifiScanConfig config{};
        config.mock_mode = request.mock_mode;
        config.include_hidden = true;
        const auto op = diagnostics::run_wifi_channel_analysis(config);
        result.success = op.success;
        result.output = "networks=" + std::to_string(op.total_networks) + ", insecure=" + std::to_string(op.insecure_network_count);
        result.message = op.message;
    } else if (request.action_id == "speed.run") {
        netsentinel::speedtest::SpeedTestConfig config{};
        config.mock_mode = request.mock_mode;
        const auto op = netsentinel::speedtest::run_speed_test(config);
        result.success = op.success;
        result.output = op.message;
        result.message = op.success ? "Speed test action completed." : "Speed test action failed.";
    } else if (request.action_id == "report.generate") {
        reports::ReportConfig config{};
        config.storage = request.storage;
        config.report_type = request.report_type;
        config.format = request.report_format;
        const auto report = reports::generate_report(config);
        result.success = report.success;
        result.output = report.content.substr(0, 256);
        result.message = report.message;
    } else if (request.action_id == "api.status") {
        netsentinel::api::LocalRestApiConfig config{};
        config.enabled = true;
        config.auth_token = request.api_token;
        config.storage = request.storage;
        const auto status = netsentinel::api::validate_local_rest_api_config(config);
        result.success = status.valid;
        result.output = status.message;
        result.message = status.message;
    } else if (request.action_id == "scan.trigger") {
        const std::string scope = request.target.empty() ? default_gui_scan_scope() : request.target;
        if (request.dry_run) {
            netsentinel::api::LocalRestApiConfig config{};
            config.enabled = true;
            config.auth_token = request.api_token;
            config.csrf_token = "netsentinel-gui-local-csrf";
            config.permissions = {"read", "scan:trigger"};
            config.dry_run = true;
            config.storage = request.storage;
            netsentinel::api::LocalRestApiRequest api_request{};
            api_request.method = "POST";
            api_request.path = "/v1/scans/trigger";
            api_request.bearer_token = request.api_token;
            api_request.csrf_token = config.csrf_token;
            const auto response = netsentinel::api::handle_local_rest_api_request(config, api_request);
            result.success = response.status_code >= 200 && response.status_code < 300;
            result.output = response.body;
            result.message = result.success ? "Scan trigger action accepted as dry-run." : "Scan trigger action failed.";
        } else if (!is_authorized_gui_scan_scope(scope)) {
            result.success = false;
            result.severity = "warning";
            result.output = "{\"ok\":false,\"accepted\":false,\"error\":\"scope is not in the authorized local LAN allow-list\"}";
            result.message = "Blocked scan trigger outside authorized local LAN scope.";
        } else {
            netsentinel::engine::ArpDiscoveryRequest arp_request{};
            arp_request.cidr_or_range = scope;
            arp_request.max_host_count = 256;
            arp_request.only_local = true;
            arp_request.mock_mode = request.mock_mode;

            const auto arp = netsentinel::engine::discover_arp_devices(arp_request);
            if (arp.failed()) {
                result.success = false;
                result.severity = "warning";
                result.output = "{\"ok\":false,\"accepted\":false,\"error\":" + json_string(arp.error().user_message) + "}";
                result.message = "Safe LAN discovery failed before completion.";
            } else {
                const auto icmp = netsentinel::engine::discover_icmp_hosts(scope, request.mock_mode, 8, false);
                const bool icmp_ok = icmp.valid();
                std::size_t icmp_reachable = 0;
                if (icmp_ok) {
                    for (const auto& host : icmp.value()) {
                        if (host.ping_ok) {
                            ++icmp_reachable;
                        }
                    }
                }
                result.success = true;
                result.output = std::string{"{\"ok\":true,\"accepted\":true,\"dry_run\":false,\"scope\":"} +
                    json_string(scope) +
                    ",\"arp_count\":" + std::to_string(arp.value().size()) +
                    ",\"icmp_reachable_count\":" + std::to_string(icmp_reachable) +
                    ",\"icmp_probed_count\":" + std::to_string(icmp_ok ? icmp.value().size() : 0) +
                    ",\"methods\":[\"ARP\",\"ICMP\"]," +
                    "\"safety\":\"authorized LAN only; no exploit, brute force, MITM, spoofing, deauth, or stealth behavior\"}";
                result.message = "Safe LAN discovery completed from the GUI scan action.";
            }
        }
    } else if (request.action_id == "security.control") {
        diagnostics::InternetControlConfig config{};
        config.mock_mode = request.mock_mode;
        config.backend = "advisory";
        config.action = "block";
        config.target_ip = request.target.empty() ? std::string{"192.168.50.1"} : request.target;
        config.dry_run = request.dry_run;
        config.confirm = request.confirmed;
        const auto op = diagnostics::run_internet_control(config);
        result.success = op.success;
        result.requires_confirmation = op.confirm_required;
        result.output = op.message;
        result.message = op.success ? "Safe control action completed." : op.message;
    } else if (request.action_id == "outage.check") {
        netsentinel::outage::OutageCheckConfig config{};
        config.mock_mode = request.mock_mode;
        config.gateway_ip = request.target.empty() ? std::string{"192.168.50.1"} : request.target;
        config.dns_host = "localhost";
        config.external_url = "local-only";
        config.host_ip = (config.gateway_ip == "localhost" || config.gateway_ip.rfind("127.", 0) == 0)
            ? config.gateway_ip
            : std::string{"192.168.50.30"};
        const auto op = netsentinel::outage::run_outage_check(config);
        result.success = op.success;
        result.output = std::string{"classification="} + netsentinel::outage::to_string(op.result.classification) +
            ", outage=" + (op.result.outage_detected ? "true" : "false") +
            ", mode=" + (config.mock_mode ? "mock-safe" : "live-local-check");
        result.message = op.message;
    } else {
        result.success = false;
        result.severity = "error";
        result.message = "Unknown GUI action: " + request.action_id;
        result.errors.push_back(result.message);
    }

    add_progress(result, result.success ? "completed" : "failed", 100, result.success ? "ok" : "error");
    if (!result.success && result.errors.empty()) {
        result.errors.push_back(result.message);
    }
    return result;
}

std::string gui_action_result_json(const GuiActionResult& result) {
    std::string out = "{";
    out += "\"success\":" + std::string(result.success ? "true" : "false") + ",";
    out += "\"requires_confirmation\":" + std::string(result.requires_confirmation ? "true" : "false") + ",";
    out += "\"action_id\":" + json_string(result.action_id) + ",";
    out += "\"severity\":" + json_string(result.severity) + ",";
    out += "\"message\":" + json_string(result.message) + ",";
    out += "\"output\":" + json_string(result.output) + ",";
    out += "\"progress\":[";
    for (std::size_t i = 0; i < result.progress.size(); ++i) {
        const auto& item = result.progress[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"stage\":" + json_string(item.stage) + ",";
        out += "\"percent\":" + std::to_string(item.percent) + ",";
        out += "\"state\":" + json_string(item.state);
        out += "}";
    }
    out += "],\"errors\":" + json_string_array(result.errors);
    out += "}";
    return out;
}

GuiAccessibilityModel build_gui_accessibility_model(const GuiAccessibilityConfig& config) {
    GuiAccessibilityModel model{};
    model.success = true;
    model.language = config.language.empty() ? "en-US" : config.language;
    model.language_file = "i18n/" + model.language + ".txt";
    model.keyboard_navigation_ready = true;
    model.high_dpi_ready = true;
    model.screen_reader_labels_ready = config.screen_reader_mode;
    model.low_resource_mode = config.low_resource_mode;
    model.message = "Accessibility, localization, and low-resource checks are ready for GUI integration.";
    model.low_resource_scan = {
        .profile = "low-resource",
        .timeout_seconds = 12,
        .max_concurrency = 2,
        .max_qps = 4,
        .schedule_interval_minutes = 30,
        .enabled_probes = {"arp", "icmp"},
        .tcp_port_hints = {},
        .rationale = "Use fewer concurrent probes, lower QPS, longer intervals, and no default TCP fan-out on weak PCs or slow networks."
    };
    model.checks = {
        {
            .id = "keyboard.navigation",
            .title = "Keyboard navigation",
            .status = "pass",
            .details = "Dashboard, scan button, device list, device details, reports, and settings must be reachable by Tab/Shift+Tab with visible focus."
        },
        {
            .id = "screen.reader.labels",
            .title = "Screen-reader labels",
            .status = config.screen_reader_mode ? "pass" : "warning",
            .details = "Qt widgets should set accessible names for scan actions, device cards, severity badges, progress bars, and report actions."
        },
        {
            .id = "high.dpi",
            .title = "High-DPI behavior",
            .status = "pass",
            .details = "Use scalable layouts/icons, avoid fixed pixel-only layouts, and respect Windows display scaling."
        },
        {
            .id = "localization.structure",
            .title = "Localization structure",
            .status = "pass",
            .details = "Default English strings live under i18n/en-US.txt and future translations use the same keys."
        },
        {
            .id = "low.resource.scan",
            .title = "Low-resource scan settings",
            .status = config.low_resource_mode ? "active" : "available",
            .details = model.low_resource_scan.rationale
        }
    };
    if (config.high_contrast) {
        model.checks.push_back({
            .id = "contrast.high",
            .title = "High contrast",
            .status = "active",
            .details = "Use severity colors with text labels and high-contrast-safe borders, not color alone."
        });
    }
    if (model.language != "en-US") {
        model.warnings.push_back("Default English text is complete; requested language file structure is ready but translation coverage must be supplied.");
    }
    if (config.dpi_scale < 1.0) {
        model.warnings.push_back("DPI scale below 1.0 is unusual on Windows 11; GUI should clamp visual scale in the native layer.");
    }
    return model;
}

std::string gui_accessibility_model_json(const GuiAccessibilityModel& model) {
    std::string out = "{";
    out += "\"success\":" + std::string(model.success ? "true" : "false") + ",";
    out += "\"language\":" + json_string(model.language) + ",";
    out += "\"language_file\":" + json_string(model.language_file) + ",";
    out += "\"keyboard_navigation_ready\":" + std::string(model.keyboard_navigation_ready ? "true" : "false") + ",";
    out += "\"high_dpi_ready\":" + std::string(model.high_dpi_ready ? "true" : "false") + ",";
    out += "\"screen_reader_labels_ready\":" + std::string(model.screen_reader_labels_ready ? "true" : "false") + ",";
    out += "\"low_resource_mode\":" + std::string(model.low_resource_mode ? "true" : "false") + ",";
    out += "\"low_resource_scan\":{";
    out += "\"profile\":" + json_string(model.low_resource_scan.profile) + ",";
    out += "\"timeout_seconds\":" + std::to_string(model.low_resource_scan.timeout_seconds) + ",";
    out += "\"max_concurrency\":" + std::to_string(model.low_resource_scan.max_concurrency) + ",";
    out += "\"max_qps\":" + std::to_string(model.low_resource_scan.max_qps) + ",";
    out += "\"schedule_interval_minutes\":" + std::to_string(model.low_resource_scan.schedule_interval_minutes) + ",";
    out += "\"enabled_probes\":" + json_string_array(model.low_resource_scan.enabled_probes) + ",";
    out += "\"rationale\":" + json_string(model.low_resource_scan.rationale);
    out += "},\"checks\":[";
    for (std::size_t i = 0; i < model.checks.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        const auto& check = model.checks[i];
        out += "{";
        out += "\"id\":" + json_string(check.id) + ",";
        out += "\"title\":" + json_string(check.title) + ",";
        out += "\"status\":" + json_string(check.status) + ",";
        out += "\"details\":" + json_string(check.details);
        out += "}";
    }
    out += "],\"warnings\":" + json_string_array(model.warnings) + ",";
    out += "\"message\":" + json_string(model.message);
    out += "}";
    return out;
}

std::string gui_accessibility_model_markdown(const GuiAccessibilityModel& model) {
    std::ostringstream out;
    out << "# Accessibility, Localization, And Low Resource Mode\n\n";
    out << "- Language: " << model.language << "\n";
    out << "- Language file: " << model.language_file << "\n";
    out << "- Keyboard navigation ready: " << (model.keyboard_navigation_ready ? "yes" : "no") << "\n";
    out << "- High-DPI ready: " << (model.high_dpi_ready ? "yes" : "no") << "\n";
    out << "- Screen-reader labels ready: " << (model.screen_reader_labels_ready ? "yes" : "no") << "\n";
    out << "- Low-resource mode: " << (model.low_resource_mode ? "enabled" : "available") << "\n\n";
    out << "## Checks\n\n";
    for (const auto& check : model.checks) {
        out << "- " << check.title << " [" << check.status << "]: " << check.details << "\n";
    }
    out << "\n## Low-resource scan settings\n\n";
    out << "- Profile: " << model.low_resource_scan.profile << "\n";
    out << "- Timeout seconds: " << model.low_resource_scan.timeout_seconds << "\n";
    out << "- Max concurrency: " << model.low_resource_scan.max_concurrency << "\n";
    out << "- Max QPS: " << model.low_resource_scan.max_qps << "\n";
    out << "- Schedule interval minutes: " << model.low_resource_scan.schedule_interval_minutes << "\n";
    out << "- Enabled probes: ";
    for (std::size_t i = 0; i < model.low_resource_scan.enabled_probes.size(); ++i) {
        if (i > 0) {
            out << ", ";
        }
        out << model.low_resource_scan.enabled_probes[i];
    }
    out << "\n";
    out << "- Rationale: " << model.low_resource_scan.rationale << "\n\n";
    out << "## Warnings\n\n";
    if (model.warnings.empty()) {
        out << "- None\n";
    } else {
        for (const auto& warning : model.warnings) {
            out << "- " << warning << "\n";
        }
    }
    return out.str();
}

} // namespace netsentinel::ui
