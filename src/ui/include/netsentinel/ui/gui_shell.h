#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "netsentinel/storage/storage.h"

namespace netsentinel::ui {

struct GuiShellConfig {
    bool demo_mode = false;
    netsentinel::storage::StorageConfig storage{};
    std::string gateway = "192.168.1.1";
};

struct GuiBandwidthDashboardConfig {
    bool demo_mode = false;
    bool mock_mode = false;
    netsentinel::storage::StorageConfig storage{};
};

struct GuiViewSummary {
    std::string id;
    std::string title;
    std::string description;
    std::string badge;
    bool enabled = true;
};

struct GuiShellModel {
    bool qt_available = false;
    bool demo_mode = false;
    std::vector<GuiViewSummary> views{};
    std::vector<std::string> warnings{};
    std::string visual_direction;
    std::string message;
};

struct GuiBandwidthTopTalkerRow {
    std::string device_id;
    std::string display_name;
    std::string confidence;
    std::string source_label;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    std::uint64_t total_bytes = 0;
    bool incomplete_or_estimated = false;
};

struct GuiBandwidthChartPoint {
    std::string timestamp_utc;
    std::string device_id;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    std::string measurement_kind;
};

struct GuiBandwidthDashboardModel {
    bool success = false;
    bool empty_state = false;
    std::string active_source;
    std::vector<std::string> source_limitations{};
    std::vector<std::string> source_confidence_summary{};
    std::vector<GuiBandwidthTopTalkerRow> top_talkers{};
    std::vector<GuiBandwidthChartPoint> history_chart{};
    std::vector<std::string> alerts{};
    std::string message;
};

struct GuiDeviceListConfig {
    netsentinel::storage::StorageConfig storage{};
    std::string preset = "all";
    std::string search_text;
    std::string vendor;
    std::string network_id;
    std::string sort_by = "relevance";
    bool include_hidden = false;
};

struct GuiDeviceRow {
    std::string device_id;
    std::string hostname;
    std::string primary_ip;
    std::string vendor;
    std::string device_type;
    std::string icon;
    std::string status_badge;
    std::string network_id;
    int importance = 0;
    int confidence_percent = 0;
    std::vector<std::string> labels{};
    std::vector<std::string> matched_reasons{};
};

struct GuiProtocolObservation {
    int port = 0;
    std::string protocol = "tcp";
    std::string service;
    std::string confidence;
};

struct GuiDeviceDetail {
    bool found = false;
    GuiDeviceRow summary{};
    std::vector<GuiProtocolObservation> protocols{};
    std::vector<std::string> confidence_explanations{};
    std::vector<std::string> manual_labels{};
    std::vector<netsentinel::storage::DeviceTimelineRecord> history{};
    std::string message;
};

struct GuiDeviceListModel {
    std::vector<GuiDeviceRow> rows{};
    std::vector<std::string> available_filters{};
    std::string sort_by;
    std::string message;
};

struct GuiActionDescriptor {
    std::string id;
    std::string title;
    std::string area;
    bool requires_confirmation = false;
    bool dry_run_supported = true;
    std::string description;
};

struct GuiActionRequest {
    std::string action_id;
    std::string target;
    bool mock_mode = true;
    bool dry_run = true;
    bool confirmed = false;
    netsentinel::storage::StorageConfig storage{};
    std::string api_token = "local-gui-token";
    std::string report_type = "executive";
    std::string report_format = "html";
};

struct GuiActionProgress {
    std::string stage;
    int percent = 0;
    std::string state = "pending";
};

struct GuiActionResult {
    bool success = false;
    bool requires_confirmation = false;
    std::string action_id;
    std::string severity = "info";
    std::vector<GuiActionProgress> progress{};
    std::string message;
    std::string output;
    std::vector<std::string> errors{};
};

struct GuiAccessibilityConfig {
    std::string language = "en-US";
    bool low_resource_mode = false;
    bool high_contrast = false;
    bool screen_reader_mode = true;
    double dpi_scale = 1.0;
};

struct GuiAccessibilityCheck {
    std::string id;
    std::string title;
    std::string status = "pass";
    std::string details;
};

struct GuiLowResourceScanSettings {
    std::string profile = "low-resource";
    int timeout_seconds = 12;
    int max_concurrency = 2;
    int max_qps = 4;
    int schedule_interval_minutes = 30;
    std::vector<std::string> enabled_probes{"arp", "icmp"};
    std::vector<int> tcp_port_hints{};
    std::string rationale;
};

struct GuiAccessibilityModel {
    bool success = false;
    std::string language = "en-US";
    std::string language_file = "i18n/en-US.txt";
    bool keyboard_navigation_ready = false;
    bool high_dpi_ready = false;
    bool screen_reader_labels_ready = false;
    bool low_resource_mode = false;
    GuiLowResourceScanSettings low_resource_scan{};
    std::vector<GuiAccessibilityCheck> checks{};
    std::vector<std::string> warnings{};
    std::string message;
};

GuiShellModel build_gui_shell_model(const GuiShellConfig& config);
std::string gui_shell_model_json(const GuiShellModel& model);
GuiBandwidthDashboardModel build_gui_bandwidth_dashboard_model(const GuiBandwidthDashboardConfig& config);
std::string gui_bandwidth_dashboard_json(const GuiBandwidthDashboardModel& model);
GuiDeviceListModel build_gui_device_list_model(const GuiDeviceListConfig& config);
GuiDeviceDetail build_gui_device_detail_model(
    const netsentinel::storage::StorageConfig& storage,
    const std::string& device_id
);
std::string gui_device_list_model_json(const GuiDeviceListModel& model);
std::string gui_device_detail_json(const GuiDeviceDetail& detail);
std::vector<GuiActionDescriptor> build_gui_action_catalog();
GuiActionResult run_gui_action(const GuiActionRequest& request);
std::string gui_action_result_json(const GuiActionResult& result);
GuiAccessibilityModel build_gui_accessibility_model(const GuiAccessibilityConfig& config);
std::string gui_accessibility_model_json(const GuiAccessibilityModel& model);
std::string gui_accessibility_model_markdown(const GuiAccessibilityModel& model);

} // namespace netsentinel::ui
