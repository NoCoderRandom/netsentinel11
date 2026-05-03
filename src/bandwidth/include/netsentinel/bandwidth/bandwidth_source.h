#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace netsentinel::bandwidth {

enum class BandwidthConfidence {
    unknown,
    low,
    medium,
    high,
    authoritative
};

enum class BandwidthSourceKind {
    mock,
    local_machine,
    packet_capture,
    snmp_router,
    upnp_igd,
    flow_export,
    router_plugin,
    agent,
    manual_import
};

enum class BandwidthErrorCode {
    none,
    unavailable,
    permission_required,
    unsupported,
    invalid_argument,
    source_failed
};

struct BandwidthError {
    BandwidthErrorCode code = BandwidthErrorCode::none;
    std::string user_message;
    std::string technical_detail;
};

struct DeviceIdentityHint {
    std::string device_id;
    std::string ip_address;
    std::string mac_address;
    std::string hostname;
};

struct BandwidthSourceCapability {
    std::string source_name;
    BandwidthSourceKind kind = BandwidthSourceKind::mock;
    bool available = false;
    bool realtime = false;
    bool per_device = false;
    bool aggregate = false;
    bool requires_admin = false;
    bool sends_network_traffic = false;
    bool optional_dependency = false;
    std::string dependency_name;
    std::vector<std::string> limitations;
    std::string safe_setup_hint;
};

struct BandwidthSample {
    std::string source_name;
    std::string timestamp_utc;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    DeviceIdentityHint identity;
    BandwidthConfidence confidence = BandwidthConfidence::unknown;
    std::vector<std::string> tags;
};

struct BandwidthAttributionResult {
    bool success = false;
    std::string source_name;
    DeviceIdentityHint identity;
    std::uint64_t rx_delta_bytes = 0;
    std::uint64_t tx_delta_bytes = 0;
    BandwidthConfidence confidence = BandwidthConfidence::unknown;
    std::string explanation;
    std::vector<std::string> limitations;
};

struct BandwidthSourceStatus {
    bool success = false;
    BandwidthError error;
    BandwidthSourceCapability capability;
    std::vector<BandwidthSample> samples;
};

struct MockBandwidthSourceConfig {
    std::string source_name = "mock-bandwidth";
    std::string timestamp_utc = "2026-05-02T00:00:00Z";
    bool include_low_confidence_sample = true;
};

struct NpcapAdapterCapability {
    std::string adapter_id;
    std::string display_name;
    bool supported = false;
    bool permission_granted = false;
    bool monitor_mode_supported = false;
    std::string user_message;
    std::vector<std::string> limitations;
};

struct NpcapDetectionConfig {
    bool mock_mode = false;
    bool simulate_installed = false;
    bool simulate_admin = false;
    bool include_unsupported_adapter = true;
};

struct NpcapDetectionReport {
    bool installed = false;
    bool driver_service_present = false;
    bool current_user_admin = false;
    bool capture_available = false;
    bool monitor_mode_available = false;
    BandwidthSourceCapability source_capability;
    std::vector<NpcapAdapterCapability> adapters;
    std::vector<std::string> messages;
};

struct LocalMachineBandwidthConfig {
    bool mock_mode = false;
    std::string timestamp_utc = "2026-05-02T00:00:00Z";
    bool persist_rollup = false;
    std::string database_path = "netsentinel11_storage.db";
    bool has_previous_totals = false;
    std::uint64_t previous_rx_total_bytes = 0;
    std::uint64_t previous_tx_total_bytes = 0;
    double elapsed_seconds = 1.0;
};

struct LocalMachineBandwidthSnapshot {
    bool success = false;
    BandwidthError error;
    BandwidthSourceStatus status;
    std::vector<BandwidthAttributionResult> attributions;
    std::uint64_t rx_total_bytes = 0;
    std::uint64_t tx_total_bytes = 0;
    double rx_rate_bps = 0.0;
    double tx_rate_bps = 0.0;
    bool persisted = false;
    std::string storage_message;
    std::string scope = "local-machine-only";
    std::string limitation;
};

struct VisibleLanCaptureConfig {
    bool mock_mode = false;
    bool dry_run = true;
    bool confirmed = false;
    bool assume_mirrored_or_gateway_visible = false;
    std::string adapter_id = "default";
    std::string timestamp_utc = "2026-05-02T00:00:00Z";
    std::uint32_t capture_seconds = 5;
};

struct VisibleLanCaptureReport {
    bool success = false;
    bool capture_started = false;
    bool dry_run = true;
    bool injection_used = false;
    std::string adapter_id;
    BandwidthError error;
    NpcapDetectionReport npcap;
    std::vector<BandwidthSample> samples;
    std::vector<BandwidthAttributionResult> attributions;
    std::vector<std::string> limitations;
    std::string user_message;
};

struct CounterDeltaResult {
    std::uint64_t delta = 0;
    bool rollover_detected = false;
};

struct SnmpRouterCounterConfig {
    bool mock_mode = false;
    bool dry_run = true;
    std::string router_ip = "192.168.50.1";
    std::string credential_reference;
    std::string timestamp_utc = "2026-05-02T00:00:00Z";
    double elapsed_seconds = 60.0;
};

struct SnmpInterfaceCounter {
    std::string interface_id;
    std::string interface_name;
    std::string mac_address;
    std::string ip_address_hint;
    std::uint64_t previous_rx_counter = 0;
    std::uint64_t previous_tx_counter = 0;
    std::uint64_t current_rx_counter = 0;
    std::uint64_t current_tx_counter = 0;
    std::uint64_t rx_delta_bytes = 0;
    std::uint64_t tx_delta_bytes = 0;
    bool rollover_detected = false;
    BandwidthConfidence confidence = BandwidthConfidence::medium;
};

struct SnmpRouterCounterReport {
    bool success = false;
    bool read_only = true;
    bool credential_reference_used = false;
    bool network_poll_started = false;
    std::string router_ip;
    BandwidthError error;
    std::vector<SnmpInterfaceCounter> interfaces;
    std::vector<BandwidthSample> samples;
    std::vector<BandwidthAttributionResult> attributions;
    std::vector<std::string> limitations;
    std::string user_message;
};

struct UpnpIgdCounterConfig {
    bool mock_mode = false;
    bool dry_run = true;
    bool mock_no_counters = false;
    std::string gateway = "192.168.50.1";
    std::string timestamp_utc = "2026-05-02T00:00:00Z";
    std::uint64_t previous_rx_total_bytes = 900000000;
    std::uint64_t previous_tx_total_bytes = 120000000;
    double elapsed_seconds = 60.0;
};

struct UpnpIgdCounterReport {
    bool success = false;
    bool read_only = true;
    bool mapping_changes_attempted = false;
    bool counters_available = false;
    bool network_poll_started = false;
    bool network_wide = true;
    std::string gateway;
    BandwidthError error;
    std::uint64_t rx_delta_bytes = 0;
    std::uint64_t tx_delta_bytes = 0;
    double rx_rate_bps = 0.0;
    double tx_rate_bps = 0.0;
    std::vector<BandwidthSample> samples;
    std::vector<BandwidthAttributionResult> attributions;
    std::vector<std::string> limitations;
    std::string user_message;
};

enum class FlowExportProtocol {
    netflow,
    sflow,
    ipfix
};

struct FlowExportRecord {
    FlowExportProtocol protocol = FlowExportProtocol::netflow;
    std::string exporter;
    std::string source_ip;
    std::string destination_ip;
    std::string source_mac;
    std::string destination_mac;
    std::uint64_t bytes = 0;
    std::uint64_t packets = 0;
    std::string ingress_interface;
    std::string egress_interface;
    std::string timestamp_utc;
};

struct FlowParseResult {
    bool success = false;
    FlowExportRecord record;
    BandwidthError error;
};

struct FlowCollectorConfig {
    bool mock_mode = false;
    bool enabled = false;
    bool dry_run = true;
    std::string bind_address = "127.0.0.1";
    std::uint16_t port = 2055;
    std::vector<std::string> fixture_lines;
};

struct FlowCollectorReport {
    bool success = false;
    bool listener_started = false;
    bool explicit_enablement = false;
    std::string bind_address;
    std::uint16_t port = 0;
    BandwidthError error;
    std::vector<FlowExportRecord> records;
    std::vector<BandwidthSample> samples;
    std::vector<BandwidthAttributionResult> attributions;
    std::vector<std::string> limitations;
    std::string user_message;
};

struct RouterPluginCapability {
    std::string plugin_id;
    std::string display_name;
    std::string vendor_family;
    bool implemented = false;
    bool read_only_telemetry = true;
    bool reversible_access_control = false;
    bool documented_api_required = true;
    bool credential_reference_required = true;
    std::string planned_adapter;
    std::vector<std::string> limitations;
};

struct RouterPluginRequest {
    bool mock_mode = false;
    bool dry_run = true;
    bool confirmed = false;
    std::string plugin_id = "mock-router";
    std::string operation = "telemetry";
    std::string target_device_id;
    std::string credential_reference;
};

struct RouterPluginResult {
    bool success = false;
    bool applied = false;
    bool reversible = true;
    bool requires_confirmation = false;
    bool used_documented_api = true;
    bool password_scraping_used = false;
    std::string plugin_id;
    std::string operation;
    BandwidthError error;
    std::vector<BandwidthSample> telemetry_samples;
    std::vector<std::string> limitations;
    std::string user_message;
};

struct BandwidthLimitBackendCapability {
    std::string backend_id{};
    std::string display_name{};
    bool implemented = false;
    bool supports_bandwidth_limit = false;
    bool supports_pause_resume = false;
    bool requires_credentials = true;
    bool documented_api_required = true;
    bool reversible_actions = true;
    std::vector<std::string> limitations{};
};

struct BandwidthLimitRequest {
    bool mock_mode = false;
    bool dry_run = true;
    bool confirmed = false;
    bool saved_rule = false;
    std::string backend = "mock";
    std::string action = "limit";
    std::string target_device_id{};
    std::string target_ip{};
    std::string endpoint{};
    std::string credential_reference{};
    std::string rule_id{};
    int download_limit_kbps = 0;
    int upload_limit_kbps = 0;
};

struct BandwidthLimitStep {
    std::string backend{};
    std::string action{};
    std::string target{};
    std::string status{};
    std::string reversible_action{};
    std::string detail{};
};

struct BandwidthLimitResult {
    bool success = false;
    bool applied = false;
    bool dry_run = true;
    bool reversible = true;
    bool requires_confirmation = false;
    bool documented_api_used = true;
    bool unsafe_method_rejected = false;
    bool logged = false;
    std::string backend{};
    std::string action{};
    std::string rollback_id{};
    BandwidthError error{};
    std::vector<BandwidthLimitStep> steps{};
    std::vector<std::string> limitations{};
    std::vector<std::string> audit_log{};
    std::string user_message{};
};

struct UnknownDeviceObservation {
    std::string device_id{};
    std::string hostname{};
    std::string ip_address{};
    std::string mac_address{};
    std::string vendor_hint{};
    std::string device_type = "unknown";
    std::vector<std::string> labels{};
    bool trusted = false;
    std::string last_seen_utc{};
};

struct AutoblockPolicyConfig {
    bool mock_mode = true;
    bool enforcement_enabled = false;
    bool dry_run = true;
    bool confirmed = false;
    bool saved_rule = false;
    bool rollback_button_required = true;
    std::string safe_backend = "mock";
    std::string endpoint{};
    std::string credential_reference{};
    std::string rule_id = "autoblock-unknown-devices";
    std::vector<UnknownDeviceObservation> devices{};
};

struct AutoblockDecision {
    std::string device_id{};
    std::string ip_address{};
    std::string mac_address{};
    bool unknown = false;
    std::string state{};
    bool enforcement_attempted = false;
    bool rollback_available = false;
    std::string rollback_id{};
    std::string detail{};
    BandwidthLimitResult backend_result{};
};

struct AutoblockPolicyResult {
    bool success = false;
    bool alert_only = true;
    bool enforcement_enabled = false;
    bool rollback_button_available = false;
    std::vector<AutoblockDecision> decisions{};
    std::vector<std::string> alerts{};
    std::vector<std::string> limitations{};
    std::string user_message{};
};

struct OpenWrtTelemetryDevice {
    std::string device_id;
    std::string hostname;
    std::string ip_address;
    std::string mac_address;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    bool online = true;
};

struct OpenWrtTelemetryConfig {
    bool mock_mode = false;
    bool dry_run = true;
    bool mock_unsupported_firmware = false;
    std::string endpoint = "https://openwrt.local";
    std::string credential_reference;
    std::string transport = "rpc";
    std::vector<std::string> fixture_lines;
};

struct OpenWrtTelemetryParseResult {
    bool success = false;
    OpenWrtTelemetryDevice device;
    std::string firmware_version;
    BandwidthError error;
};

struct OpenWrtTelemetryReport {
    bool success = false;
    bool read_only = true;
    bool credential_reference_used = false;
    bool network_request_started = false;
    bool firmware_supported = false;
    std::string endpoint;
    std::string transport;
    std::string firmware_version;
    BandwidthError error;
    std::vector<OpenWrtTelemetryDevice> devices;
    std::vector<BandwidthSample> samples;
    std::vector<std::string> limitations;
    std::string user_message;
};

struct AttributionSourceDetail {
    std::string source_name;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    std::string confidence;
    std::string note;
};

struct PerDeviceBandwidthUsage {
    std::string device_key;
    DeviceIdentityHint identity;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    double rx_rate_bps = 0.0;
    double tx_rate_bps = 0.0;
    std::string confidence;
    bool conflict = false;
    std::vector<AttributionSourceDetail> source_details;
    std::vector<std::string> limitations;
};

struct BandwidthAttributionMergeConfig {
    double elapsed_seconds = 60.0;
};

struct BandwidthAttributionMergeReport {
    bool success = false;
    std::vector<PerDeviceBandwidthUsage> devices;
    std::uint64_t network_only_rx_bytes = 0;
    std::uint64_t network_only_tx_bytes = 0;
    std::vector<std::string> conflicts;
    std::vector<std::string> limitations;
    std::string user_message;
};

struct BandwidthAnomalyRuleConfig {
    std::size_t top_talker_limit = 5;
    std::uint64_t spike_rx_threshold_bytes = 10000000;
    std::uint64_t unusual_upload_threshold_bytes = 5000000;
    std::uint64_t quiet_device_baseline_bytes = 100000;
    std::uint64_t quiet_device_active_threshold_bytes = 1000000;
};

struct TopTalkerEntry {
    std::string device_id;
    std::string confidence;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    std::uint64_t total_bytes = 0;
    std::vector<std::string> evidence;
};

struct BandwidthAnomalyAlert {
    std::string alert_id;
    std::string device_id;
    std::string kind;
    std::string severity;
    std::string explanation;
    std::vector<std::string> evidence;
    bool malware_claim = false;
};

struct BandwidthAnomalyReport {
    bool success = false;
    std::vector<TopTalkerEntry> top_talkers;
    std::vector<BandwidthAnomalyAlert> alerts;
    std::vector<std::string> tuning_notes;
    std::string user_message;
};

class IBandwidthSource {
public:
    virtual ~IBandwidthSource() = default;
    virtual BandwidthSourceCapability capability() const = 0;
    virtual BandwidthSourceStatus collect_samples() = 0;
};

std::string to_string(BandwidthConfidence confidence);
std::string to_string(BandwidthSourceKind kind);
std::string to_string(BandwidthErrorCode code);

std::unique_ptr<IBandwidthSource> make_mock_bandwidth_source(const MockBandwidthSourceConfig& config = {});
BandwidthSourceStatus collect_mock_bandwidth_samples(const MockBandwidthSourceConfig& config = {});
std::vector<BandwidthSourceCapability> list_planned_bandwidth_source_capabilities();
std::vector<BandwidthAttributionResult> build_attribution_results(const std::vector<BandwidthSample>& samples);
BandwidthError validate_bandwidth_sample(const BandwidthSample& sample);
NpcapDetectionReport detect_npcap_capabilities(const NpcapDetectionConfig& config = {});
LocalMachineBandwidthSnapshot collect_local_machine_bandwidth(const LocalMachineBandwidthConfig& config = {});
VisibleLanCaptureReport collect_visible_lan_capture_bandwidth(const VisibleLanCaptureConfig& config = {});
CounterDeltaResult calculate_counter_delta(std::uint64_t previous, std::uint64_t current, std::uint64_t max_counter_value);
SnmpRouterCounterReport collect_snmp_router_counters(const SnmpRouterCounterConfig& config = {});
UpnpIgdCounterReport collect_upnp_igd_counters(const UpnpIgdCounterConfig& config = {});
std::string to_string(FlowExportProtocol protocol);
std::vector<std::string> mock_flow_fixture_lines();
FlowParseResult parse_flow_fixture_line(const std::string& line);
FlowCollectorReport collect_flow_exports(const FlowCollectorConfig& config = {});
std::vector<RouterPluginCapability> list_router_plugin_capabilities();
RouterPluginResult run_router_plugin_request(const RouterPluginRequest& request = {});
std::vector<BandwidthLimitBackendCapability> list_safe_bandwidth_limit_backends();
BandwidthLimitResult run_safe_bandwidth_limit_backend(const BandwidthLimitRequest& request = {});
AutoblockPolicyResult run_unknown_device_autoblock_policy(const AutoblockPolicyConfig& config = {});
std::vector<std::string> mock_openwrt_telemetry_lines();
OpenWrtTelemetryParseResult parse_openwrt_telemetry_line(const std::string& line);
OpenWrtTelemetryReport collect_openwrt_readonly_telemetry(const OpenWrtTelemetryConfig& config = {});
std::vector<BandwidthSample> mock_bandwidth_attribution_samples();
BandwidthAttributionMergeReport attribute_bandwidth_per_device(
    const std::vector<BandwidthSample>& samples,
    const BandwidthAttributionMergeConfig& config = {}
);
BandwidthAnomalyReport analyze_bandwidth_top_talkers_and_anomalies(
    const std::vector<PerDeviceBandwidthUsage>& current,
    const std::vector<PerDeviceBandwidthUsage>& baseline,
    const BandwidthAnomalyRuleConfig& config = {}
);
BandwidthAnomalyReport mock_bandwidth_anomaly_report();
std::string bandwidth_capabilities_markdown(const std::vector<BandwidthSourceCapability>& capabilities);
std::string bandwidth_samples_markdown(const BandwidthSourceStatus& status);
std::string npcap_detection_markdown(const NpcapDetectionReport& report);
std::string local_machine_bandwidth_markdown(const LocalMachineBandwidthSnapshot& snapshot);
std::string visible_lan_capture_markdown(const VisibleLanCaptureReport& report);
std::string snmp_router_counter_markdown(const SnmpRouterCounterReport& report);
std::string upnp_igd_counter_markdown(const UpnpIgdCounterReport& report);
std::string flow_collector_markdown(const FlowCollectorReport& report);
std::string router_plugin_capabilities_markdown(const std::vector<RouterPluginCapability>& capabilities);
std::string router_plugin_result_markdown(const RouterPluginResult& result);
std::string bandwidth_limit_result_markdown(const BandwidthLimitResult& result);
std::string autoblock_policy_markdown(const AutoblockPolicyResult& result);
std::string openwrt_telemetry_markdown(const OpenWrtTelemetryReport& report);
std::string bandwidth_attribution_markdown(const BandwidthAttributionMergeReport& report);
std::string bandwidth_anomaly_report_markdown(const BandwidthAnomalyReport& report);

} // namespace netsentinel::bandwidth
