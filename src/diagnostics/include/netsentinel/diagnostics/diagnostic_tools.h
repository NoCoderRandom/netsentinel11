#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <cstddef>
#include <vector>

namespace netsentinel::diagnostics {

struct PingConfig {
    bool mock_mode = true;
    std::string target = "127.0.0.1";
    std::size_t count = 4;
    std::size_t timeout_ms = 1000;
    std::string resolver = "";
};

struct PingResult {
    bool reachable = false;
    bool timed_out = false;
    double avg_latency_ms = 0.0;
    std::string message;
};

struct PingOperationResult {
    bool success = false;
    bool persisted = false;
    PingResult result{};
    std::string message;
};

struct TracerouteConfig {
    bool mock_mode = true;
    std::string destination = "127.0.0.1";
    std::size_t max_hops = 30;
    std::size_t timeout_ms = 1000;
};

struct TracerouteHop {
    std::size_t hop = 0;
    std::string address = "";
    double latency_ms = -1.0;
};

struct TracerouteResult {
    bool destination_reached = false;
    std::vector<TracerouteHop> hops{};
    std::string message;
};

struct TracerouteOperationResult {
    bool success = false;
    bool persisted = false;
    TracerouteResult result{};
    std::string message;
};

struct DnsLookupConfig {
    bool mock_mode = true;
    bool reverse = false;
    std::string target = "localhost";
    std::string resolver = "8.8.8.8";
    std::size_t max_records = 10;
};

struct DnsLookupResult {
    bool resolved = false;
    std::vector<std::string> answers{};
    std::string message;
};

struct DnsOperationResult {
    bool success = false;
    bool persisted = false;
    DnsLookupResult result{};
    std::string message;
};

struct DiagnosticHistoryPoint {
    std::string timestamp_utc{};
    std::string command{};
    std::string target{};
    std::string status{};
    std::string details{};
};

struct DnsBenchmarkConfig {
    bool mock_mode = true;
    std::vector<std::string> resolvers{};
    std::vector<std::string> queries{};
    std::size_t samples = 3;
    std::size_t timeout_ms = 1000;
};

struct DnsBenchmarkResult {
    std::string resolver;
    double avg_latency_ms = 0.0;
    double failure_rate = 0.0;
    double consistency_score = 0.0;
    bool dnssec_available = false;
    std::size_t success_count = 0;
    std::size_t total_queries = 0;
    std::string recommendation;
};

struct DhcpDiscoveryConfig {
    bool mock_mode = true;
    bool allow_multiple_reply_check = false;
    std::string adapter_filter = "";
};

struct DhcpDiscoveryAdapterResult {
    std::string adapter_id{};
    std::string interface_name{};
    bool dhcp_enabled = false;
    bool discovered_server = false;
    std::string selected_server{};
    std::vector<std::string> observed_servers{};
    bool multiple_responses_detected = false;
    std::string message;
};

struct DhcpDiscoveryResult {
    bool success = false;
    bool persisted = false;
    bool multiple_reply_detected = false;
    std::vector<DhcpDiscoveryAdapterResult> adapters{};
    std::string limitations;
    std::string message;
};

struct DnsBenchmarkOperationResult {
    bool success = false;
    bool persisted = false;
    std::vector<DnsBenchmarkResult> results{};
    std::string message;
};

struct WifiScanConfig {
    bool mock_mode = true;
    bool include_hidden = false;
};

struct WifiNetworkInfo {
    std::string ssid{};
    std::string bssid{};
    int rssi_dbm = 0;
    int channel = 0;
    std::string band{};
    std::string auth{};
    std::string cipher{};
    int signal_quality = 0;
    bool connected = false;
    bool hidden = false;
};

struct WifiScanResult {
    bool success = false;
    bool persisted = false;
    std::vector<WifiNetworkInfo> networks{};
    std::string connected_ssid;
    std::string message;
};

struct WifiChannelSummary {
    std::string band{};
    std::size_t network_count = 0;
    std::size_t crowded_channels = 0;
    double average_signal_quality = 0.0;
};

struct WifiSecurityWarning {
    std::string ssid{};
    std::string bssid{};
    std::string reason{};
};

struct WifiChannelAnalysisResult {
    bool success = false;
    bool persisted = false;
    std::size_t total_networks = 0;
    std::size_t crowded_channels = 0;
    std::size_t weak_signal_count = 0;
    std::size_t insecure_network_count = 0;
    std::vector<WifiChannelSummary> band_summaries{};
    std::vector<std::string> suggestions{};
    std::vector<WifiSecurityWarning> security_warnings{};
    std::string history_snapshot;
    std::string message;
};

struct WifiEnvironmentNetwork {
    std::string ssid{};
    std::string bssid{};
    int channel = 0;
    std::string band{};
    int rssi_dbm = 0;
    int signal_quality = 0;
    std::string auth{};
    std::string cipher{};
    bool connected = false;
    bool hidden = false;
    int overlap_count = 0;
    std::string overlap_severity{};
    std::string recommendation{};
};

struct WifiChannelRecommendation {
    std::string band{};
    int channel = 0;
    std::string severity{};
    std::string reason{};
};

struct WifiEnvironmentView {
    bool success = false;
    bool persisted = false;
    std::vector<WifiEnvironmentNetwork> networks{};
    std::vector<WifiChannelSummary> band_summaries{};
    std::vector<WifiChannelRecommendation> channel_recommendations{};
    std::vector<std::string> safety_notes{};
    std::string connected_ssid{};
    std::string scan_source{};
    std::string message{};
};

struct WifiSweetSpotSample {
    std::string location_label{};
    std::string ssid{};
    std::string bssid{};
    int rssi_dbm = 0;
    int link_quality = 0;
    int channel = 0;
    std::string band{};
    std::string timestamp_utc{};
};

struct WifiSweetSpotLocationSummary {
    std::string location_label{};
    std::size_t sample_count = 0;
    double average_quality = 0.0;
    int weakest_rssi_dbm = 0;
    bool weak_spot = false;
    std::string recommendation{};
};

struct WifiSweetSpotConfig {
    bool mock_mode = true;
    bool include_hidden = false;
    std::string location_label = "unlabeled-room";
    std::string timestamp_utc = "2026-05-02T00:00:00Z";
};

struct WifiSweetSpotReport {
    bool success = false;
    bool persisted = false;
    std::vector<WifiSweetSpotSample> samples{};
    std::vector<WifiSweetSpotLocationSummary> summaries{};
    std::vector<std::string> chart_lines{};
    std::vector<std::string> limitations{};
    std::string message{};
};

struct PortScanTarget {
    std::string address{};
    std::vector<int> open_ports{};
    std::vector<std::string> banners{};
};

struct PortScanConfig {
    bool mock_mode = true;
    std::vector<std::string> targets{};
    std::vector<int> ports{};
    std::size_t concurrency = 8;
    bool banner = false;
};

struct PortScanResult {
    bool success = false;
    bool persisted = false;
    std::vector<PortScanTarget> results{};
    std::size_t open_port_count = 0;
    std::string preset{};
    std::string message;
};

struct ServiceObservation {
    std::string target{};
    int port = 0;
    std::string protocol{};
    std::string service{};
    int confidence_percent = 0;
    std::string source{};
    std::string detail{};
    std::string observed_at_utc{};
};

struct ServiceIdentificationResult {
    bool success = false;
    bool persisted = false;
    std::vector<ServiceObservation> observations{};
    std::vector<std::string> device_hints{};
    std::string message{};
};

struct RouterPortExposure {
    std::string protocol{};
    int external_port = 0;
    int internal_port = 0;
    std::string service{};
    std::string detail{};
};

struct RouterSecurityFinding {
    std::string category{};
    std::string severity{};
    std::string title{};
    std::string detail{};
    int risk_score = 0;
};

struct RouterCveCorrelation {
    std::string component{};
    std::string firmware{};
    std::string cve{};
    std::string description{};
};

struct RouterSecurityConfig {
    bool mock_mode = true;
    std::string gateway = "192.168.1.1";
};

struct RouterSecurityResult {
    bool success = false;
    bool persisted = false;
    std::string gateway{};
    bool upnp_exposed = false;
    bool natpmp_exposed = false;
    std::vector<RouterPortExposure> exposed_mappings{};
    std::vector<RouterSecurityFinding> findings{};
    std::vector<std::string> weak_protocols{};
    std::vector<std::string> tls_protocols{};
    std::vector<RouterCveCorrelation> cve_correlations{};
    int risk_score = 0;
    std::string firmware_version{};
    std::string message{};
};

struct RouterUpnpNatpmpManagementConfig {
    bool mock_mode = true;
    std::string gateway = "192.168.1.1";
    bool dry_run = true;
    bool confirm = false;
    std::vector<int> target_ports{};
};

struct RouterUpnpNatpmpManagementResult {
    bool success = false;
    bool persisted = false;
    std::string gateway{};
    bool dry_run = true;
    bool confirm_required = false;
    bool safe_api_available = false;
    std::vector<RouterPortExposure> discovered_mappings{};
    std::vector<RouterPortExposure> removable_mappings{};
    std::vector<std::string> guidance{};
    std::vector<RouterPortExposure> applied_mappings{};
    std::string message{};
};

struct HiddenCameraDetectorConfig {
    bool mock_mode = true;
    bool include_mdns = true;
    bool include_ssdp = true;
    bool include_port_hints = true;
    bool privacy_mode = true;
    bool rental_mode = false;
    bool include_unknown_iot = true;
    std::string storage_db_path = "";
};

struct HiddenCameraFinding {
    std::string device_id;
    std::string hostname;
    std::string ip_address;
    std::string vendor_hint;
    std::string device_type;
    std::string classification{};
    int risk_score = 0;
    bool user_approved = false;
    std::string checklist_category{};
    int confidence_percent = 0;
    std::vector<std::string> false_positive_warnings{};
    std::vector<std::string> recommended_checks{};
    std::vector<int> exposed_ports{};
    std::vector<std::string> evidence{};
};

struct HiddenCameraDetectorResult {
    bool success = false;
    bool persisted = false;
    std::string storage_db_path{};
    std::vector<HiddenCameraFinding> findings{};
    std::vector<std::string> limitations{};
    std::vector<std::string> checklist_report{};
    std::size_t likely_camera_count = 0;
    std::size_t possible_camera_count = 0;
    std::size_t unknown_iot_count = 0;
    std::size_t false_positive_warning_count = 0;
    std::string message{};
};

struct DeviceLifecycleConfig {
    bool mock_mode = true;
    bool include_unknown = true;
    std::string storage_db_path = "";
    std::string catalog_path = "data/device_lifecycle_catalog.json";
    std::string reference_date_utc = "";
};

struct DeviceLifecycleFinding {
    std::string device_id;
    std::string hostname;
    std::string ip_address;
    std::string vendor_hint;
    std::string device_type;
    std::string matched_vendor{};
    std::string matched_model{};
    std::string lifecycle_status{};
    std::string severity{};
    std::string source{};
    std::string notes{};
    int confidence_percent = 0;
    int first_seen_year = 0;
    int eol_year = 0;
    int estimated_age_years = 0;
    std::vector<std::string> evidence{};
    std::vector<std::string> recommendations{};
};

struct DeviceLifecycleResult {
    bool success = false;
    bool persisted = false;
    std::string storage_db_path{};
    std::string catalog_path{};
    std::string reference_date_utc{};
    std::size_t device_count = 0;
    std::size_t finding_count = 0;
    std::size_t likely_eol_count = 0;
    std::size_t outdated_count = 0;
    std::size_t monitor_count = 0;
    std::size_t unknown_count = 0;
    std::vector<DeviceLifecycleFinding> findings{};
    std::vector<std::string> limitations{};
    std::string message{};
};

struct CveCpeCorrelationConfig {
    bool mock_mode = true;
    bool include_possible_matches = true;
    std::string storage_db_path = "";
    std::string catalog_path = "data/cve_cpe_catalog.json";
};

struct CveCpeMatch {
    std::string device_id;
    std::string hostname;
    std::string ip_address;
    std::string vendor_hint;
    std::string device_type;
    std::string cpe{};
    std::string cve{};
    std::string severity{};
    std::string cvss{};
    std::string match_label{};
    std::string source{};
    std::string summary{};
    int confidence_percent = 0;
    bool version_evidence = false;
    std::vector<std::string> evidence{};
    std::vector<std::string> recommendations{};
};

struct CveCpeCorrelationResult {
    bool success = false;
    bool persisted = false;
    std::string storage_db_path{};
    std::string catalog_path{};
    std::size_t device_count = 0;
    std::size_t match_count = 0;
    std::size_t possible_match_count = 0;
    std::size_t strong_version_match_count = 0;
    std::vector<CveCpeMatch> matches{};
    std::vector<std::string> limitations{};
    std::string message{};
};

struct LocalRecognitionLearningConfig {
    bool mock_mode = true;
    std::string inventory_db_path = "";
    std::string recognition_db_path = "data/local_recognition_rules.tsv";
    std::string import_path = "";
    std::string export_path = "";
    std::string learn_device_id = "";
    std::string learn_hostname = "";
    std::string learn_vendor_hint = "";
    std::string learn_device_type = "";
    std::vector<std::string> learn_labels{};
};

struct LocalRecognitionSuggestion {
    std::string device_id;
    std::string hostname;
    std::string vendor_hint;
    std::string current_device_type;
    std::string suggested_device_type;
    std::vector<std::string> suggested_labels{};
    int confidence_percent = 0;
    std::string source{};
    std::vector<std::string> evidence{};
};

struct LocalRecognitionLearningResult {
    bool success = false;
    bool persisted = false;
    std::string inventory_db_path{};
    std::string recognition_db_path{};
    std::size_t rules_loaded = 0;
    std::size_t rules_imported = 0;
    std::size_t rules_written = 0;
    std::size_t suggestions_count = 0;
    std::vector<LocalRecognitionSuggestion> suggestions{};
    std::vector<std::string> limitations{};
    std::string message{};
};

struct GenericInventoryImportConfig {
    std::string input_path = "";
    std::string output_db_path = "";
    std::string format = "auto";
    bool apply = false;
};

struct GenericImportedDevice {
    std::string device_id;
    std::string hostname;
    std::string ip_address;
    std::string mac_address;
    std::string vendor_hint;
    std::string device_type;
    std::vector<std::string> labels{};
    std::string first_seen_utc;
    std::string last_seen_utc;
    std::vector<std::string> mapping_notes{};
};

struct GenericInventoryImportResult {
    bool success = false;
    bool preview_only = true;
    bool persisted = false;
    std::string input_path{};
    std::string output_db_path{};
    std::string format{};
    std::size_t rows_read = 0;
    std::size_t rows_importable = 0;
    std::size_t rows_written = 0;
    std::vector<GenericImportedDevice> devices{};
    std::vector<std::string> warnings{};
    std::vector<std::string> limitations{};
    std::string message{};
};

struct SecurityHealthCheckConfig {
    bool mock_mode = true;
    std::string storage_db_path = "";
    std::string gateway = "192.168.1.1";
};

struct SecurityScoreComponent {
    std::string name{};
    int penalty = 0;
    int max_penalty = 0;
    std::string status{};
    std::string detail{};
};

struct SecurityHealthCheckResult {
    bool success = false;
    bool persisted = false;
    int score = 0;
    std::string grade{};
    std::vector<SecurityScoreComponent> components{};
    std::vector<std::string> recommendations{};
    std::string message{};
};

struct InternetControlConfig {
    bool mock_mode = true;
    std::string backend = "advisory";
    std::string action = "block";
    std::string target_ip{};
    std::string device_id{};
    std::string target_label{};
    std::string requested_method = "safe-control-api";
    bool dry_run = true;
    bool confirm = false;
    int download_limit_kbps = 0;
    int upload_limit_kbps = 0;
    std::string router_plugin{};
    std::string router_username{};
    std::string router_password{};
};

struct InternetControlStep {
    std::string backend{};
    std::string action{};
    std::string target{};
    std::string status{};
    std::string detail{};
};

struct InternetControlResult {
    bool success = false;
    bool persisted = false;
    std::string backend{};
    std::string action{};
    bool dry_run = true;
    bool confirm_required = false;
    bool applied = false;
    bool safe_backend = false;
    std::vector<InternetControlStep> steps{};
    std::vector<std::string> safety_guards{};
    std::vector<std::string> limitations{};
    std::string message{};
};

struct ParentalDowntimeWindow {
    std::string days = "all";
    std::string start_local = "22:00";
    std::string end_local = "06:00";
    bool enabled = true;
};

struct ParentalDowntimeAssignment {
    std::string user{};
    std::string group{};
    std::string device_id{};
    std::string target_ip{};
    std::string label{};
};

struct ParentalDowntimeConfig {
    bool mock_mode = true;
    std::string schedule_id = "default";
    std::vector<ParentalDowntimeWindow> windows{};
    std::vector<ParentalDowntimeAssignment> assignments{};
    std::string backend = "advisory";
    std::string now_local{};
    bool dry_run = true;
    bool confirm = false;
    bool emergency_disable = false;
};

struct ParentalDowntimeAuditEvent {
    std::string timestamp_utc{};
    std::string schedule_id{};
    std::string event{};
    std::string detail{};
};

struct ParentalDowntimeDecision {
    ParentalDowntimeAssignment assignment{};
    bool downtime_active = false;
    bool advisory_only = true;
    std::string requested_action{};
    std::string detail{};
    InternetControlResult control{};
};

struct ParentalDowntimeResult {
    bool success = false;
    bool persisted = false;
    std::string schedule_id{};
    bool emergency_disabled = false;
    bool downtime_active = false;
    bool advisory_only = true;
    std::vector<ParentalDowntimeDecision> decisions{};
    std::vector<ParentalDowntimeAuditEvent> audit_events{};
    std::vector<std::string> limitations{};
    std::string message{};
};

struct UsagePolicyRule {
    std::string rule_id{};
    std::string profile = "family";
    std::string device_id{};
    std::string group{};
    std::string target_ip{};
    std::string schedule_days = "all";
    std::string schedule_window = "00:00-23:59";
    std::uint64_t quota_bytes = 0;
    std::uint64_t warning_threshold_bytes = 0;
    bool enabled = true;
};

struct UsagePolicyObservation {
    std::string device_id{};
    std::string group{};
    std::string target_ip{};
    std::uint64_t used_bytes = 0;
    std::string source = "mock-bandwidth-rollup";
};

struct UsagePolicyDecision {
    std::string rule_id{};
    std::string profile{};
    std::string subject{};
    std::string state{};
    std::uint64_t quota_bytes = 0;
    std::uint64_t used_bytes = 0;
    std::uint64_t remaining_bytes = 0;
    bool enforcement_requested = false;
    std::string explanation{};
};

struct UsagePolicyConfig {
    bool mock_mode = true;
    std::vector<UsagePolicyRule> rules{};
    std::vector<UsagePolicyObservation> observations{};
    std::string now_local{};
};

struct UsagePolicyResult {
    bool success = false;
    bool persisted = false;
    bool advisory_only = true;
    std::vector<UsagePolicyDecision> decisions{};
    std::vector<std::string> warnings{};
    std::vector<std::string> limitations{};
    std::string message{};
};

PingOperationResult run_ping(const PingConfig& config);
TracerouteOperationResult run_traceroute(const TracerouteConfig& config);
DnsOperationResult run_dns_lookup(const DnsLookupConfig& config);
DnsBenchmarkOperationResult run_dns_benchmark(const DnsBenchmarkConfig& config);
DhcpDiscoveryResult run_dhcp_discovery(const DhcpDiscoveryConfig& config);
WifiScanResult run_wifi_scan(const WifiScanConfig& config);
WifiChannelAnalysisResult run_wifi_channel_analysis(const WifiScanConfig& config);
WifiEnvironmentView run_wifi_environment_view(const WifiScanConfig& config);
WifiSweetSpotReport run_wifi_sweet_spot_logger(const WifiSweetSpotConfig& config);
PortScanResult run_port_scan(const PortScanConfig& config, const std::string& preset, const std::vector<int>& custom_ports);
ServiceIdentificationResult run_service_identification(const PortScanConfig& config, const std::string& preset, const std::vector<int>& custom_ports);
HiddenCameraDetectorResult run_hidden_camera_detector(const HiddenCameraDetectorConfig& config);
std::string hidden_camera_detector_markdown(const HiddenCameraDetectorResult& result);
DeviceLifecycleResult run_device_lifecycle_intelligence(const DeviceLifecycleConfig& config);
std::string device_lifecycle_markdown(const DeviceLifecycleResult& result);
CveCpeCorrelationResult run_cve_cpe_correlation(const CveCpeCorrelationConfig& config);
std::string cve_cpe_correlation_markdown(const CveCpeCorrelationResult& result);
LocalRecognitionLearningResult run_local_recognition_learning(const LocalRecognitionLearningConfig& config);
std::string local_recognition_learning_markdown(const LocalRecognitionLearningResult& result);
GenericInventoryImportResult run_generic_inventory_import(const GenericInventoryImportConfig& config);
std::string generic_inventory_import_markdown(const GenericInventoryImportResult& result);
SecurityHealthCheckResult run_security_health_check(const SecurityHealthCheckConfig& config);
InternetControlResult run_internet_control(const InternetControlConfig& config);
ParentalDowntimeResult run_parental_downtime_schedule(const ParentalDowntimeConfig& config);
UsagePolicyResult evaluate_usage_policy(const UsagePolicyConfig& config);
RouterSecurityResult run_router_security_check(const RouterSecurityConfig& config);
RouterUpnpNatpmpManagementResult run_router_upnp_natpmp_management(const RouterUpnpNatpmpManagementConfig& config);
std::vector<DiagnosticHistoryPoint> read_diagnostics_history(std::size_t max_entries);
std::string wifi_environment_markdown(const WifiEnvironmentView& view);
std::string wifi_sweet_spot_csv(const WifiSweetSpotReport& report);
std::string wifi_sweet_spot_markdown(const WifiSweetSpotReport& report);

} // namespace netsentinel::diagnostics
