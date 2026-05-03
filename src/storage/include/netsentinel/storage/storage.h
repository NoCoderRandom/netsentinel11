#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "netsentinel/engine/domain_model.h"
#include "netsentinel/engine/error_model.h"

namespace netsentinel::storage {

template <typename T>
using Result = netsentinel::engine::Result<T>;

struct StorageConfig {
    std::string database_path = "netsentinel11_storage.db";
    std::size_t target_schema_version = 2;
    std::size_t monitored_network_limit = 16;
};

struct DeviceInventoryRecord {
    std::string device_id;
    std::string hostname;
    std::vector<std::string> ip_addresses;
    std::string mac_address;
    std::string vendor_hint;
    std::string device_type;
    std::vector<std::string> user_labels;
    std::vector<int> open_tcp_ports;
    int importance = 0;
    bool hidden = false;
    bool stale = false;
    std::string details;
    std::string last_seen_utc;
};

struct DeviceInventoryPatch {
    std::optional<std::string> device_type;
    std::optional<std::vector<std::string>> user_labels;
    std::optional<int> importance;
    std::optional<bool> hidden;
    std::optional<bool> stale;
};

Result<std::size_t> current_schema_version(const StorageConfig& config);
Result<std::size_t> migrate_schema(const StorageConfig& config);
Result<std::int64_t> save_scan_session(
    const netsentinel::engine::ScanProfile& profile,
    const netsentinel::engine::ScanSession& session,
    const StorageConfig& config = {}
);
Result<netsentinel::engine::ScanSession> load_scan_session(std::int64_t session_id, const StorageConfig& config = {});
Result<std::string> export_scan_session_json(std::int64_t session_id, const StorageConfig& config = {});
Result<std::vector<DeviceInventoryRecord>> list_inventory_records(
    const StorageConfig& config = {},
    bool include_hidden = false
);
Result<DeviceInventoryRecord> get_inventory_record(
    const std::string& device_id,
    const StorageConfig& config = {}
);
Result<std::size_t> upsert_inventory_record(
    const DeviceInventoryRecord& record,
    const StorageConfig& config = {}
);
Result<std::size_t> patch_inventory_record(
    const std::string& device_id,
    const DeviceInventoryPatch& patch,
    const StorageConfig& config = {}
);
Result<std::size_t> hide_stale_inventory_records(const StorageConfig& config = {});
Result<std::string> export_inventory_records_json(const StorageConfig& config = {});
struct DeviceTimelineRecord {
    std::string device_id;
    std::string network_id;
    std::string event_type;
    std::string source;
    int severity = 0;
    std::string old_value;
    std::string new_value;
    std::string at_utc;
};

struct TimelineFilter {
    std::optional<std::string> network_id;
    std::optional<std::string> device_id;
    std::optional<std::string> event_type;
    std::optional<std::string> from_utc;
    std::optional<std::string> to_utc;
};

struct DevicePresenceHistoryConfig {
    std::string network_id{};
    std::string now_utc{};
    std::string cutoff_utc{};
    std::size_t retention_days = 30;
    bool include_unlabeled_devices = false;
};

struct DevicePresenceRecord {
    std::string device_id{};
    std::string network_id{};
    std::string device_label{};
    std::string first_seen_utc{};
    std::string last_seen_utc{};
    std::uint64_t dwell_seconds = 0;
    bool currently_present = false;
    bool user_assigned_person = false;
    std::string privacy_notice{};
};

struct DevicePresenceRetentionResult {
    std::size_t before_count = 0;
    std::size_t after_count = 0;
    std::size_t removed_count = 0;
    std::string cutoff_utc{};
    std::string message{};
};

Result<std::size_t> append_timeline_record(
    const DeviceTimelineRecord& record,
    const StorageConfig& config = {}
);
Result<std::vector<DeviceTimelineRecord>> list_timeline_records(
    const StorageConfig& config = {},
    const TimelineFilter& filter = {}
);
Result<std::vector<DeviceTimelineRecord>> generate_timeline_events(
    const std::vector<DeviceInventoryRecord>& previous_snapshot,
    const std::vector<DeviceInventoryRecord>& current_snapshot,
    const std::string& network_id,
    const std::string& source = "manual"
);
Result<std::vector<DevicePresenceRecord>> build_device_presence_history(
    const DevicePresenceHistoryConfig& presence_config,
    const StorageConfig& config = {}
);
Result<DevicePresenceRetentionResult> apply_device_presence_retention(
    const DevicePresenceHistoryConfig& presence_config,
    const StorageConfig& config = {}
);

struct BandwidthRollupRecord {
    std::string source_name;
    std::string device_id;
    std::string adapter_id;
    std::string timestamp_utc;
    std::uint64_t rx_total_bytes = 0;
    std::uint64_t tx_total_bytes = 0;
    double rx_rate_bps = 0.0;
    double tx_rate_bps = 0.0;
    std::string scope = "local-machine";
    std::string confidence;
    std::string notes;
    std::string rollup_granularity = "minute";
    std::string source_metadata;
    bool privacy_redacted = false;
};

struct BandwidthRollupFilter {
    std::optional<std::string> source_name;
    std::optional<std::string> device_id;
    std::optional<std::string> rollup_granularity;
    std::optional<std::string> from_utc;
    std::optional<std::string> to_utc;
};

struct BandwidthPrivacySettings {
    bool redact_device_identifiers = false;
    bool store_source_metadata = true;
};

struct BandwidthRetentionPolicy {
    std::string rollup_granularity = "minute";
    std::size_t retain_days = 30;
    std::string cutoff_utc;
};

struct BandwidthRetentionResult {
    std::size_t before_count = 0;
    std::size_t after_count = 0;
    std::size_t removed_count = 0;
    std::string message;
};

Result<std::size_t> append_bandwidth_rollup(
    const BandwidthRollupRecord& record,
    const StorageConfig& config = {}
);
Result<std::size_t> append_bandwidth_rollup_with_privacy(
    const BandwidthRollupRecord& record,
    const BandwidthPrivacySettings& privacy,
    const StorageConfig& config = {}
);
Result<std::vector<BandwidthRollupRecord>> list_bandwidth_rollups(
    const StorageConfig& config = {},
    const BandwidthRollupFilter& filter = {}
);
Result<BandwidthRetentionResult> apply_bandwidth_retention(
    const BandwidthRetentionPolicy& policy,
    const StorageConfig& config = {}
);

struct NetworkWorkspaceKey {
    std::string gateway_mac;
    std::string subnet;
    std::string ssid;
    std::string user_label;
};

struct NetworkWorkspaceSettings {
    bool monitoring_enabled = true;
    std::size_t monitored_network_limit = 16;
    std::string scan_profile = "standard";
    std::string notes;
};

struct NetworkWorkspaceRecord {
    std::string workspace_id;
    NetworkWorkspaceKey key{};
    NetworkWorkspaceSettings settings{};
    bool active = false;
    std::string created_utc;
    std::string updated_utc;
};

struct WorkspaceScanHistoryRecord {
    std::string workspace_id;
    std::int64_t scan_id = 0;
    std::string status;
    std::string summary;
    std::string at_utc;
};

struct DeviceSearchQuery {
    std::string preset = "all";
    std::string vendor;
    std::string os_guess;
    std::string text;
    std::string network_id;
    std::vector<int> risky_ports{};
    bool include_hidden = false;
};

struct DeviceSearchResult {
    DeviceInventoryRecord device{};
    std::string network_id;
    std::vector<std::string> matched_reasons{};
    int relevance = 0;
};

struct SavedFilterTemplate {
    std::string filter_id;
    std::string name;
    DeviceSearchQuery query{};
    std::string created_utc;
};

Result<NetworkWorkspaceRecord> upsert_network_workspace(
    const NetworkWorkspaceRecord& workspace,
    const StorageConfig& config = {}
);
Result<std::vector<NetworkWorkspaceRecord>> list_network_workspaces(const StorageConfig& config = {});
Result<NetworkWorkspaceRecord> switch_active_network_workspace(
    const std::string& workspace_id,
    const StorageConfig& config = {}
);
Result<NetworkWorkspaceRecord> get_active_network_workspace(const StorageConfig& config = {});
Result<std::size_t> append_workspace_scan_history(
    const WorkspaceScanHistoryRecord& record,
    const StorageConfig& config = {}
);
Result<std::vector<WorkspaceScanHistoryRecord>> list_workspace_scan_history(
    const std::string& workspace_id,
    const StorageConfig& config = {}
);
Result<std::vector<DeviceSearchResult>> search_inventory_devices(
    const DeviceSearchQuery& query,
    const StorageConfig& config = {}
);
Result<SavedFilterTemplate> save_filter_template(
    const SavedFilterTemplate& filter,
    const StorageConfig& config = {}
);
Result<std::vector<SavedFilterTemplate>> list_filter_templates(const StorageConfig& config = {});
Result<std::vector<DeviceSearchResult>> run_saved_filter_template(
    const std::string& filter_id,
    const StorageConfig& config = {}
);

} // namespace netsentinel::storage
