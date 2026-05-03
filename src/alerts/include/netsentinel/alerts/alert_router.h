#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace netsentinel::alerts {

enum class AlertKind {
    new_device = 0,
    important_status_change = 1,
    outage = 2,
    security_finding = 3,
    scan_failure = 4,
    presence = 5
};

struct AlertRoutingConfig {
    bool enable_toast = true;
    bool enable_email = false;
    bool enable_webhook = false;
    bool mock_mode = false;
    std::size_t max_events_per_minute = 30;
    std::string toast_app_id = "NetSentinel11";
    std::string email_from;
    std::string email_to;
    std::string webhook_url;
};

struct AlertEvent {
    AlertKind kind = AlertKind::new_device;
    std::string target_id;
    std::string message;
};

struct AlertOperationResult {
    bool success = false;
    bool rate_limited = false;
    std::string message;
};

struct PresenceProfile {
    std::string profile_id{};
    std::string display_name{};
    std::string privacy_notice{};
};

struct PresenceNotificationObservation {
    std::string device_id{};
    std::string device_label{};
    std::string profile = "unknown";
    std::string event = "online";
    bool user_assigned_person = false;
};

struct PresenceNotificationRule {
    std::string rule_id{};
    std::string profile = "all";
    std::string event = "online";
    bool enabled = true;
    std::string quiet_start_local = "22:00";
    std::string quiet_end_local = "07:00";
};

struct PresenceNotificationConfig {
    bool opt_in = false;
    bool mock_mode = true;
    std::string now_local = "12:00";
    AlertRoutingConfig routing{};
    std::vector<PresenceNotificationObservation> observations{};
    std::vector<PresenceNotificationRule> rules{};
};

struct PresenceNotificationDecision {
    std::string device_id{};
    std::string profile{};
    std::string event{};
    bool matched_rule = false;
    bool quieted = false;
    bool sent = false;
    std::string message{};
    std::string privacy_notice{};
    AlertOperationResult dispatch{};
};

struct PresenceNotificationResult {
    bool success = false;
    bool opt_in = false;
    std::size_t notifications_sent = 0;
    std::vector<PresenceNotificationDecision> decisions{};
    std::vector<std::string> limitations{};
    std::string message{};
};

const char* to_string(AlertKind kind);

AlertOperationResult send_alert(const AlertRoutingConfig& config, const AlertEvent& event);
std::vector<PresenceProfile> default_presence_profiles();
PresenceNotificationResult evaluate_presence_notifications(const PresenceNotificationConfig& config);

bool is_retry_safe_rate_limit(
    std::size_t recent_count,
    std::size_t max_per_minute,
    std::string& reason
);

} // namespace netsentinel::alerts
