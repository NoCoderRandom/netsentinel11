#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace netsentinel::api {

struct PrivacyRetentionDefaults {
    std::size_t inventory_days = 90;
    std::size_t traffic_history_days = 30;
    std::size_t presence_history_days = 14;
    std::size_t log_days = 14;
    std::size_t report_export_days = 30;
};

struct PrivacyMinimizationSettings {
    bool redact_ip_addresses = true;
    bool redact_mac_addresses = true;
    bool redact_hostnames = false;
    bool redact_secrets = true;
    bool require_export_acknowledgement = true;
    PrivacyRetentionDefaults retention{};
};

struct PrivacyReviewRequest {
    PrivacyMinimizationSettings settings{};
    bool export_requested = false;
    bool export_acknowledged = false;
    std::string report_type = "inventory";
    std::vector<std::string> log_lines{};
};

struct PrivacyReviewResult {
    bool success = false;
    bool export_allowed = false;
    PrivacyMinimizationSettings settings{};
    std::vector<std::string> warnings{};
    std::vector<std::string> blockers{};
    std::vector<std::string> redacted_log_preview{};
    std::string message;
};

PrivacyMinimizationSettings default_privacy_minimization_settings();
std::string redact_private_text(const std::string& text, const PrivacyMinimizationSettings& settings);
PrivacyReviewResult run_privacy_review(const PrivacyReviewRequest& request);
std::string privacy_review_markdown(const PrivacyReviewResult& result);

} // namespace netsentinel::api
