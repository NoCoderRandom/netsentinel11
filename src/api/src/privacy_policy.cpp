#include "netsentinel/api/privacy_policy.h"

#include <regex>
#include <sstream>

namespace netsentinel::api {

namespace {

std::string regex_replace_all(const std::string& input, const std::regex& pattern, const std::string& replacement) {
    return std::regex_replace(input, pattern, replacement);
}

std::vector<std::string> default_warnings(const PrivacyReviewRequest& request) {
    std::vector<std::string> warnings;
    warnings.push_back("Local inventories can contain private device names, IP addresses, MAC addresses, vendors, and presence history.");
    warnings.push_back("Traffic history and bandwidth reports can reveal household or business usage patterns.");
    warnings.push_back("Reports should be shared only with authorized recipients.");
    if (request.export_requested) {
        warnings.push_back("Export requested for " + request.report_type + " report; review redaction settings before sharing.");
    }
    return warnings;
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

PrivacyMinimizationSettings default_privacy_minimization_settings() {
    PrivacyMinimizationSettings settings{};
    settings.redact_ip_addresses = true;
    settings.redact_mac_addresses = true;
    settings.redact_hostnames = false;
    settings.redact_secrets = true;
    settings.require_export_acknowledgement = true;
    settings.retention.inventory_days = 90;
    settings.retention.traffic_history_days = 30;
    settings.retention.presence_history_days = 14;
    settings.retention.log_days = 14;
    settings.retention.report_export_days = 30;
    return settings;
}

std::string redact_private_text(const std::string& text, const PrivacyMinimizationSettings& settings) {
    std::string out = text;
    if (settings.redact_secrets) {
        out = regex_replace_all(
            out,
            std::regex{R"((password|token|router-password|community|authorization)\s*[:=]\s*[^ \r\n]+)", std::regex::icase},
            "$1=<secret-redacted>"
        );
        out = regex_replace_all(
            out,
            std::regex{R"(Bearer\s+[A-Za-z0-9._~+/=-]+)", std::regex::icase},
            "Bearer <secret-redacted>"
        );
    }
    if (settings.redact_mac_addresses) {
        out = regex_replace_all(
            out,
            std::regex{R"(\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b)"},
            "<mac-redacted>"
        );
    }
    if (settings.redact_ip_addresses) {
        out = regex_replace_all(
            out,
            std::regex{R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)"},
            "<ip-redacted>"
        );
    }
    return out;
}

PrivacyReviewResult run_privacy_review(const PrivacyReviewRequest& request) {
    PrivacyReviewResult result{};
    result.settings = request.settings;
    result.warnings = default_warnings(request);

    if (request.export_requested && request.settings.require_export_acknowledgement && !request.export_acknowledged) {
        result.blockers.push_back("Report export contains potentially private device data; re-run with explicit export acknowledgement.");
    }

    for (const auto& line : request.log_lines) {
        const auto redacted = redact_private_text(line, request.settings);
        result.redacted_log_preview.push_back(redacted);
        if (redacted != line) {
            result.warnings.push_back("Log line required privacy redaction before sharing.");
        }
    }

    result.export_allowed = request.export_requested ? result.blockers.empty() : true;
    result.success = result.blockers.empty();
    result.message = result.success
        ? "Privacy review passed with minimization settings applied."
        : "Privacy review blocked until privacy warnings are acknowledged.";
    return result;
}

std::string privacy_review_markdown(const PrivacyReviewResult& result) {
    std::ostringstream out;
    out << "# Privacy Threat Model And Data Minimization\n\n";
    out << "## Status\n\n";
    out << "- Success: " << (result.success ? "yes" : "no") << "\n";
    out << "- Export allowed: " << (result.export_allowed ? "yes" : "no") << "\n";
    out << "- Message: " << result.message << "\n\n";
    out << "## Data minimization settings\n\n";
    out << "- Redact IP addresses: " << (result.settings.redact_ip_addresses ? "yes" : "no") << "\n";
    out << "- Redact MAC addresses: " << (result.settings.redact_mac_addresses ? "yes" : "no") << "\n";
    out << "- Redact hostnames: " << (result.settings.redact_hostnames ? "yes" : "no") << "\n";
    out << "- Redact secrets: " << (result.settings.redact_secrets ? "yes" : "no") << "\n";
    out << "- Require export acknowledgement: " << (result.settings.require_export_acknowledgement ? "yes" : "no") << "\n\n";
    out << "## Retention defaults\n\n";
    out << "- Inventory: " << result.settings.retention.inventory_days << " days\n";
    out << "- Traffic history: " << result.settings.retention.traffic_history_days << " days\n";
    out << "- Presence history: " << result.settings.retention.presence_history_days << " days\n";
    out << "- Logs: " << result.settings.retention.log_days << " days\n";
    out << "- Report exports: " << result.settings.retention.report_export_days << " days\n\n";
    out << "## Warnings\n\n";
    out << markdown_list(result.warnings) << "\n";
    out << "## Blockers\n\n";
    out << markdown_list(result.blockers) << "\n";
    out << "## Redacted log preview\n\n";
    out << markdown_list(result.redacted_log_preview);
    return out.str();
}

} // namespace netsentinel::api
