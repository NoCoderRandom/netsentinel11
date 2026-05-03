#include "netsentinel/alerts/alert_router.h"

#include <chrono>
#include <cctype>
#include <fstream>
#include <string_view>
#include <vector>

#include <cstdlib>
#include <filesystem>
#include <sstream>

namespace netsentinel::alerts {

namespace {

std::filesystem::path state_directory() {
    if (const char* override = std::getenv("NETSENTINEL_ALERT_STATE_DIR")) {
        if (*override != '\0') {
            return std::filesystem::path{override};
        }
    }
    const char* local = std::getenv("LOCALAPPDATA");
    if (local == nullptr || *local == '\0') {
        local = std::getenv("TEMP");
    }
    if (local == nullptr || *local == '\0') {
        local = ".";
    }
    return std::filesystem::path{local} / "NetSentinel11";
}

std::string kind_to_string(AlertKind kind) {
    switch (kind) {
        case AlertKind::new_device:
            return "new-device";
        case AlertKind::important_status_change:
            return "status-change";
        case AlertKind::outage:
            return "outage";
        case AlertKind::security_finding:
            return "security-finding";
        case AlertKind::scan_failure:
            return "scan-failure";
        case AlertKind::presence:
            return "presence";
        default:
            return "unknown";
    }
}

std::filesystem::path rate_limit_path() {
    return state_directory() / "alerts-rate-state.txt";
}

std::filesystem::path history_path() {
    return state_directory() / "alerts-history-mock.txt";
}

std::vector<std::uint64_t> read_recent_event_times(std::uint64_t now_epoch_seconds) {
    std::vector<std::uint64_t> out;
    const auto path = rate_limit_path();
    std::ifstream stream{path};
    if (!stream.is_open()) {
        return out;
    }

    std::string line;
    while (std::getline(stream, line)) {
        try {
            auto parsed = std::stoull(line);
            if (now_epoch_seconds - parsed <= 60) {
                out.push_back(parsed);
            }
        } catch (...) {
            continue;
        }
    }
    return out;
}

void append_event_time(std::uint64_t now_epoch_seconds) {
    const auto path = rate_limit_path();
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream{path, std::ios::app};
    if (stream.is_open()) {
        stream << now_epoch_seconds << "\n";
    }
}

void append_mock_history(const AlertEvent& event, bool toast_enabled, bool email_enabled, bool webhook_enabled, const std::string& result_message) {
    const auto path = history_path();
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream{path, std::ios::app};
    if (!stream.is_open()) {
        return;
    }

    std::uint64_t now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    stream << now << "," << kind_to_string(event.kind) << ",toast=" << (toast_enabled ? 1 : 0)
           << ",email=" << (email_enabled ? 1 : 0)
           << ",webhook=" << (webhook_enabled ? 1 : 0)
           << ",target=" << event.target_id << ",message=" << event.message << ",result=" << result_message << "\n";
}

AlertOperationResult blocked_due_to_rate_limit(std::size_t recent_count, std::size_t max_per_minute) {
    std::ostringstream out;
    out << "Rate limit reached: " << recent_count << " alerts in last 60s, max " << max_per_minute;
    return AlertOperationResult{
        .success = false,
        .rate_limited = true,
        .message = out.str()
    };
}

} // namespace

const char* to_string(AlertKind kind) {
    switch (kind) {
        case AlertKind::new_device:
            return "new_device";
        case AlertKind::important_status_change:
            return "important_status_change";
        case AlertKind::outage:
            return "outage";
        case AlertKind::security_finding:
            return "security_finding";
        case AlertKind::scan_failure:
            return "scan_failure";
        case AlertKind::presence:
            return "presence";
        default:
            return "unknown";
    }
}

bool is_retry_safe_rate_limit(std::size_t recent_count, std::size_t max_per_minute, std::string& reason) {
    if (recent_count <= max_per_minute) {
        return true;
    }
    std::ostringstream out;
    out << "Rate limit exceeded: " << recent_count << " events in 60 seconds";
    reason = out.str();
    return false;
}

AlertOperationResult send_alert(const AlertRoutingConfig& config, const AlertEvent& event) {
    if (event.message.empty()) {
        return AlertOperationResult{
            .success = false,
            .rate_limited = false,
            .message = "Alert payload missing message."
        };
    }
    if (config.max_events_per_minute == 0) {
        return AlertOperationResult{
            .success = false,
            .rate_limited = false,
            .message = "Invalid max_events_per_minute (must be greater than zero)."
        };
    }

    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto now_seconds = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now).count());
    const auto recent = read_recent_event_times(now_seconds);
    std::string reason;
    if (!is_retry_safe_rate_limit(recent.size(), config.max_events_per_minute, reason)) {
        return blocked_due_to_rate_limit(recent.size(), config.max_events_per_minute);
    }

    append_event_time(now_seconds);

    const bool toast_enabled = config.enable_toast;
    const bool email_enabled = config.enable_email;
    const bool webhook_enabled = config.enable_webhook;

    if (!toast_enabled && !email_enabled && !webhook_enabled) {
        append_mock_history(event, false, false, false, "No notification channels configured.");
        return AlertOperationResult{
            .success = true,
            .rate_limited = false,
            .message = "No channels enabled; alert recorded for privacy-safe audit."
        };
    }
    if (config.mock_mode) {
        append_mock_history(event, toast_enabled, email_enabled, webhook_enabled, "mock-dispatch");
        return AlertOperationResult{
            .success = true,
            .rate_limited = false,
            .message = "Alert routed in mock mode: " + kind_to_string(event.kind)
        };
    }

    if (!email_enabled && !webhook_enabled && toast_enabled) {
        append_mock_history(event, true, false, false, "stub-toast");
        return AlertOperationResult{
            .success = true,
            .rate_limited = false,
            .message = "Toast dispatch planned (stubbed on non-mock mode)."
        };
    }
    if (email_enabled && !webhook_enabled) {
        append_mock_history(event, toast_enabled, true, false, "stub-email");
        return AlertOperationResult{
            .success = true,
            .rate_limited = false,
            .message = "Email dispatch planned (stubbed on non-mock mode)."
        };
    }
    append_mock_history(event, toast_enabled, email_enabled, webhook_enabled, "stub-webhook");
    return AlertOperationResult{
        .success = true,
        .rate_limited = false,
        .message = "Webhook dispatch planned (stubbed on non-mock mode)."
    };
}

std::string alert_lower_copy(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char ch : text) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

bool parse_alert_minutes(std::string_view text, int& minutes_out) {
    if (text.size() < 5 || text[2] != ':') {
        return false;
    }
    try {
        const int hours = std::stoi(std::string{text.substr(0, 2)});
        const int minutes = std::stoi(std::string{text.substr(3, 2)});
        if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) {
            return false;
        }
        minutes_out = hours * 60 + minutes;
        return true;
    } catch (...) {
        return false;
    }
}

std::string alert_time_token(std::string_view now_local) {
    if (now_local.size() >= 5 && std::isdigit(static_cast<unsigned char>(now_local[0])) && now_local[2] == ':') {
        return std::string{now_local.substr(0, 5)};
    }
    const auto t_pos = now_local.find('T');
    if (t_pos != std::string_view::npos && t_pos > 0 && t_pos + 5 < now_local.size()) {
        return std::string{now_local.substr(t_pos + 1, 5)};
    }
    const auto space_pos = now_local.rfind(' ');
    if (space_pos != std::string_view::npos && space_pos + 5 < now_local.size()) {
        return std::string{now_local.substr(space_pos + 1, 5)};
    }
    return "12:00";
}

bool quiet_hours_active(const PresenceNotificationRule& rule, std::string_view now_local) {
    int start = 0;
    int end = 0;
    int now = 0;
    if (!parse_alert_minutes(rule.quiet_start_local, start) ||
        !parse_alert_minutes(rule.quiet_end_local, end) ||
        !parse_alert_minutes(alert_time_token(now_local), now)) {
        return false;
    }
    if (start == end) {
        return false;
    }
    return start < end ? (now >= start && now < end) : (now >= start || now < end);
}

std::string normalize_presence_event(std::string_view event) {
    const auto lower = alert_lower_copy(event);
    if (lower == "join" || lower == "came-online" || lower == "online") {
        return "online";
    }
    if (lower == "leave" || lower == "went-offline" || lower == "offline") {
        return "offline";
    }
    if (lower == "appeared") {
        return "appeared";
    }
    return lower.empty() ? std::string{"online"} : lower;
}

std::string normalize_presence_profile(std::string_view profile) {
    const auto lower = alert_lower_copy(profile);
    if (lower == "child" || lower == "kid" || lower == "kids" || lower == "family") {
        return "family";
    }
    if (lower == "guest" || lower == "guests") {
        return "guest";
    }
    if (lower == "work" || lower == "office") {
        return "work";
    }
    if (lower == "iot" || lower == "unknown-iot") {
        return "unknown";
    }
    return lower.empty() ? std::string{"unknown"} : lower;
}

std::vector<PresenceNotificationObservation> default_presence_observations() {
    return {
        PresenceNotificationObservation{.device_id = "child-phone", .device_label = "child phone", .profile = "family", .event = "online", .user_assigned_person = false},
        PresenceNotificationObservation{.device_id = "guest-device", .device_label = "guest device", .profile = "guest", .event = "online", .user_assigned_person = false},
        PresenceNotificationObservation{.device_id = "work-laptop", .device_label = "work laptop", .profile = "work", .event = "offline", .user_assigned_person = false},
        PresenceNotificationObservation{.device_id = "unknown-iot", .device_label = "unknown IoT device", .profile = "unknown", .event = "online", .user_assigned_person = false}
    };
}

std::vector<PresenceNotificationRule> default_presence_rules() {
    return {
        PresenceNotificationRule{.rule_id = "family-online", .profile = "family", .event = "online", .enabled = true},
        PresenceNotificationRule{.rule_id = "guest-online", .profile = "guest", .event = "online", .enabled = true},
        PresenceNotificationRule{.rule_id = "work-offline", .profile = "work", .event = "offline", .enabled = true},
        PresenceNotificationRule{.rule_id = "unknown-online", .profile = "unknown", .event = "online", .enabled = true}
    };
}

bool rule_matches_observation(const PresenceNotificationRule& rule, const PresenceNotificationObservation& observation) {
    if (!rule.enabled) {
        return false;
    }
    const auto rule_profile = normalize_presence_profile(rule.profile);
    const auto observation_profile = normalize_presence_profile(observation.profile);
    const auto rule_event = normalize_presence_event(rule.event);
    const auto observation_event = normalize_presence_event(observation.event);
    const bool profile_matches = rule_profile == "all" || rule_profile == observation_profile;
    const bool event_matches = rule_event == "all" || rule_event == observation_event;
    return profile_matches && event_matches;
}

std::string presence_message(const PresenceNotificationObservation& observation) {
    const auto profile = normalize_presence_profile(observation.profile);
    const auto event = normalize_presence_event(observation.event);
    const auto label = observation.device_label.empty() ? observation.device_id : observation.device_label;
    if (profile == "guest" && event == "online") {
        return "Guest device appeared: " + label;
    }
    if (profile == "work" && event == "offline") {
        return "Work device went offline: " + label;
    }
    if (profile == "unknown" && event == "online") {
        return "Unknown IoT device appeared: " + label;
    }
    if (profile == "family" && event == "online") {
        return "Family device came online: " + label;
    }
    return "Presence update for " + label + ": " + event;
}

std::string presence_privacy_notice(const PresenceNotificationObservation& observation) {
    if (observation.user_assigned_person) {
        return "User explicitly assigned this device to a household member profile.";
    }
    return "Device presence notification only; NetSentinel does not infer a person from this device.";
}

std::vector<PresenceProfile> default_presence_profiles() {
    return {
        PresenceProfile{.profile_id = "family", .display_name = "Family devices", .privacy_notice = "Family notifications are opt-in and device-based unless a user assigns a person label."},
        PresenceProfile{.profile_id = "guest", .display_name = "Guest devices", .privacy_notice = "Guest notifications are opt-in and can be edited or disabled."},
        PresenceProfile{.profile_id = "work", .display_name = "Work devices", .privacy_notice = "Work notifications track device availability, not employee presence."},
        PresenceProfile{.profile_id = "unknown", .display_name = "Unknown or IoT devices", .privacy_notice = "Unknown-device notifications are security-oriented and do not identify people."}
    };
}

PresenceNotificationResult evaluate_presence_notifications(const PresenceNotificationConfig& config) {
    PresenceNotificationResult result{};
    result.success = true;
    result.opt_in = config.opt_in;
    result.limitations = {
        "Presence notifications are opt-in and editable.",
        "Quiet hours suppress sends by default.",
        "Notifications are based on device labels and profiles; people are not inferred unless explicitly assigned by the user."
    };

    const auto observations = config.observations.empty() ? default_presence_observations() : config.observations;
    const auto rules = config.rules.empty() ? default_presence_rules() : config.rules;
    if (!config.opt_in) {
        for (const auto& observation : observations) {
            PresenceNotificationDecision decision{};
            decision.device_id = observation.device_id;
            decision.profile = normalize_presence_profile(observation.profile);
            decision.event = normalize_presence_event(observation.event);
            decision.matched_rule = false;
            decision.quieted = false;
            decision.sent = false;
            decision.message = "Notifications are disabled until the user opts in.";
            decision.privacy_notice = presence_privacy_notice(observation);
            result.decisions.push_back(std::move(decision));
        }
        result.message = "Presence notifications are opt-in; no notifications were sent.";
        return result;
    }

    AlertRoutingConfig routing = config.routing;
    routing.mock_mode = config.mock_mode;
    if (!routing.enable_toast && !routing.enable_email && !routing.enable_webhook) {
        routing.enable_toast = true;
    }

    for (const auto& observation : observations) {
        PresenceNotificationDecision decision{};
        decision.device_id = observation.device_id;
        decision.profile = normalize_presence_profile(observation.profile);
        decision.event = normalize_presence_event(observation.event);
        decision.privacy_notice = presence_privacy_notice(observation);

        for (const auto& rule : rules) {
            if (!rule_matches_observation(rule, observation)) {
                continue;
            }
            decision.matched_rule = true;
            decision.quieted = quiet_hours_active(rule, config.now_local);
            decision.message = presence_message(observation);
            if (decision.quieted) {
                decision.sent = false;
                decision.dispatch = AlertOperationResult{.success = true, .rate_limited = false, .message = "Quiet hours active; notification suppressed."};
                break;
            }
            decision.dispatch = send_alert(
                routing,
                AlertEvent{.kind = AlertKind::presence, .target_id = observation.device_id, .message = decision.message}
            );
            decision.sent = decision.dispatch.success && !decision.dispatch.rate_limited;
            if (decision.sent) {
                ++result.notifications_sent;
            }
            break;
        }
        if (!decision.matched_rule) {
            decision.message = "No editable presence notification rule matched this device/profile/event.";
        }
        if (decision.dispatch.rate_limited) {
            result.success = false;
        }
        result.decisions.push_back(std::move(decision));
    }

    result.message = "Presence notification rules evaluated.";
    return result;
}

} // namespace netsentinel::alerts
