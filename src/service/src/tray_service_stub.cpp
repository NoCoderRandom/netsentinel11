#include "netsentinel/service/tray_service.h"

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>

namespace netsentinel::service {

namespace {

std::string normalize_scope(std::string scope) {
    if (scope.empty()) {
        return "192.168.1.0/24";
    }
    return scope;
}

std::string sanitize_message(std::string text) {
    if (text.empty()) {
        return "(not set)";
    }
    return text;
}

std::filesystem::path get_state_directory() {
    if (const char* override = std::getenv("NETSENTINEL_TRAY_STATE_DIR")) {
        if (*override != '\0') {
            return std::filesystem::path{override};
        }
    }
    const char* path = std::getenv("LOCALAPPDATA");
    if (path == nullptr || *path == '\0') {
        path = std::getenv("TEMP");
    }
    if (path == nullptr || *path == '\0') {
        path = std::getenv("TMP");
    }
    if (path == nullptr || *path == '\0') {
        path = ".";
    }
    return std::filesystem::path{path} / "NetSentinel11";
}

std::filesystem::path get_state_path(bool mock_mode) {
    const auto file_name = mock_mode ? "tray-state-mock.txt" : "tray-state.txt";
    return get_state_directory() / file_name;
}

std::filesystem::path get_log_path(bool mock_mode) {
    const auto file_name = mock_mode ? "tray-log-mock.txt" : "tray-log.txt";
    return get_state_directory() / file_name;
}

std::string now_utc_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string{buffer};
}

TrayOperationResult ok_result(std::string message) {
    return TrayOperationResult{
        .success = true,
        .code = TrayOperationCode::ok,
        .message = std::move(message)
    };
}

TrayOperationResult failure(TrayOperationCode code, std::string message) {
    return TrayOperationResult{
        .success = false,
        .code = code,
        .message = std::move(message)
    };
}

bool parse_bool(std::string_view value) {
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

std::size_t parse_size_or_default(const std::string& value, std::size_t fallback) {
    try {
        return std::stoull(value);
    } catch (...) {
        return fallback;
    }
}

TrayOperationResult read_state_file(const std::filesystem::path& path, TrayStatus& status) {
    if (!std::filesystem::exists(path)) {
        return ok_result("No tray state file exists yet. Showing defaults.");
    }

    std::ifstream stream{path};
    if (!stream.is_open()) {
        return failure(TrayOperationCode::io_error, "Unable to open tray state file.");
    }

    std::string line;
    while (std::getline(stream, line)) {
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }
        const auto key = line.substr(0, separator);
        const auto value = line.substr(separator + 1);
        if (key == "running") {
            status.running = parse_bool(value);
        } else if (key == "mock") {
            status.mock_mode = parse_bool(value);
        } else if (key == "profile") {
            status.profile = value.empty() ? status.profile : value;
        } else if (key == "scope") {
            status.scope = value.empty() ? status.scope : value;
        } else if (key == "interval") {
            status.interval_minutes = parse_size_or_default(value, status.interval_minutes);
        } else if (key == "mode") {
            status.mode = value.empty() ? status.mode : value;
        } else if (key == "updated") {
            status.last_update_utc = value;
        } else if (key == "optional") {
            status.service_optional = parse_bool(value);
        } else if (key == "visible") {
            status.visible_user_control = parse_bool(value);
        } else if (key == "crash_recovery") {
            status.crash_recovery_enabled = parse_bool(value);
        } else if (key == "hidden_persistence") {
            status.hidden_persistence = parse_bool(value);
        } else if (key == "restart_limit") {
            status.crash_restart_limit = parse_size_or_default(value, status.crash_restart_limit);
        } else if (key == "restart_count") {
            status.crash_restart_count = parse_size_or_default(value, status.crash_restart_count);
        } else if (key == "log_path") {
            status.log_path = value;
        }
    }
    if (!stream.eof() && stream.fail()) {
        return failure(TrayOperationCode::io_error, "Failed while reading tray state file.");
    }
    return ok_result("Tray status loaded.");
}

TrayOperationResult write_state_file(const std::filesystem::path& path, const TrayStatus& status) {
    std::error_code error;
    const auto directory = path.parent_path();
    if (!std::filesystem::exists(directory) && !std::filesystem::create_directories(directory, error)) {
        return failure(TrayOperationCode::io_error, "Unable to create tray state directory.");
    }

    std::ofstream stream{path, std::ios::trunc};
    if (!stream.is_open()) {
        return failure(TrayOperationCode::io_error, "Unable to write tray state file.");
    }
    stream << "running=" << (status.running ? 1 : 0) << "\n";
    stream << "mock=" << (status.mock_mode ? 1 : 0) << "\n";
    stream << "profile=" << status.profile << "\n";
    stream << "scope=" << status.scope << "\n";
    stream << "interval=" << status.interval_minutes << "\n";
    stream << "mode=" << status.mode << "\n";
    stream << "updated=" << status.last_update_utc << "\n";
    stream << "optional=" << (status.service_optional ? 1 : 0) << "\n";
    stream << "visible=" << (status.visible_user_control ? 1 : 0) << "\n";
    stream << "crash_recovery=" << (status.crash_recovery_enabled ? 1 : 0) << "\n";
    stream << "hidden_persistence=" << (status.hidden_persistence ? 1 : 0) << "\n";
    stream << "restart_limit=" << status.crash_restart_limit << "\n";
    stream << "restart_count=" << status.crash_restart_count << "\n";
    stream << "log_path=" << status.log_path << "\n";
    if (!stream.good()) {
        return failure(TrayOperationCode::io_error, "Unable to fully write tray state file.");
    }
    return ok_result("Tray state persisted.");
}

TrayOperationResult append_log(bool mock_mode, std::string_view action, std::string_view message) {
    const auto path = get_log_path(mock_mode);
    std::error_code error;
    const auto directory = path.parent_path();
    if (!std::filesystem::exists(directory) && !std::filesystem::create_directories(directory, error)) {
        return failure(TrayOperationCode::io_error, "Unable to create tray log directory.");
    }
    std::ofstream stream{path, std::ios::app};
    if (!stream.is_open()) {
        return failure(TrayOperationCode::io_error, "Unable to write tray log file.");
    }
    stream << now_utc_iso8601() << " action=" << action << " mock=" << (mock_mode ? 1 : 0)
           << " message=" << message << "\n";
    if (!stream.good()) {
        return failure(TrayOperationCode::io_error, "Unable to fully write tray log file.");
    }
    return ok_result("Tray log updated.");
}

TrayStatus default_status(bool mock_mode, const TrayMonitorConfig& config, bool running) {
    TrayStatus status{};
    status.running = running;
    status.mock_mode = mock_mode;
    status.profile = sanitize_message(config.profile);
    status.scope = normalize_scope(config.scope);
    status.interval_minutes = config.interval_minutes;
    status.mode = "visible-stub";
    status.last_update_utc = now_utc_iso8601();
    status.service_optional = true;
    status.visible_user_control = config.visible_user_control;
    status.crash_recovery_enabled = true;
    status.hidden_persistence = false;
    status.crash_restart_limit = config.crash_restart_limit;
    status.crash_restart_count = 0;
    status.log_path = get_log_path(mock_mode).string();
    return status;
}

void ensure_monitor_defaults(TrayMonitorConfig& config) {
    if (config.interval_minutes == 0) {
        config.interval_minutes = 2;
    }
    if (config.crash_restart_limit == 0) {
        config.crash_restart_limit = 3;
    }
    if (config.profile.empty()) {
        config.profile = "monitor";
    }
    config.scope = normalize_scope(config.scope);
}

std::vector<std::string> hardening_controls() {
    return {
        "service-is-optional",
        "tray-control-is-visible",
        "start-stop-status-commands-available",
        "plain-text-local-log-path-is-disclosed",
        "crash-recovery-has-bounded-restart-limit",
        "uninstall-cleanup-removes-state-and-logs",
        "no-hidden-persistence-or-stealth-mode"
    };
}

std::vector<std::string> cleanup_actions() {
    return {
        "stop monitoring before removal",
        "remove tray state file",
        "remove tray log file",
        "leave no hidden startup task from this stub layer"
    };
}

std::vector<std::string> hardening_limitations() {
    return {
        "this stage does not install a real Windows service",
        "service manager recovery policy must be applied by a future installer step",
        "native tray UI still depends on the GUI/tray executable integration"
    };
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

bool is_tray_controller_supported() {
    return true;
}

const char* to_string(TrayOperationCode code) {
    switch (code) {
        case TrayOperationCode::ok:
            return "ok";
        case TrayOperationCode::io_error:
            return "io-error";
        case TrayOperationCode::parse_error:
            return "parse-error";
        default:
            return "parse-error";
    }
}

TrayOperationResult get_tray_status(TrayStatus& status, bool mock_mode) {
    auto config = TrayMonitorConfig{};
    ensure_monitor_defaults(config);
    status = default_status(mock_mode, config, false);
    return read_state_file(get_state_path(mock_mode), status);
}

TrayOperationResult start_tray_monitoring(const TrayMonitorConfig& config, bool mock_mode) {
    TrayMonitorConfig normalized = config;
    ensure_monitor_defaults(normalized);
    TrayStatus status = default_status(mock_mode, normalized, true);
    if (!is_tray_controller_supported()) {
        return failure(TrayOperationCode::io_error, "Tray controller is not available on this platform.");
    }
    const auto result = write_state_file(get_state_path(mock_mode), status);
    if (!result.success) {
        return result;
    }
    const auto log_result = append_log(mock_mode, "start", "visible optional tray monitoring started");
    if (!log_result.success) {
        return log_result;
    }

    return ok_result("Tray monitoring stub started with visible controls and bounded crash recovery.");
}

TrayOperationResult stop_tray_monitoring(bool mock_mode) {
    auto config = TrayMonitorConfig{};
    ensure_monitor_defaults(config);
    TrayStatus status = default_status(mock_mode, config, false);
    if (!is_tray_controller_supported()) {
        return failure(TrayOperationCode::io_error, "Tray controller is not available on this platform.");
    }
    const auto result = write_state_file(get_state_path(mock_mode), status);
    if (!result.success) {
        return result;
    }
    const auto log_result = append_log(mock_mode, "stop", "visible optional tray monitoring stopped");
    if (!log_result.success) {
        return log_result;
    }
    return ok_result("Tray monitoring stub stopped.");
}

TrayOperationResult cleanup_tray_monitoring(bool mock_mode) {
    if (!is_tray_controller_supported()) {
        return failure(TrayOperationCode::io_error, "Tray controller is not available on this platform.");
    }

    std::error_code error;
    const auto state_path = get_state_path(mock_mode);
    if (std::filesystem::exists(state_path, error) && !std::filesystem::remove(state_path, error)) {
        return failure(TrayOperationCode::io_error, "Unable to remove tray state file during cleanup.");
    }
    error.clear();
    const auto log_path = get_log_path(mock_mode);
    if (std::filesystem::exists(log_path, error) && !std::filesystem::remove(log_path, error)) {
        return failure(TrayOperationCode::io_error, "Unable to remove tray log file during cleanup.");
    }
    return ok_result("Tray monitoring cleanup completed; state and logs removed when present.");
}

TrayHardeningPlan build_tray_hardening_plan(bool mock_mode) {
    TrayHardeningPlan plan{};
    plan.mock_mode = mock_mode;
    plan.service_optional = true;
    plan.visible_user_control = true;
    plan.crash_recovery_enabled = true;
    plan.hidden_persistence_allowed = false;
    plan.uninstall_cleanup_available = true;
    plan.crash_restart_limit = 3;
    plan.state_path = get_state_path(mock_mode).string();
    plan.log_path = get_log_path(mock_mode).string();
    plan.controls = hardening_controls();
    plan.cleanup_actions = cleanup_actions();
    plan.limitations = hardening_limitations();
    return plan;
}

std::string tray_hardening_plan_markdown(const TrayHardeningPlan& plan) {
    std::ostringstream out;
    out << "# Windows Service And Tray Hardening\n\n";
    out << "## Status\n\n";
    out << "- Mock mode: " << (plan.mock_mode ? "yes" : "no") << "\n";
    out << "- Service optional: " << (plan.service_optional ? "yes" : "no") << "\n";
    out << "- Visible user control: " << (plan.visible_user_control ? "yes" : "no") << "\n";
    out << "- Crash recovery enabled: " << (plan.crash_recovery_enabled ? "yes" : "no") << "\n";
    out << "- Crash restart limit: " << plan.crash_restart_limit << "\n";
    out << "- Hidden persistence allowed: " << (plan.hidden_persistence_allowed ? "yes" : "no") << "\n";
    out << "- Uninstall cleanup available: " << (plan.uninstall_cleanup_available ? "yes" : "no") << "\n";
    out << "- State path: " << plan.state_path << "\n";
    out << "- Log path: " << plan.log_path << "\n\n";
    out << "## Controls\n\n";
    out << markdown_list(plan.controls) << "\n";
    out << "## Uninstall cleanup actions\n\n";
    out << markdown_list(plan.cleanup_actions) << "\n";
    out << "## Limitations\n\n";
    out << markdown_list(plan.limitations);
    return out.str();
}

} // namespace netsentinel::service
