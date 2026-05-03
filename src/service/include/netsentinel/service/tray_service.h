#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace netsentinel::service {

struct TrayMonitorConfig {
    std::string profile = "monitor";
    std::string scope = "192.168.1.0/24";
    std::size_t interval_minutes = 2;
    std::size_t crash_restart_limit = 3;
    bool visible_user_control = true;
    bool mock_mode = false;
};

struct TrayStatus {
    bool running = false;
    bool mock_mode = false;
    std::string profile = "monitor";
    std::string scope = "192.168.1.0/24";
    std::size_t interval_minutes = 2;
    std::string mode = "stub";
    std::string last_update_utc = "";
    bool service_optional = true;
    bool visible_user_control = true;
    bool crash_recovery_enabled = true;
    bool hidden_persistence = false;
    std::size_t crash_restart_limit = 3;
    std::size_t crash_restart_count = 0;
    std::string log_path = "";
};

struct TrayHardeningPlan {
    bool mock_mode = false;
    bool service_optional = true;
    bool visible_user_control = true;
    bool crash_recovery_enabled = true;
    bool hidden_persistence_allowed = false;
    bool uninstall_cleanup_available = true;
    std::size_t crash_restart_limit = 3;
    std::string state_path;
    std::string log_path;
    std::vector<std::string> controls{};
    std::vector<std::string> cleanup_actions{};
    std::vector<std::string> limitations{};
};

enum class TrayOperationCode {
    ok = 0,
    io_error = 1,
    parse_error = 2
};

struct TrayOperationResult {
    bool success = false;
    TrayOperationCode code = TrayOperationCode::parse_error;
    std::string message;
};

bool is_tray_controller_supported();

const char* to_string(TrayOperationCode code);

TrayOperationResult get_tray_status(TrayStatus& status, bool mock_mode);

TrayOperationResult start_tray_monitoring(const TrayMonitorConfig& config, bool mock_mode);

TrayOperationResult stop_tray_monitoring(bool mock_mode);

TrayOperationResult cleanup_tray_monitoring(bool mock_mode);

TrayHardeningPlan build_tray_hardening_plan(bool mock_mode);

std::string tray_hardening_plan_markdown(const TrayHardeningPlan& plan);

} // namespace netsentinel::service
