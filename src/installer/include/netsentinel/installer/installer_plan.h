#pragma once

#include <string>
#include <vector>

namespace netsentinel::installer {

struct InstallerPackagingConfig {
    std::string package_format = "wix";
    std::string install_scope = "per-user";
    std::string install_location = "%LOCALAPPDATA%\\Programs\\NetSentinel11";
    bool include_service = true;
    bool include_tray = true;
    bool require_npcap = false;
    bool request_firewall_permission = false;
    bool enable_auto_update = false;
    std::string code_signing_subject = "CN=NetSentinel11 Placeholder";
};

struct InstallerPackagingPlan {
    bool success = false;
    std::string package_format;
    std::string install_location;
    std::vector<std::string> packaging_steps{};
    std::vector<std::string> permission_explanations{};
    std::vector<std::string> optional_dependency_checks{};
    std::vector<std::string> uninstall_cleanup{};
    std::vector<std::string> upgrade_migration{};
    std::vector<std::string> warnings{};
    std::string message;
};

struct ReleaseCandidateConfig {
    bool mock_mode = true;
    bool qt_gui_available = false;
    bool include_npcap_features = false;
    bool include_router_integrations = false;
    bool include_service = true;
    bool include_tray = true;
    std::string version = "0.1.0-rc";
};

struct ReleaseCandidateReadiness {
    bool success = false;
    bool release_ready = false;
    std::string version;
    std::vector<std::string> onboarding_steps{};
    std::vector<std::string> safe_defaults{};
    std::vector<std::string> installer_disclosures{};
    std::vector<std::string> checklist{};
    std::vector<std::string> changelog{};
    std::vector<std::string> blockers{};
    std::vector<std::string> warnings{};
    std::string message;
};

InstallerPackagingPlan generate_installer_packaging_plan(const InstallerPackagingConfig& config);
std::string installer_plan_markdown(const InstallerPackagingPlan& plan);
ReleaseCandidateReadiness generate_release_candidate_readiness(const ReleaseCandidateConfig& config);
std::string release_candidate_readiness_markdown(const ReleaseCandidateReadiness& readiness);
std::string release_candidate_changelog_markdown(const ReleaseCandidateReadiness& readiness);

} // namespace netsentinel::installer
