#include "netsentinel/installer/installer_plan.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace netsentinel::installer {

namespace {

std::string lower_copy(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        }
    );
    return value;
}

void append_common_plan(InstallerPackagingPlan& plan, const InstallerPackagingConfig& config) {
    plan.packaging_steps.push_back("Build Release binaries with CMake/MSVC before packaging.");
    plan.packaging_steps.push_back("Stage netsentinel11.exe, optional netsentinel11_gui.exe when Qt6 is available, licenses, README, and safety contract.");
    plan.packaging_steps.push_back("Install to " + config.install_location + " using " + config.install_scope + " scope.");
    if (config.include_tray) {
        plan.packaging_steps.push_back("Register tray startup shortcut only after explicit user opt-in.");
    }
    if (config.include_service) {
        plan.packaging_steps.push_back("Install service component disabled-by-default; enable only through explicit Settings confirmation.");
    }
    plan.packaging_steps.push_back("Use code signing subject placeholder: " + config.code_signing_subject + ".");

    plan.permission_explanations.push_back("Npcap is optional and must be detected; never install packet capture drivers silently.");
    plan.permission_explanations.push_back("Firewall prompts must explain local-only API binding and any local Windows Firewall rule before asking for consent.");
    plan.permission_explanations.push_back("Service/tray permissions are optional and should be reversible from Settings and uninstall.");
    plan.permission_explanations.push_back("The local REST API remains disabled by default and bound to 127.0.0.1 with token auth.");

    plan.optional_dependency_checks.push_back("Check Qt6 runtime only when native GUI executable is packaged.");
    plan.optional_dependency_checks.push_back("Check Npcap presence when packet capture sources are enabled; fall back to non-capture bandwidth sources when absent.");
    plan.optional_dependency_checks.push_back("Check VC++ runtime availability or bundle the redistributable according to Microsoft licensing.");

    plan.uninstall_cleanup.push_back("Remove tray startup shortcut.");
    plan.uninstall_cleanup.push_back("Stop and remove NetSentinel11 service if installed.");
    plan.uninstall_cleanup.push_back("Remove app-owned firewall rules only; never remove user-created rules.");
    plan.uninstall_cleanup.push_back("Preserve user data by default and offer explicit data cleanup.");

    plan.upgrade_migration.push_back("Run storage schema migration before starting background monitoring.");
    plan.upgrade_migration.push_back("Preserve workspaces, inventory labels, saved filters, and report templates.");
    plan.upgrade_migration.push_back("Re-check optional dependencies after upgrade and show non-blocking remediation guidance.");
}

} // namespace

InstallerPackagingPlan generate_installer_packaging_plan(const InstallerPackagingConfig& config) {
    InstallerPackagingPlan plan{};
    plan.package_format = lower_copy(config.package_format.empty() ? std::string{"wix"} : config.package_format);
    plan.install_location = config.install_location;

    if (plan.package_format != "wix" && plan.package_format != "msix") {
        plan.success = false;
        plan.message = "Unsupported package format. Use wix or msix.";
        plan.warnings.push_back("Packaging plan was not generated because the format is unsupported.");
        return plan;
    }

    append_common_plan(plan, config);
    if (plan.package_format == "wix") {
        plan.packaging_steps.push_back("Generate WiX Product.wxs from packaging/windows/Product.wxs.in.");
        plan.packaging_steps.push_back("Run candle.exe and light.exe from WiX Toolset in Release packaging workflow.");
    } else {
        plan.packaging_steps.push_back("Generate MSIX manifest from packaging/windows/msix_manifest_template.xml.");
        plan.packaging_steps.push_back("Run MakeAppx and SignTool in Release packaging workflow.");
    }

    if (config.require_npcap) {
        plan.warnings.push_back("Npcap was marked required; installer must block capture features until the operator confirms dependency installation.");
    }
    if (config.request_firewall_permission) {
        plan.warnings.push_back("Firewall permission requested; installer must present a clear consent dialog and only create app-owned rules.");
    }
    if (!config.enable_auto_update) {
        plan.warnings.push_back("Auto-update is disabled by default for open-source builds; document manual update path.");
    }

    plan.success = true;
    plan.message = "Windows packaging plan generated without modifying the system.";
    return plan;
}

std::string installer_plan_markdown(const InstallerPackagingPlan& plan) {
    std::ostringstream out;
    out << "# NetSentinel11 Windows Packaging Plan\n\n";
    out << "- Format: " << plan.package_format << "\n";
    out << "- Install location: " << plan.install_location << "\n";
    out << "- Status: " << (plan.success ? "ready" : "blocked") << "\n";
    out << "- Message: " << plan.message << "\n\n";
    out << "## Packaging steps\n";
    for (const auto& item : plan.packaging_steps) {
        out << "- " << item << "\n";
    }
    out << "\n## Permission explanations\n";
    for (const auto& item : plan.permission_explanations) {
        out << "- " << item << "\n";
    }
    out << "\n## Optional dependency checks\n";
    for (const auto& item : plan.optional_dependency_checks) {
        out << "- " << item << "\n";
    }
    out << "\n## Uninstall cleanup\n";
    for (const auto& item : plan.uninstall_cleanup) {
        out << "- " << item << "\n";
    }
    out << "\n## Upgrade migration\n";
    for (const auto& item : plan.upgrade_migration) {
        out << "- " << item << "\n";
    }
    if (!plan.warnings.empty()) {
        out << "\n## Warnings\n";
        for (const auto& item : plan.warnings) {
            out << "- " << item << "\n";
        }
    }
    return out.str();
}

ReleaseCandidateReadiness generate_release_candidate_readiness(const ReleaseCandidateConfig& config) {
    ReleaseCandidateReadiness readiness{};
    readiness.success = true;
    readiness.version = config.version.empty() ? "0.1.0-rc" : config.version;
    readiness.onboarding_steps = {
        "Explain that scans must be run only on networks the user owns or is explicitly authorized to test.",
        "Explain that no exploit payloads, credential attacks, MITM, spoofing, deauth, stealth, or disruption features are included.",
        "Explain privacy defaults: local-first storage, report export warning, retention defaults, and redaction tools.",
        "Explain measurement limitations: bandwidth attribution may be estimated unless router/Npcap/SNMP sources are explicitly configured.",
        "Offer low-resource mode for older Windows 11 PCs and slow networks."
    };
    readiness.safe_defaults = {
        "Local REST API disabled by default and loopback-only when enabled.",
        "Service/tray optional and visible, with cleanup support.",
        "Npcap and router integrations optional and never installed silently.",
        "Blocking backends default to advisory/dry-run unless explicitly confirmed.",
        "Professional collaboration works through local files without cloud subscription."
    };
    readiness.installer_disclosures = {
        "Npcap packet capture is optional and must be disclosed before enabling capture-based bandwidth features.",
        "Router integrations are optional and must disclose that credentials stay local and are never brute-forced.",
        "Windows service/tray startup is optional and must be reversible from Settings and uninstall.",
        "Firewall rules, if ever requested, must be app-owned, local-only, and explained before consent."
    };
    readiness.checklist = {
        "Build Release CLI with MSVC/CMake.",
        "Run focused smoke tests and end-to-end simulation suite.",
        "Generate REAL_LAN_TEST_REPORT.md for authorized LAN validation.",
        "Generate GUI_MILESTONE_PLAN.md and verify native GUI once Qt6 is installed.",
        "Generate installer packaging plan.",
        "Generate privacy review report.",
        "Ship sample reports and deterministic simulation data.",
        "Review logs for secrets before publishing artifacts."
    };
    readiness.changelog = {
        "Added safe LAN discovery, service identification, reporting, and local inventory workflows.",
        "Added router, camera, lifecycle, CPE/CVE, recognition, importer, and privacy review workflows.",
        "Added bandwidth abstractions, dashboards, reports, and deterministic top-talker simulations.",
        "Added local REST hardening, optional agent protocol mock, service/tray hardening, and professional workspace bundles.",
        "Added accessibility/localization readiness, low-resource mode, and end-to-end simulation suite."
    };
    if (!config.qt_gui_available) {
        readiness.blockers.push_back("Native Qt6 GUI build/launch is not verified because Qt6 Widgets is not installed/configured.");
    }
    if (config.include_npcap_features) {
        readiness.warnings.push_back("Npcap features selected; installer must disclose optional driver dependency and provide graceful fallback.");
    }
    if (config.include_router_integrations) {
        readiness.warnings.push_back("Router integrations selected; installer/onboarding must disclose credential handling and local-only storage.");
    }
    if (!config.mock_mode) {
        readiness.warnings.push_back("Release candidate readiness generation should remain a dry-run planning step.");
    }
    if (!config.include_service) {
        readiness.warnings.push_back("Service component excluded; background monitoring will be limited to foreground/tray workflows.");
    }
    if (!config.include_tray) {
        readiness.warnings.push_back("Tray component excluded; visible background controls must be provided elsewhere.");
    }
    readiness.release_ready = readiness.blockers.empty();
    readiness.message = readiness.release_ready
        ? "Release candidate checklist generated and no readiness blockers are known."
        : "Release candidate checklist generated with explicit blockers.";
    return readiness;
}

std::string release_candidate_readiness_markdown(const ReleaseCandidateReadiness& readiness) {
    auto write_list = [](std::ostringstream& out, const std::vector<std::string>& values) {
        if (values.empty()) {
            out << "- None\n";
            return;
        }
        for (const auto& value : values) {
            out << "- " << value << "\n";
        }
    };

    std::ostringstream out;
    out << "# NetSentinel11 Release Candidate Readiness\n\n";
    out << "- Version: " << readiness.version << "\n";
    out << "- Generated: yes\n";
    out << "- Release ready: " << (readiness.release_ready ? "yes" : "no") << "\n";
    out << "- Message: " << readiness.message << "\n\n";
    out << "## First-run onboarding\n\n";
    write_list(out, readiness.onboarding_steps);
    out << "\n## Safe defaults\n\n";
    write_list(out, readiness.safe_defaults);
    out << "\n## Installer disclosures\n\n";
    write_list(out, readiness.installer_disclosures);
    out << "\n## Release checklist\n\n";
    write_list(out, readiness.checklist);
    out << "\n## Blockers\n\n";
    write_list(out, readiness.blockers);
    out << "\n## Warnings\n\n";
    write_list(out, readiness.warnings);
    return out.str();
}

std::string release_candidate_changelog_markdown(const ReleaseCandidateReadiness& readiness) {
    std::ostringstream out;
    out << "# Changelog\n\n";
    out << "## " << readiness.version << "\n\n";
    for (const auto& item : readiness.changelog) {
        out << "- " << item << "\n";
    }
    out << "\n## Known release-candidate limitations\n\n";
    if (readiness.blockers.empty() && readiness.warnings.empty()) {
        out << "- None known.\n";
    } else {
        for (const auto& blocker : readiness.blockers) {
            out << "- BLOCKER: " << blocker << "\n";
        }
        for (const auto& warning : readiness.warnings) {
            out << "- WARNING: " << warning << "\n";
        }
    }
    return out.str();
}

} // namespace netsentinel::installer
