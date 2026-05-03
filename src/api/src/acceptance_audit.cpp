#include "netsentinel/api/acceptance_audit.h"

#include <sstream>

namespace netsentinel::api {

namespace {

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        if (ch == '\\') {
            out += "\\\\";
        } else if (ch == '"') {
            out += "\\\"";
        } else if (ch == '\n') {
            out += "\\n";
        } else if (ch == '\r') {
            out += "\\r";
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::string json_string(const std::string& value) {
    return "\"" + json_escape(value) + "\"";
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

std::size_t count_status(const std::vector<AcceptanceFeatureStatus>& matrix, const std::string& status) {
    std::size_t count = 0;
    for (const auto& row : matrix) {
        if (row.status == status) {
            ++count;
        }
    }
    return count;
}

} // namespace

AcceptanceAuditResult run_final_acceptance_audit() {
    AcceptanceAuditResult result{};
    result.success = true;
    result.matrix = {
        {"Safety boundaries", "pass", "Authorized-LAN-only validation documented; no exploit/bruteforce/MITM/deauth/stealth behavior added.", ""},
        {"CLI build and launch", "pass", "netsentinel11 builds and launches in Debug with focused prompt tests.", ""},
        {"Authorized LAN discovery/service validation", "pass", "REAL_LAN_TEST_REPORT.md documents safe ARP/ICMP/TCP validation on 192.168.50.0/24.", "Must be rerun before public release on final build."},
        {"Device inventory and workspaces", "pass", "Local inventory/workspace flows, imports, professional bundles, and reports exist.", ""},
        {"Security/privacy checks", "pass", "Router/camera/lifecycle/CPE/CVE/recognition/privacy review workflows are metadata-only and tested.", "Catalog coverage needs expansion before strong vulnerability claims."},
        {"Bandwidth/top talkers", "partial", "Source abstractions, dashboards, rollups, reports, and simulations exist.", "Per-device accuracy depends on router counters, Npcap visibility, NetFlow/sFlow/IPFIX, or agents."},
        {"Safe blocking/limits", "partial", "Advisory/dry-run and safe backend abstractions exist.", "Real enforcement requires supported router/firewall backend and explicit confirmation."},
        {"Optional agent/collector", "partial", "Protocol/spec/mock collector exists with mutual-TLS metadata and signed-token requirements.", "No production TLS agent or installer exists yet."},
        {"Native Qt6 GUI", "fail", "GUI shell/model source exists and CLI previews work.", "Qt6 Widgets is not installed/configured, so native GUI build/launch is unverified."},
        {"Installer package", "partial", "Packaging/readiness plans and disclosures exist.", "No signed WiX/MSIX package was produced in this environment."},
        {"End-to-end simulation", "pass", "Deterministic mock suite covers discovery, monitoring, alerts, security, bandwidth, blocking, and reports.", ""},
        {"Privacy/data minimization", "pass", "Retention defaults, redaction, export acknowledgement, and report warnings exist.", "Full artifact-wide automated log audit remains future work."},
        {"Accessibility/localization/low-resource", "partial", "Checklist/model/language file/low-resource profile exist.", "Native Qt keyboard/screen-reader/high-DPI verification requires Qt6 GUI build."}
    };
    result.release_blockers = {
        "Install/configure Qt6 Widgets and verify native polished GUI build/launch.",
        "Run final GUI manual acceptance: dashboard, device cards, scan progress, device details, topology/list, warnings, timeline, bandwidth, reports, settings, dark/light mode.",
        "Build/sign/package a Windows installer and verify uninstall cleanup.",
        "Run final authorized LAN validation with the release build and update REAL_LAN_TEST_REPORT.md.",
        "Complete release artifact privacy/log audit."
    };
    result.impossible_without_router_support = {
        "Accurate per-device WAN bandwidth attribution from the internet gateway.",
        "Router-level blocking, bandwidth limiting, quota enforcement, and downtime schedules.",
        "WAN outage classification that requires gateway counters or router state.",
        "UPnP/NAT-PMP management against routers that do not expose safe read/write APIs."
    };
    result.impossible_without_agent = {
        "Reliable bandwidth/process attribution for devices whose traffic is not visible to the scanner host.",
        "Host-level CPU/memory/process telemetry from NAS, Raspberry Pi, or second Windows machines.",
        "Deep device-local health checks without credentials or installed local collector.",
        "Roaming/off-network presence telemetry."
    };
    result.topology_limitations = {
        "Switched Ethernet hides most peer-to-peer traffic from a normal endpoint without port mirroring, router counters, or capture position.",
        "Client isolation, guest Wi-Fi, VLANs, and firewall rules can hide devices from discovery.",
        "mDNS/SSDP/NetBIOS may be blocked by network policy or OS firewall.",
        "Some devices intentionally ignore ICMP or randomize MAC addresses."
    };
    result.roadmap_v1_0 = {
        "Install Qt6 Widgets and finish native GUI acceptance.",
        "Run final authorized LAN validation on release build.",
        "Ship signed installer or clearly marked portable build.",
        "Complete privacy/log audit and release notes.",
        "Keep advanced controls advisory/dry-run unless backend is explicitly configured."
    };
    result.roadmap_v1_1 = {
        "Improve GUI professional workspace and import/export UX.",
        "Expand lifecycle/CPE/CVE catalogs with verified public/licensed sources.",
        "Add signed professional bundle export and broader localization files.",
        "Add stronger router plugin examples for common open-source routers."
    };
    result.roadmap_v2_0 = {
        "Production mutual-TLS agent collector with explicit install/removal.",
        "Optional router integrations for high-quality bandwidth and control APIs.",
        "Advanced topology visualization from router/agent data.",
        "Release-grade CI with full artifact audit, installer test, and GUI automation."
    };
    result.release_ready = false;
    result.message = "Final audit generated. The roadmap is complete through Prompt 86, but public release remains blocked by native GUI and packaging verification.";
    return result;
}

std::string acceptance_audit_markdown(const AcceptanceAuditResult& result) {
    std::ostringstream out;
    out << "# Final Acceptance Audit And Future Backlog\n\n";
    out << "- Audit generated: " << (result.success ? "yes" : "no") << "\n";
    out << "- Release ready: " << (result.release_ready ? "yes" : "no") << "\n";
    out << "- Pass: " << count_status(result.matrix, "pass") << "\n";
    out << "- Partial: " << count_status(result.matrix, "partial") << "\n";
    out << "- Fail: " << count_status(result.matrix, "fail") << "\n";
    out << "- Message: " << result.message << "\n\n";
    out << "## Feature matrix\n\n";
    out << "| Feature | Status | Evidence | Limitation |\n";
    out << "| --- | --- | --- | --- |\n";
    for (const auto& row : result.matrix) {
        out << "| " << row.feature << " | " << row.status << " | " << row.evidence << " | " << (row.limitation.empty() ? "None" : row.limitation) << " |\n";
    }
    out << "\n## Release blockers\n\n";
    out << markdown_list(result.release_blockers) << "\n";
    out << "## Impossible or partial without router support\n\n";
    out << markdown_list(result.impossible_without_router_support) << "\n";
    out << "## Impossible or partial without an agent\n\n";
    out << markdown_list(result.impossible_without_agent) << "\n";
    out << "## Special topology limitations\n\n";
    out << markdown_list(result.topology_limitations) << "\n";
    out << "## v1.0 roadmap\n\n";
    out << markdown_list(result.roadmap_v1_0) << "\n";
    out << "## v1.1 roadmap\n\n";
    out << markdown_list(result.roadmap_v1_1) << "\n";
    out << "## v2.0 roadmap\n\n";
    out << markdown_list(result.roadmap_v2_0);
    return out.str();
}

std::string acceptance_audit_json(const AcceptanceAuditResult& result) {
    std::string out = "{";
    out += "\"success\":" + std::string(result.success ? "true" : "false") + ",";
    out += "\"release_ready\":" + std::string(result.release_ready ? "true" : "false") + ",";
    out += "\"pass\":" + std::to_string(count_status(result.matrix, "pass")) + ",";
    out += "\"partial\":" + std::to_string(count_status(result.matrix, "partial")) + ",";
    out += "\"fail\":" + std::to_string(count_status(result.matrix, "fail")) + ",";
    out += "\"message\":" + json_string(result.message) + ",";
    out += "\"matrix\":[";
    for (std::size_t i = 0; i < result.matrix.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        const auto& row = result.matrix[i];
        out += "{";
        out += "\"feature\":" + json_string(row.feature) + ",";
        out += "\"status\":" + json_string(row.status) + ",";
        out += "\"evidence\":" + json_string(row.evidence) + ",";
        out += "\"limitation\":" + json_string(row.limitation);
        out += "}";
    }
    out += "]}";
    return out;
}

} // namespace netsentinel::api
