#include <cstddef>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <thread>
#include <string>
#include <iostream>
#include <string_view>
#include <unordered_set>
#include <vector>
#include "netsentinel/engine/adapter_inventory.h"
#include "netsentinel/engine/arp_discovery.h"
#include "netsentinel/engine/icmp_discovery.h"
#include "netsentinel/engine/netbios_discovery.h"
#include "netsentinel/engine/mdns_discovery.h"
#include "netsentinel/engine/ssdp_discovery.h"
#include "netsentinel/engine/snmp_read_only_discovery.h"
#include "netsentinel/engine/tcp_discovery.h"
#include "netsentinel/engine/scan_scope.h"
#include "netsentinel/engine/scan_contract.h"
#include "netsentinel/storage/storage.h"
#include "netsentinel/service/tray_service.h"
#include "netsentinel/alerts/alert_router.h"
#include "netsentinel/speedtest/speed_test.h"
#include "netsentinel/outage/outage_detector.h"
#include "netsentinel/diagnostics/diagnostic_tools.h"
#include "netsentinel/api/acceptance_audit.h"
#include "netsentinel/api/agent_collector_protocol.h"
#include "netsentinel/api/local_rest_api.h"
#include "netsentinel/api/privacy_policy.h"
#include "netsentinel/api/professional_workspace.h"
#include "netsentinel/api/simulation_suite.h"
#include "netsentinel/reports/report_generator.h"
#include "netsentinel/ui/gui_shell.h"
#include "netsentinel/installer/installer_plan.h"
#include "netsentinel/bandwidth/bandwidth_source.h"
#include "netsentinel/hardening/hardening.h"
#include "safety_contract.h"
#include "netsentinel/netcore/version.h"

namespace {

std::string join_csv(const std::vector<std::string>& values) {
    if (values.empty()) {
        return "(none)";
    }
    std::ostringstream out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            out << ", ";
        }
        out << values[i];
    }
    return out.str();
}

void print_usage() {
    std::cout << "NetSentinel11 CLI\n";
    std::cout << "Usage:\n";
    std::cout << "  netsentinel11 [--safety] [--deps] [--smoke] [--help]\n";
    std::cout << "  netsentinel11 interfaces [--mock]\n";
    std::cout << "  netsentinel11 scope [--mock] [--custom <cidr>] [--confirm] [--allow-non-local]\n";
    std::cout << "  netsentinel11 scan arp [--scope <cidr>] [--mock]\n";
    std::cout << "  netsentinel11 scan icmp [--scope <cidr>] [--mock]\n";
    std::cout << "  netsentinel11 scan tcp [--scope <cidr>] [--mock]\n";
    std::cout << "  netsentinel11 scan netbios [--scope <cidr>] [--mock]\n";
    std::cout << "  netsentinel11 scan mdns [--mock]\n";
    std::cout << "  netsentinel11 scan ssdp [--mock]\n";
    std::cout << "  netsentinel11 scan snmp --target <ipv4> --community <string> [--version <v1|v2c>] [--mock]\n";
    std::cout << "  netsentinel11 scan session [--scope <cidr>] [--mock] [--profile <manual|quick|standard|deep-safe|monitor>] [--timeout <sec>] [--qps <n>] [--concurrency <n>] [--jitter-min <ms>] [--jitter-max <ms>] [--snmp-target <ipv4>] [--snmp-community <string>] [--snmp-version <v1|v2c>]\n";
    std::cout << "  netsentinel11 monitor [--scope <cidr>] [--mock] [--profile <manual|quick|standard|deep-safe|monitor>] [--interval <minutes>] [--max-runs <n>] [--continuous] [--allow-metered] [--timeout <sec>] [--qps <n>] [--concurrency <n>] [--jitter-min <ms>] [--jitter-max <ms>]\n";
    std::cout << "  netsentinel11 tray status [--mock]\n";
    std::cout << "  netsentinel11 tray start [--mock] [--profile <manual|quick|standard|deep-safe|monitor>] [--interval <minutes>] [--scope <cidr>] [--restart-limit <n>]\n";
    std::cout << "  netsentinel11 tray stop [--mock]\n";
    std::cout << "  netsentinel11 tray cleanup [--mock]\n";
    std::cout << "  netsentinel11 tray hardening [--mock] [--output <md-path>]\n";
    std::cout << "  netsentinel11 alerts test --kind <new-device|important-status-change|outage|security-finding|scan-failure> --message <text> [--target <id>] [--mock] [--toast|--no-toast] [--email-to <address>] [--email-from <address>] [--webhook-url <url>] [--max-rate <n>]\n";
    std::cout << "  netsentinel11 speed test [--endpoint <url>] [--samples <n>] [--timeout-ms <n>] [--retention <n>] [--mock]\n";
    std::cout << "  netsentinel11 outage check [--gateway <ip>] [--dns <host>] [--external <url>] [--host <ip>] [--timeout-ms <n>] [--mock]\n";
    std::cout << "  netsentinel11 ping [--target <ip-or-host>] [--count <n>] [--timeout-ms <n>] [--mock]\n";
    std::cout << "  netsentinel11 traceroute [--target <ip-or-host>] [--max-hops <n>] [--timeout-ms <n>] [--mock]\n";
    std::cout << "  netsentinel11 dns [--target <ip-or-host>] [--reverse] [--resolver <ip>] [--max-records <n>] [--mock]\n";
    std::cout << "  netsentinel11 dns-benchmark [--resolver <ip>] [--resolver <ip2>] [--query <domain>] [--query <domain2>] [--samples <n>] [--timeout-ms <n>] [--mock]\n";
    std::cout << "  netsentinel11 dhcp [--adapter <id-or-name>] [--allow-multiple-check] [--mock]\n";
    std::cout << "  netsentinel11 wifi [--include-hidden] [--mock]\n";
    std::cout << "  netsentinel11 wifi analyze [--include-hidden] [--mock]\n";
    std::cout << "  netsentinel11 wifi environment [--include-hidden] [--output <md-path>] [--mock]\n";
    std::cout << "  netsentinel11 wifi sweetspot --location <room> [--timestamp <utc>] [--output <csv-path>] [--include-hidden] [--mock]\n";
    std::cout << "  netsentinel11 security router [--gateway <ip>] [--mock]\n";
    std::cout << "  netsentinel11 security upnp [--gateway <ip>] [--port <n>] [--apply] [--confirm] [--dry-run] [--mock]\n";
    std::cout << "  netsentinel11 security camera [--db <path>] [--no-mdns] [--no-ssdp] [--no-port-hints] [--mock] [--privacy-mode] [--rental] [--no-unknown-iot] [--output <md-path>]\n";
    std::cout << "  netsentinel11 security lifecycle [--db <path>] [--catalog <path>] [--reference-date <YYYY-MM-DD>] [--output <md-path>] [--no-unknown] [--mock]\n";
    std::cout << "  netsentinel11 security cve [--db <path>] [--catalog <path>] [--output <md-path>] [--no-possible] [--mock]\n";
    std::cout << "  netsentinel11 security recognize [--db <path>] [--recognition-db <path>] [--learn-device-id <id>] [--learn-hostname <text>] [--learn-vendor <text>] [--learn-type <type>] [--learn-labels <a,b>] [--import <path>] [--export <path>] [--output <md-path>] [--mock]\n";
    std::cout << "  netsentinel11 security import-inventory --input <path> [--format <auto|csv|json>] [--output-db <path>] [--output <md-path>] [--apply]\n";
    std::cout << "  netsentinel11 security health [--db <path>] [--gateway <ip>] [--mock]\n";
    std::cout << "  netsentinel11 security control [--backend <advisory|windows-firewall-local|router-plugin>] [--action <block|unblock|limit>] [--target-ip <ip>] [--device-id <id>] [--download-kbps <n>] [--upload-kbps <n>] [--router-plugin <name>] [--router-user <name>] [--router-password <secret>] [--method <safe-control-api>] [--apply] [--confirm] [--dry-run] [--mock]\n";
    std::cout << "  netsentinel11 security downtime [--schedule <id>] [--window <HH:MM-HH:MM>] [--days <all|mon,tue,...>] [--now <HH:MM>] [--target-ip <ip>] [--device-id <id>] [--user <name>] [--group <name>] [--label <text>] [--backend <advisory|windows-firewall-local|router-plugin>] [--emergency-disable] [--apply] [--confirm] [--dry-run] [--mock]\n";
    std::cout << "  netsentinel11 security quota [--profile <family|guest|work>] [--device-id <id>] [--group <name>] [--target-ip <ip>] [--quota-mb <n>] [--warning-mb <n>] [--window <HH:MM-HH:MM>] [--days <all|mon,tue,...>] [--now <HH:MM>] [--mock]\n";
    std::cout << "  netsentinel11 security autoblock [--mock] [--alert-only|--enforce] [--backend <mock|openwrt|windows-firewall-local|router-plugin>] [--endpoint <url>] [--credential-ref <name>] [--rule-id <id>] [--apply] [--confirm] [--saved-rule]\n";
    std::cout << "  netsentinel11 ports [identify] [--target <ip> --target <ip2>] [--preset <top|router|camera>] [--ports <p1,p2,...>] [--concurrency <n>] [--banner] [--mock]\n";
    std::cout << "  netsentinel11 inventory list [--all]\n";
    std::cout << "  netsentinel11 inventory show <device-id>\n";
    std::cout << "  netsentinel11 inventory edit <device-id> [--type <text>] [--labels <comma-separated>] [--importance <n>] [--hide <true|false>] [--stale <true|false>]\n";
    std::cout << "  netsentinel11 inventory hide <device-id> [--off]\n";
    std::cout << "  netsentinel11 inventory mark-stale <device-id> [--off]\n";
    std::cout << "  netsentinel11 inventory hide-stale\n";
    std::cout << "  netsentinel11 inventory export\n";
    std::cout << "  netsentinel11 workspace list [--db <path>]\n";
    std::cout << "  netsentinel11 workspace upsert [--db <path>] [--id <id>] [--gateway-mac <mac>] [--subnet <cidr>] [--ssid <name>] [--label <text>] [--monitoring <true|false>] [--limit <n>] [--profile <name>] [--notes <text>]\n";
    std::cout << "  netsentinel11 workspace switch --id <id> [--db <path>]\n";
    std::cout << "  netsentinel11 workspace active [--db <path>]\n";
    std::cout << "  netsentinel11 workspace record-scan --id <id> [--scan-id <n>] [--status <text>] [--summary <text>] [--db <path>]\n";
    std::cout << "  netsentinel11 workspace history [--id <id>] [--db <path>]\n";
    std::cout << "  netsentinel11 workspace pro-export [--mock] [--output <bundle-path>] [--consultant <name>] [--site <id>] [--site-name <name>] [--cidr <cidr>] [--owner <name>] [--tags <a,b>] [--issue-state <open|monitoring|resolved>] [--template <technical|executive>] [--notes <text>]\n";
    std::cout << "  netsentinel11 workspace pro-import --input <bundle-path>\n";
    std::cout << "  netsentinel11 workspace pro-report --input <bundle-path> [--output <md-path>]\n";
    std::cout << "  netsentinel11 search devices [--db <path>] [--preset <all|unknown|new-24h|cameras|routers|iot|risky-ports|offline-important|security-findings>] [--vendor <text>] [--os <text>] [--text <text>] [--network <id>] [--all]\n";
    std::cout << "  netsentinel11 search filters list [--db <path>]\n";
    std::cout << "  netsentinel11 search filters save --id <id> [--name <text>] [--preset <name>] [--vendor <text>] [--os <text>] [--text <text>] [--network <id>] [--db <path>]\n";
    std::cout << "  netsentinel11 search filters run --id <id> [--db <path>]\n";
    std::cout << "  netsentinel11 agent protocol [--mock|--real] [--collector-id <id>] [--agent-id <id>] [--agent-kind <kind>] [--server-cert <sha256:...>] [--client-cert <sha256:...>] [--token <token>] [--signature <sig>] [--permission <scope>] [--output <md-path>]\n";
    std::cout << "  netsentinel11 api status [--enabled] [--bind <127.0.0.1>] [--token <token>] [--csrf <token>] [--permission <scope>] [--rate-limit <n>] [--db <path>]\n";
    std::cout << "  netsentinel11 api request --path <endpoint> [--method <GET|POST>] [--enabled] [--bind <127.0.0.1>] [--token <token>] [--request-token <token>] [--csrf <token>] [--request-csrf <token>] [--permission <scope>] [--rate-limit <n>] [--requests-in-window <n>] [--db <path>] [--apply]\n";
    std::cout << "  netsentinel11 report generate [--type <inventory|security|outage|speed|wi-fi|bandwidth|executive>] [--format <csv|json|html>] [--db <path>] [--output <path>] [--gateway <ip>] [--mock]\n";
    std::cout << "  netsentinel11 gui shell [--db <path>] [--gateway <ip>] [--demo]\n";
    std::cout << "  netsentinel11 gui bandwidth [--db <path>] [--demo] [--mock]\n";
    std::cout << "  netsentinel11 gui devices [--db <path>] [--filter <preset>] [--search <text>] [--vendor <text>] [--network <id>] [--sort <relevance|hostname|vendor|importance|status>] [--all]\n";
    std::cout << "  netsentinel11 gui device --id <device-id> [--db <path>]\n";
    std::cout << "  netsentinel11 gui action --id <action-id> [--target <value>] [--db <path>] [--token <token>] [--report-type <type>] [--report-format <format>] [--apply] [--confirm] [--mock]\n";
    std::cout << "  netsentinel11 gui accessibility [--language <tag>] [--low-resource] [--high-contrast] [--dpi-scale <n>] [--output <md-path>]\n";
    std::cout << "  netsentinel11 privacy review [--mock] [--export] [--ack-export] [--report-type <type>] [--log-line <text>] [--output <md-path>]\n";
    std::cout << "  netsentinel11 simulation run --mock [--output <md-path>] [--max-runtime-ms <n>]\n";
    std::cout << "  netsentinel11 release candidate [--mock] [--qt-gui] [--npcap] [--router-integrations] [--output <md-path>] [--changelog <md-path>]\n";
    std::cout << "  netsentinel11 audit final [--output <md-path>]\n";
    std::cout << "  netsentinel11 installer plan [--format <wix|msix>] [--scope <per-user|per-machine>] [--install-location <path>] [--no-service] [--no-tray] [--require-npcap] [--firewall] [--auto-update]\n";
    std::cout << "  netsentinel11 hardening report [--subnet <cidr>] [--devices <n>] [--seed <n>]\n";
    std::cout << "  netsentinel11 hardening simulate [--subnet <cidr>] [--devices <n>] [--seed <n>]\n";
    std::cout << "  netsentinel11 hardening fuzz\n";
    std::cout << "  netsentinel11 bandwidth sources\n";
    std::cout << "  netsentinel11 bandwidth sample --mock [--timestamp <utc>]\n";
    std::cout << "  netsentinel11 bandwidth npcap [--mock-installed|--mock-missing] [--mock-admin|--mock-user]\n";
    std::cout << "  netsentinel11 bandwidth local [--mock] [--persist] [--db <path>] [--timestamp <utc>] [--previous-rx <bytes>] [--previous-tx <bytes>] [--elapsed-sec <n>]\n";
    std::cout << "  netsentinel11 bandwidth capture [--mock] [--dry-run] [--confirm] [--adapter <id>] [--assume-mirrored] [--timestamp <utc>]\n";
    std::cout << "  netsentinel11 bandwidth snmp [--mock] [--dry-run] [--router <ip>] [--credential-ref <name>] [--elapsed-sec <n>] [--timestamp <utc>]\n";
    std::cout << "  netsentinel11 bandwidth upnp [--mock] [--dry-run] [--gateway <ip-or-url>] [--no-counters] [--elapsed-sec <n>] [--timestamp <utc>]\n";
    std::cout << "  netsentinel11 bandwidth flows [--mock] [--enable] [--dry-run] [--bind <ip>] [--port <n>]\n";
    std::cout << "  netsentinel11 bandwidth plugin [--mock] [--operation <list|telemetry|block|unblock|limit>] [--plugin <id>] [--target <device-id>] [--apply] [--confirm]\n";
    std::cout << "  netsentinel11 bandwidth limit [--mock] [--backend <mock|openwrt|windows-firewall-local|pihole|adguard|router-plugin>] [--action <limit|pause|resume>] [--target <device-id>] [--target-ip <ip>] [--download-kbps <n>] [--upload-kbps <n>] [--endpoint <url>] [--credential-ref <name>] [--rule-id <id>] [--saved-rule] [--apply] [--confirm]\n";
    std::cout << "  netsentinel11 bandwidth openwrt [--mock] [--dry-run] [--endpoint <url>] [--credential-ref <name>] [--transport <rpc|ssh>] [--unsupported-firmware]\n";
    std::cout << "  netsentinel11 bandwidth attribute --mock [--elapsed-sec <n>]\n";
    std::cout << "  netsentinel11 bandwidth rollups --mock [--db <path>] [--privacy-redact] [--retention-cutoff <utc>]\n";
    std::cout << "  netsentinel11 bandwidth anomalies --mock [--top <n>] [--spike-rx <bytes>] [--upload <bytes>] [--quiet-baseline <bytes>] [--quiet-active <bytes>]\n";
    std::cout << "  netsentinel11 timeline [--network <network-id>] [--device <device-id>] [--type <event-type>] [--from <utc>] [--to <utc>]\n";
    std::cout << "  netsentinel11 presence history [--db <path>] [--network <network-id>] [--include-unlabeled] [--now <utc>] [--retention-days <n>] [--apply-retention] [--mock]\n";
    std::cout << "  netsentinel11 presence notify [--mock] [--opt-in] [--profile <family|guest|work|unknown>] [--event <online|offline>] [--label <text>] [--device-id <id>] [--now <HH:MM>] [--quiet-hours <HH:MM-HH:MM>]\n";
    std::cout << "  --safety   Print the explicit authorized-use safety contract.\n";
    std::cout << "  --deps     Print dependency availability and fallback behavior.\n";
    std::cout << "  --smoke    Run non-network smoke check.\n";
    std::cout << "  interfaces List local network adapters and addresses.\n";
    std::cout << "  scope      Propose local scan scope from adapter or custom CIDR.\n";
    std::cout << "  scan       Run discovery workflows (arp, icmp, tcp, netbios, session).\n";
    std::cout << "  --mock    Mock local data for deterministic tests.\n";
    std::cout << "  --help     Show this help text.\n";
}

void print_dependency_status() {
    std::cout << "Dependency matrix:\n";
    std::cout << "  sqlite: " << (NETSENTINEL_HAVE_SQLITE ? "available" : "missing") << "\n";
    std::cout << "  spdlog: " << (NETSENTINEL_HAVE_SPDLOG ? "available" : "fallback-logging") << "\n";
    std::cout << "  json: " << (NETSENTINEL_HAVE_NLOHMANN_JSON ? "available" : "fallback-json-stubs") << "\n";
    std::cout << "Safety behavior: missing optional dependencies do not block startup.\n";
    std::cout << "Network probes: local scope-only by default, mock mode available.\n";
}

void print_smoke_check() {
    std::cout << "SMOKE_OK\n";
    std::cout << "Mode: local-only\n";
    std::cout << "Network calls: none\n";
    std::cout << "Result: ready for next stage.\n";
}

struct ScanSessionProfilePreset {
    int timeout_seconds = 10;
    std::size_t max_concurrency = 4;
    std::size_t max_qps = 16;
    long long jitter_ms_min = 0;
    long long jitter_ms_max = 0;
    std::size_t schedule_interval_minutes = 0;
    std::vector<std::string> enabled_probes;
    std::vector<int> tcp_port_hints;
};

bool resolve_scan_profile(const std::string& profile_name, ScanSessionProfilePreset& preset) {
    if (profile_name == "manual" || profile_name.empty()) {
        preset = ScanSessionProfilePreset{
            .timeout_seconds = 10,
            .max_concurrency = 4,
            .max_qps = 16,
            .jitter_ms_min = 0,
            .jitter_ms_max = 0,
            .schedule_interval_minutes = 0,
            .enabled_probes = {},
            .tcp_port_hints = {}
        };
        return true;
    }
    if (profile_name == "quick") {
        preset = ScanSessionProfilePreset{
            .timeout_seconds = 4,
            .max_concurrency = 6,
            .max_qps = 24,
            .jitter_ms_min = 0,
            .jitter_ms_max = 20,
            .schedule_interval_minutes = 5,
            .enabled_probes = {"arp", "icmp", "tcp"},
            .tcp_port_hints = {22, 80, 443}
        };
        return true;
    }
    if (profile_name == "standard") {
        preset = ScanSessionProfilePreset{
            .timeout_seconds = 8,
            .max_concurrency = 8,
            .max_qps = 16,
            .jitter_ms_min = 0,
            .jitter_ms_max = 8,
            .schedule_interval_minutes = 15,
            .enabled_probes = {"arp", "icmp", "tcp", "netbios", "mdns", "ssdp"},
            .tcp_port_hints = {22, 80, 443, 445}
        };
        return true;
    }
    if (profile_name == "deep-safe") {
        preset = ScanSessionProfilePreset{
            .timeout_seconds = 12,
            .max_concurrency = 4,
            .max_qps = 12,
            .jitter_ms_min = 5,
            .jitter_ms_max = 25,
            .schedule_interval_minutes = 30,
            .enabled_probes = {"arp", "icmp", "tcp", "netbios", "mdns", "ssdp"},
            .tcp_port_hints = {22, 80, 443, 445, 8080, 8443, 3389}
        };
        return true;
    }
    if (profile_name == "monitor") {
        preset = ScanSessionProfilePreset{
            .timeout_seconds = 3,
            .max_concurrency = 2,
            .max_qps = 10,
            .jitter_ms_min = 25,
            .jitter_ms_max = 80,
            .schedule_interval_minutes = 2,
            .enabled_probes = {"arp", "icmp"},
            .tcp_port_hints = {}
        };
        return true;
    }
    return false;
}

bool parse_positive_u64(std::string_view text, std::size_t& out) {
    try {
        const auto parsed = std::stoull(std::string(text));
        if (parsed == 0) {
            return false;
        }
        out = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_non_negative_u64(std::string_view text, std::size_t& out) {
    try {
        const auto parsed = std::stoull(std::string(text));
        out = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_non_negative_i64(std::string_view text, long long& out) {
    try {
        const auto parsed = std::stoll(std::string(text));
        if (parsed < 0) {
            return false;
        }
        out = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<std::string> split_csv_tokens(std::string_view text) {
    std::vector<std::string> out;
    std::string token;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char ch = text[i];
        if (ch == ',') {
            if (!token.empty()) {
                out.push_back(token);
            }
            token.clear();
            continue;
        }
        token.push_back(ch);
    }
    if (!token.empty()) {
        out.push_back(token);
    }
    return out;
}

bool parse_downtime_window_arg(
    std::string_view text,
    const std::string& days,
    netsentinel::diagnostics::ParentalDowntimeWindow& out
) {
    const auto dash = text.find('-');
    if (dash == std::string_view::npos || dash == 0 || dash + 1 >= text.size()) {
        return false;
    }
    out.days = days.empty() ? std::string{"all"} : days;
    out.start_local = std::string{text.substr(0, dash)};
    out.end_local = std::string{text.substr(dash + 1)};
    out.enabled = true;
    return !out.start_local.empty() && !out.end_local.empty();
}

bool parse_bool_flag(std::string_view text, bool& value) {
    if (text == "1" || text == "true" || text == "on" || text == "yes") {
        value = true;
        return true;
    }
    if (text == "0" || text == "false" || text == "off" || text == "no") {
        value = false;
        return true;
    }
    return false;
}

int print_inventory_list_command(bool include_hidden) {
    const auto records = netsentinel::storage::list_inventory_records(netsentinel::storage::StorageConfig{}, include_hidden);
    if (!records) {
        std::cerr << "Inventory list failed: " << netsentinel::engine::to_string(records.error().code) << "\n";
        std::cerr << records.error().user_message << "\n";
        return 3;
    }
    const auto& devices = records.value();
    std::cout << "Device inventory: " << devices.size() << " record(s)\n\n";
    for (std::size_t i = 0; i < devices.size(); ++i) {
        const auto& device = devices[i];
        std::cout << (i + 1) << ". " << device.device_id << "\n";
        std::cout << "  Hostname: " << (device.hostname.empty() ? "(none)" : device.hostname) << "\n";
        std::cout << "  IPs: " << (device.ip_addresses.empty() ? "(none)" : join_csv(device.ip_addresses)) << "\n";
        std::cout << "  MAC: " << (device.mac_address.empty() ? "(none)" : device.mac_address) << "\n";
        std::cout << "  Type: " << (device.device_type.empty() ? "(none)" : device.device_type) << "\n";
        std::cout << "  Importance: " << device.importance << "\n";
        std::cout << "  Labels: " << (device.user_labels.empty() ? "(none)" : join_csv(device.user_labels)) << "\n";
        std::cout << "  Hidden: " << (device.hidden ? "yes" : "no") << "\n";
        std::cout << "  Stale: " << (device.stale ? "yes" : "no") << "\n";
        std::cout << "  Last seen: " << (device.last_seen_utc.empty() ? "(none)" : device.last_seen_utc) << "\n";
    }
    return 0;
}

int print_inventory_show_command(const std::string& device_id) {
    const auto record = netsentinel::storage::get_inventory_record(device_id);
    if (!record) {
        std::cerr << "Inventory device not found: " << netsentinel::engine::to_string(record.error().code) << "\n";
        std::cerr << record.error().user_message << "\n";
        return 3;
    }
    const auto& device = record.value();
    std::cout << "Device: " << device.device_id << "\n";
    std::cout << "  Hostname: " << (device.hostname.empty() ? "(none)" : device.hostname) << "\n";
    std::cout << "  IPs: " << (device.ip_addresses.empty() ? "(none)" : join_csv(device.ip_addresses)) << "\n";
    std::cout << "  MAC: " << (device.mac_address.empty() ? "(none)" : device.mac_address) << "\n";
    std::cout << "  Vendor hint: " << (device.vendor_hint.empty() ? "(none)" : device.vendor_hint) << "\n";
    std::cout << "  Type: " << (device.device_type.empty() ? "(none)" : device.device_type) << "\n";
    std::cout << "  Importance: " << device.importance << "\n";
    std::cout << "  Labels: " << (device.user_labels.empty() ? "(none)" : join_csv(device.user_labels)) << "\n";
    std::cout << "  Hidden: " << (device.hidden ? "yes" : "no") << "\n";
    std::cout << "  Stale: " << (device.stale ? "yes" : "no") << "\n";
    std::cout << "  Details: " << (device.details.empty() ? "(none)" : device.details) << "\n";
    std::cout << "  Last seen: " << (device.last_seen_utc.empty() ? "(none)" : device.last_seen_utc) << "\n";
    return 0;
}

int print_inventory_edit_command(
    const std::string& device_id,
    const std::string& device_type,
    const std::string& labels_csv,
    int importance,
    bool set_importance,
    bool hide_value_set,
    bool hide_value,
    bool stale_value_set,
    bool stale_value
) {
    netsentinel::storage::DeviceInventoryPatch patch{};
    if (!device_type.empty()) {
        patch.device_type = device_type;
    }
    if (!labels_csv.empty()) {
        patch.user_labels = split_csv_tokens(labels_csv);
    }
    if (set_importance) {
        patch.importance = importance;
    }
    if (hide_value_set) {
        patch.hidden = hide_value;
    }
    if (stale_value_set) {
        patch.stale = stale_value;
    }
    if (!patch.device_type && !patch.user_labels && !patch.importance && !patch.hidden && !patch.stale) {
        std::cerr << "No edit fields provided.\n";
        return 2;
    }
    const auto updated = netsentinel::storage::patch_inventory_record(device_id, patch);
    if (!updated) {
        std::cerr << "Inventory edit failed: " << netsentinel::engine::to_string(updated.error().code) << "\n";
        std::cerr << updated.error().user_message << "\n";
        return 3;
    }
    std::cout << "Inventory record updated: " << device_id << "\n";
    return 0;
}

int print_inventory_hide_command(const std::string& device_id, bool hide_value) {
    netsentinel::storage::DeviceInventoryPatch patch{};
    patch.hidden = hide_value;
    const auto updated = netsentinel::storage::patch_inventory_record(device_id, patch);
    if (!updated) {
        std::cerr << "Inventory hide failed: " << netsentinel::engine::to_string(updated.error().code) << "\n";
        std::cerr << updated.error().user_message << "\n";
        return 3;
    }
    std::cout << "Inventory device " << device_id << " hide=" << (hide_value ? "on" : "off") << "\n";
    return 0;
}

int print_inventory_mark_stale_command(const std::string& device_id, bool stale_value) {
    netsentinel::storage::DeviceInventoryPatch patch{};
    patch.stale = stale_value;
    const auto updated = netsentinel::storage::patch_inventory_record(device_id, patch);
    if (!updated) {
        std::cerr << "Inventory stale edit failed: " << netsentinel::engine::to_string(updated.error().code) << "\n";
        std::cerr << updated.error().user_message << "\n";
        return 3;
    }
    std::cout << "Inventory device " << device_id << " stale=" << (stale_value ? "on" : "off") << "\n";
    return 0;
}

int print_inventory_hide_stale_command() {
    const auto updated = netsentinel::storage::hide_stale_inventory_records();
    if (!updated) {
        std::cerr << "Inventory hide-stale failed: " << netsentinel::engine::to_string(updated.error().code) << "\n";
        std::cerr << updated.error().user_message << "\n";
        return 3;
    }
    std::cout << "Inventory stale records hidden: " << updated.value() << "\n";
    return 0;
}

int print_inventory_export_command() {
    const auto json = netsentinel::storage::export_inventory_records_json();
    if (!json) {
        std::cerr << "Inventory export failed: " << netsentinel::engine::to_string(json.error().code) << "\n";
        std::cerr << json.error().user_message << "\n";
        return 3;
    }
    std::cout << json.value() << "\n";
    return 0;
}

std::string workspace_display_name(const netsentinel::storage::NetworkWorkspaceRecord& workspace) {
    if (!workspace.key.user_label.empty()) {
        return workspace.key.user_label;
    }
    if (!workspace.key.ssid.empty()) {
        return workspace.key.ssid;
    }
    return workspace.workspace_id;
}

int print_workspace_list_command(const netsentinel::storage::StorageConfig& config) {
    const auto workspaces = netsentinel::storage::list_network_workspaces(config);
    if (!workspaces) {
        std::cerr << "Workspace list failed: " << netsentinel::engine::to_string(workspaces.error().code) << "\n";
        std::cerr << workspaces.error().user_message << "\n";
        return 3;
    }
    std::cout << "WORKSPACE_LIST_OK\n";
    std::cout << "count=" << workspaces.value().size() << "\n";
    for (const auto& workspace : workspaces.value()) {
        std::cout << "workspace=" << workspace.workspace_id
                  << ",label=" << workspace_display_name(workspace)
                  << ",subnet=" << (workspace.key.subnet.empty() ? "(none)" : workspace.key.subnet)
                  << ",ssid=" << (workspace.key.ssid.empty() ? "(none)" : workspace.key.ssid)
                  << ",gateway_mac=" << (workspace.key.gateway_mac.empty() ? "(none)" : workspace.key.gateway_mac)
                  << ",active=" << (workspace.active ? "true" : "false")
                  << ",monitoring=" << (workspace.settings.monitoring_enabled ? "true" : "false")
                  << ",limit=" << workspace.settings.monitored_network_limit
                  << ",profile=" << workspace.settings.scan_profile << "\n";
    }
    return 0;
}

int print_workspace_upsert_command(
    const netsentinel::storage::StorageConfig& config,
    const netsentinel::storage::NetworkWorkspaceRecord& workspace
) {
    const auto saved = netsentinel::storage::upsert_network_workspace(workspace, config);
    if (!saved) {
        std::cerr << "Workspace save failed: " << netsentinel::engine::to_string(saved.error().code) << "\n";
        std::cerr << saved.error().user_message << "\n";
        return 3;
    }
    const auto& out = saved.value();
    std::cout << "WORKSPACE_UPSERT_OK\n";
    std::cout << "id=" << out.workspace_id << "\n";
    std::cout << "label=" << workspace_display_name(out) << "\n";
    std::cout << "subnet=" << out.key.subnet << "\n";
    std::cout << "ssid=" << out.key.ssid << "\n";
    std::cout << "gateway_mac=" << out.key.gateway_mac << "\n";
    std::cout << "monitoring=" << (out.settings.monitoring_enabled ? "true" : "false") << "\n";
    std::cout << "limit=" << out.settings.monitored_network_limit << "\n";
    std::cout << "profile=" << out.settings.scan_profile << "\n";
    return 0;
}

int print_workspace_switch_command(const netsentinel::storage::StorageConfig& config, const std::string& workspace_id) {
    const auto active = netsentinel::storage::switch_active_network_workspace(workspace_id, config);
    if (!active) {
        std::cerr << "Workspace switch failed: " << netsentinel::engine::to_string(active.error().code) << "\n";
        std::cerr << active.error().user_message << "\n";
        return 3;
    }
    std::cout << "WORKSPACE_SWITCH_OK\n";
    std::cout << "active=" << active.value().workspace_id << "\n";
    std::cout << "label=" << workspace_display_name(active.value()) << "\n";
    return 0;
}

int print_workspace_active_command(const netsentinel::storage::StorageConfig& config) {
    const auto active = netsentinel::storage::get_active_network_workspace(config);
    if (!active) {
        std::cerr << "Active workspace failed: " << netsentinel::engine::to_string(active.error().code) << "\n";
        std::cerr << active.error().user_message << "\n";
        return 3;
    }
    std::cout << "WORKSPACE_ACTIVE_OK\n";
    std::cout << "id=" << active.value().workspace_id << "\n";
    std::cout << "label=" << workspace_display_name(active.value()) << "\n";
    std::cout << "subnet=" << active.value().key.subnet << "\n";
    return 0;
}

int print_workspace_record_scan_command(
    const netsentinel::storage::StorageConfig& config,
    const netsentinel::storage::WorkspaceScanHistoryRecord& record
) {
    const auto appended = netsentinel::storage::append_workspace_scan_history(record, config);
    if (!appended) {
        std::cerr << "Workspace scan history failed: " << netsentinel::engine::to_string(appended.error().code) << "\n";
        std::cerr << appended.error().user_message << "\n";
        return 3;
    }
    std::cout << "WORKSPACE_SCAN_HISTORY_OK\n";
    std::cout << "workspace=" << record.workspace_id << "\n";
    std::cout << "scan_id=" << record.scan_id << "\n";
    std::cout << "status=" << (record.status.empty() ? "unknown" : record.status) << "\n";
    return 0;
}

int print_workspace_history_command(const netsentinel::storage::StorageConfig& config, const std::string& workspace_id) {
    const auto history = netsentinel::storage::list_workspace_scan_history(workspace_id, config);
    if (!history) {
        std::cerr << "Workspace history failed: " << netsentinel::engine::to_string(history.error().code) << "\n";
        std::cerr << history.error().user_message << "\n";
        return 3;
    }
    std::cout << "WORKSPACE_HISTORY_OK\n";
    std::cout << "count=" << history.value().size() << "\n";
    for (const auto& entry : history.value()) {
        std::cout << "scan=" << entry.scan_id
                  << ",workspace=" << entry.workspace_id
                  << ",status=" << entry.status
                  << ",summary=" << entry.summary
                  << ",at=" << entry.at_utc << "\n";
    }
    return 0;
}

int print_professional_workspace_export_command(
    const netsentinel::api::ProfessionalWorkspacePack& pack,
    const std::string& output_path
) {
    if (!output_path.empty()) {
        std::string error;
        if (!netsentinel::api::write_professional_workspace_pack(pack, output_path, error)) {
            std::cerr << "Professional workspace export failed: " << error << "\n";
            return 3;
        }
    }
    std::cout << "PRO_WORKSPACE_EXPORT_OK\n";
    std::cout << "consultant=" << pack.consultant_name << "\n";
    std::cout << "sites=" << pack.sites.size() << "\n";
    std::cout << "controls=" << join_csv(pack.collaboration_controls) << "\n";
    if (!output_path.empty()) {
        std::cout << "output=" << output_path << "\n";
    } else {
        std::cout << netsentinel::api::export_professional_workspace_pack(pack);
    }
    return 0;
}

int print_professional_workspace_import_command(const std::string& input_path) {
    const auto imported = netsentinel::api::read_professional_workspace_pack(input_path);
    if (!imported.success) {
        std::cerr << "Professional workspace import failed: " << imported.message << "\n";
        return 3;
    }
    std::cout << "PRO_WORKSPACE_IMPORT_OK\n";
    std::cout << "consultant=" << imported.pack.consultant_name << "\n";
    std::cout << "sites=" << imported.pack.sites.size() << "\n";
    for (const auto& site : imported.pack.sites) {
        std::cout << "site=" << site.site_id
                  << ",name=" << site.site_name
                  << ",cidr=" << site.network_cidr
                  << ",owner=" << site.owner
                  << ",state=" << site.issue_state
                  << ",template=" << site.report_template
                  << ",tags=" << join_csv(site.tags) << "\n";
    }
    return 0;
}

int print_professional_workspace_report_command(
    const std::string& input_path,
    const std::string& output_path
) {
    const auto imported = netsentinel::api::read_professional_workspace_pack(input_path);
    if (!imported.success) {
        std::cerr << "Professional workspace report failed: " << imported.message << "\n";
        return 3;
    }
    const auto markdown = netsentinel::api::professional_workspace_pack_markdown(imported.pack);
    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Professional workspace report write failed: " << output_path << "\n";
            return 3;
        }
        out << markdown;
    }
    std::cout << "PRO_WORKSPACE_REPORT_OK\n";
    std::cout << "sites=" << imported.pack.sites.size() << "\n";
    if (!output_path.empty()) {
        std::cout << "output=" << output_path << "\n";
    } else {
        std::cout << markdown;
    }
    return 0;
}

int print_search_results(
    const std::string& ok_marker,
    const netsentinel::storage::Result<std::vector<netsentinel::storage::DeviceSearchResult>>& results
) {
    if (!results) {
        std::cerr << "Search failed: " << netsentinel::engine::to_string(results.error().code) << "\n";
        std::cerr << results.error().user_message << "\n";
        return 3;
    }
    std::cout << ok_marker << "\n";
    std::cout << "count=" << results.value().size() << "\n";
    for (const auto& result : results.value()) {
        std::cout << "device=" << result.device.device_id
                  << ",hostname=" << (result.device.hostname.empty() ? "(none)" : result.device.hostname)
                  << ",network=" << (result.network_id.empty() ? "(unknown)" : result.network_id)
                  << ",vendor=" << (result.device.vendor_hint.empty() ? "(none)" : result.device.vendor_hint)
                  << ",type=" << (result.device.device_type.empty() ? "(none)" : result.device.device_type)
                  << ",relevance=" << result.relevance
                  << ",reasons=" << join_csv(result.matched_reasons) << "\n";
    }
    return 0;
}

int print_search_devices_command(
    const netsentinel::storage::StorageConfig& config,
    const netsentinel::storage::DeviceSearchQuery& query
) {
    return print_search_results("SEARCH_DEVICES_OK", netsentinel::storage::search_inventory_devices(query, config));
}

int print_filter_list_command(const netsentinel::storage::StorageConfig& config) {
    const auto filters = netsentinel::storage::list_filter_templates(config);
    if (!filters) {
        std::cerr << "Filter list failed: " << netsentinel::engine::to_string(filters.error().code) << "\n";
        std::cerr << filters.error().user_message << "\n";
        return 3;
    }
    std::cout << "SEARCH_FILTER_LIST_OK\n";
    std::cout << "count=" << filters.value().size() << "\n";
    for (const auto& filter : filters.value()) {
        std::cout << "filter=" << filter.filter_id
                  << ",name=" << filter.name
                  << ",preset=" << filter.query.preset
                  << ",vendor=" << (filter.query.vendor.empty() ? "(none)" : filter.query.vendor)
                  << ",network=" << (filter.query.network_id.empty() ? "(any)" : filter.query.network_id) << "\n";
    }
    return 0;
}

int print_filter_save_command(
    const netsentinel::storage::StorageConfig& config,
    const netsentinel::storage::SavedFilterTemplate& filter
) {
    const auto saved = netsentinel::storage::save_filter_template(filter, config);
    if (!saved) {
        std::cerr << "Filter save failed: " << netsentinel::engine::to_string(saved.error().code) << "\n";
        std::cerr << saved.error().user_message << "\n";
        return 3;
    }
    std::cout << "SEARCH_FILTER_SAVE_OK\n";
    std::cout << "id=" << saved.value().filter_id << "\n";
    std::cout << "name=" << saved.value().name << "\n";
    std::cout << "preset=" << saved.value().query.preset << "\n";
    return 0;
}

int print_filter_run_command(const netsentinel::storage::StorageConfig& config, const std::string& filter_id) {
    return print_search_results("SEARCH_FILTER_RUN_OK", netsentinel::storage::run_saved_filter_template(filter_id, config));
}

int print_api_status_command(const netsentinel::api::LocalRestApiConfig& config) {
    const auto status = netsentinel::api::validate_local_rest_api_config(config);
    std::cout << "LOCAL_API_STATUS_OK\n";
    std::cout << "enabled=" << (status.enabled ? "true" : "false") << "\n";
    std::cout << "valid=" << (status.valid ? "true" : "false") << "\n";
    std::cout << "localhost_only=" << (status.localhost_only ? "true" : "false") << "\n";
    std::cout << "token_required=" << (status.token_required ? "true" : "false") << "\n";
    std::cout << "csrf_required=" << (status.csrf_required ? "true" : "false") << "\n";
    std::cout << "rate_limit_enabled=" << (status.rate_limit_enabled ? "true" : "false") << "\n";
    std::cout << "rate_limit_per_minute=" << status.rate_limit_per_minute << "\n";
    std::cout << "permission_model_enabled=" << (status.permission_model_enabled ? "true" : "false") << "\n";
    std::cout << "permissions=" << join_csv(status.permissions) << "\n";
    std::cout << "message=" << status.message << "\n";
    std::cout << "security_controls=" << join_csv(status.security_controls) << "\n";
    return status.valid ? 0 : 3;
}

int print_api_request_command(
    const netsentinel::api::LocalRestApiConfig& config,
    const netsentinel::api::LocalRestApiRequest& request
) {
    const auto response = netsentinel::api::handle_local_rest_api_request(config, request);
    if (response.status_code < 200 || response.status_code >= 300) {
        std::cerr << "Local API request failed: HTTP " << response.status_code << "\n";
        std::cerr << response.body << "\n";
        return 3;
    }
    std::cout << "LOCAL_API_REQUEST_OK\n";
    std::cout << "status=" << response.status_code << "\n";
    std::cout << "content_type=" << response.content_type << "\n";
    std::cout << "security_controls=" << join_csv(response.security_controls) << "\n";
    std::cout << response.body << "\n";
    return 0;
}

int print_agent_protocol_command(
    const netsentinel::api::AgentCollectorConfig& config,
    const std::string& output_path
) {
    const auto session = netsentinel::api::run_mock_agent_collector_session(config);
    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Agent protocol report write failed: " << output_path << "\n";
            return 3;
        }
        out << netsentinel::api::agent_collector_protocol_markdown(session);
    }

    if (!session.accepted) {
        std::cerr << "Agent collector protocol rejected configuration.\n";
        for (const auto& error : session.validation.errors) {
            std::cerr << "- " << error << "\n";
        }
        return 3;
    }

    std::cout << "AGENT_COLLECTOR_PROTOCOL_OK\n";
    std::cout << "accepted=true\n";
    std::cout << "collector_id=" << session.collector_id << "\n";
    std::cout << "agent_id=" << session.agent_id << "\n";
    std::cout << "agent_kind=" << session.agent_kind << "\n";
    std::cout << "message=" << session.message << "\n";
    std::cout << "security_controls=" << join_csv(session.validation.security_controls) << "\n";
    std::cout << "telemetry_count=" << session.telemetry.size() << "\n";
    if (!output_path.empty()) {
        std::cout << "report=" << output_path << "\n";
    }
    std::cout << netsentinel::api::agent_collector_session_json(session) << "\n";
    return 0;
}

int print_report_generate_command(const netsentinel::reports::ReportConfig& config) {
    if (!config.output_path.empty()) {
        std::cout << "privacy_warning=Reports may contain private device data. Share exported files only with authorized recipients.\n";
    }
    const auto report = netsentinel::reports::write_report(config);
    if (!report.success) {
        std::cerr << "Report generation failed: " << report.message << "\n";
        return 3;
    }
    std::cout << "REPORT_GENERATE_OK\n";
    std::cout << "type=" << report.report_type << "\n";
    std::cout << "format=" << report.format << "\n";
    std::cout << "written=" << (report.written ? "true" : "false") << "\n";
    if (!report.output_path.empty()) {
        std::cout << "output=" << report.output_path << "\n";
    }
    std::cout << "warnings=" << report.warnings.size() << "\n";
    for (const auto& warning : report.warnings) {
        std::cout << "warning=" << warning << "\n";
    }
    if (config.output_path.empty()) {
        std::cout << report.content << "\n";
    }
    return 0;
}

int print_gui_shell_command(const netsentinel::ui::GuiShellConfig& config) {
    const auto model = netsentinel::ui::build_gui_shell_model(config);
    std::cout << "GUI_SHELL_OK\n";
    std::cout << "qt_available=" << (model.qt_available ? "true" : "false") << "\n";
    std::cout << "demo_mode=" << (model.demo_mode ? "true" : "false") << "\n";
    std::cout << "view_count=" << model.views.size() << "\n";
    std::cout << "message=" << model.message << "\n";
    for (const auto& view : model.views) {
        std::cout << "view=" << view.id
                  << ",title=" << view.title
                  << ",badge=" << view.badge
                  << ",enabled=" << (view.enabled ? "true" : "false") << "\n";
    }
    if (!model.warnings.empty()) {
        std::cout << "warnings=" << model.warnings.size() << "\n";
        for (const auto& warning : model.warnings) {
            std::cout << "warning=" << warning << "\n";
        }
    }
    std::cout << netsentinel::ui::gui_shell_model_json(model) << "\n";
    return 0;
}

int print_gui_devices_command(const netsentinel::ui::GuiDeviceListConfig& config) {
    const auto model = netsentinel::ui::build_gui_device_list_model(config);
    std::cout << "GUI_DEVICES_OK\n";
    std::cout << "count=" << model.rows.size() << "\n";
    std::cout << "sort_by=" << model.sort_by << "\n";
    std::cout << "message=" << model.message << "\n";
    for (const auto& row : model.rows) {
        std::cout << "device=" << row.device_id
                  << ",hostname=" << (row.hostname.empty() ? "(none)" : row.hostname)
                  << ",ip=" << (row.primary_ip.empty() ? "(none)" : row.primary_ip)
                  << ",vendor=" << (row.vendor.empty() ? "(none)" : row.vendor)
                  << ",type=" << row.device_type
                  << ",icon=" << row.icon
                  << ",status=" << row.status_badge
                  << ",confidence=" << row.confidence_percent << "\n";
    }
    std::cout << netsentinel::ui::gui_device_list_model_json(model) << "\n";
    return 0;
}

int print_gui_bandwidth_dashboard_command(const netsentinel::ui::GuiBandwidthDashboardConfig& config) {
    const auto model = netsentinel::ui::build_gui_bandwidth_dashboard_model(config);
    std::cout << "GUI_BANDWIDTH_OK\n";
    std::cout << "success=" << (model.success ? "true" : "false") << "\n";
    std::cout << "empty_state=" << (model.empty_state ? "true" : "false") << "\n";
    std::cout << "active_source=" << model.active_source << "\n";
    std::cout << "top_talkers=" << model.top_talkers.size() << "\n";
    std::cout << "chart_points=" << model.history_chart.size() << "\n";
    std::cout << "alerts=" << model.alerts.size() << "\n";
    std::cout << "message=" << model.message << "\n";
    for (const auto& limitation : model.source_limitations) {
        std::cout << "limitation=" << limitation << "\n";
    }
    for (const auto& row : model.top_talkers) {
        std::cout << "talker=" << row.device_id
                  << ",rx=" << row.rx_bytes
                  << ",tx=" << row.tx_bytes
                  << ",confidence=" << row.confidence
                  << ",estimated=" << (row.incomplete_or_estimated ? "true" : "false")
                  << "\n";
    }
    std::cout << netsentinel::ui::gui_bandwidth_dashboard_json(model) << "\n";
    return model.success ? 0 : 3;
}

int print_gui_device_detail_command(
    const netsentinel::storage::StorageConfig& storage,
    const std::string& device_id
) {
    const auto detail = netsentinel::ui::build_gui_device_detail_model(storage, device_id);
    if (!detail.found) {
        std::cerr << "GUI device detail failed: " << detail.message << "\n";
        return 3;
    }
    std::cout << "GUI_DEVICE_DETAIL_OK\n";
    std::cout << "device=" << detail.summary.device_id << "\n";
    std::cout << "hostname=" << detail.summary.hostname << "\n";
    std::cout << "status=" << detail.summary.status_badge << "\n";
    std::cout << "protocol_count=" << detail.protocols.size() << "\n";
    std::cout << "history_count=" << detail.history.size() << "\n";
    std::cout << netsentinel::ui::gui_device_detail_json(detail) << "\n";
    return 0;
}

int print_gui_action_command(const netsentinel::ui::GuiActionRequest& request) {
    const auto result = netsentinel::ui::run_gui_action(request);
    if (!result.success) {
        std::cerr << "GUI action failed: " << result.message << "\n";
        if (result.requires_confirmation) {
            std::cerr << "Confirmation required. Re-run with --confirm or keep --dry-run behavior.\n";
        }
        std::cerr << netsentinel::ui::gui_action_result_json(result) << "\n";
        return result.requires_confirmation ? 2 : 3;
    }
    std::cout << "GUI_ACTION_OK\n";
    std::cout << "action=" << result.action_id << "\n";
    std::cout << "message=" << result.message << "\n";
    std::cout << "output=" << result.output << "\n";
    std::cout << netsentinel::ui::gui_action_result_json(result) << "\n";
    return 0;
}

int print_gui_accessibility_command(
    const netsentinel::ui::GuiAccessibilityConfig& config,
    const std::string& output_path
) {
    const auto model = netsentinel::ui::build_gui_accessibility_model(config);
    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "GUI accessibility report write failed: " << output_path << "\n";
            return 3;
        }
        out << netsentinel::ui::gui_accessibility_model_markdown(model);
    }
    std::cout << "GUI_ACCESSIBILITY_OK\n";
    std::cout << "language=" << model.language << "\n";
    std::cout << "language_file=" << model.language_file << "\n";
    std::cout << "keyboard_navigation_ready=" << (model.keyboard_navigation_ready ? "true" : "false") << "\n";
    std::cout << "high_dpi_ready=" << (model.high_dpi_ready ? "true" : "false") << "\n";
    std::cout << "screen_reader_labels_ready=" << (model.screen_reader_labels_ready ? "true" : "false") << "\n";
    std::cout << "low_resource_mode=" << (model.low_resource_mode ? "true" : "false") << "\n";
    std::cout << "low_resource_profile=" << model.low_resource_scan.profile << "\n";
    std::cout << "low_resource_concurrency=" << model.low_resource_scan.max_concurrency << "\n";
    std::cout << "low_resource_qps=" << model.low_resource_scan.max_qps << "\n";
    std::cout << "checks=" << model.checks.size() << "\n";
    if (!output_path.empty()) {
        std::cout << "output=" << output_path << "\n";
    }
    std::cout << netsentinel::ui::gui_accessibility_model_json(model) << "\n";
    return model.success ? 0 : 3;
}

int print_privacy_review_command(
    const netsentinel::api::PrivacyReviewRequest& request,
    const std::string& output_path
) {
    const auto result = netsentinel::api::run_privacy_review(request);
    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Privacy review report write failed: " << output_path << "\n";
            return 3;
        }
        out << netsentinel::api::privacy_review_markdown(result);
    }
    if (!result.success) {
        std::cerr << "Privacy review blocked: " << result.message << "\n";
        for (const auto& blocker : result.blockers) {
            std::cerr << "- " << blocker << "\n";
        }
        return 3;
    }
    std::cout << "PRIVACY_REVIEW_OK\n";
    std::cout << "export_allowed=" << (result.export_allowed ? "true" : "false") << "\n";
    std::cout << "warnings=" << result.warnings.size() << "\n";
    std::cout << "blockers=" << result.blockers.size() << "\n";
    std::cout << "inventory_retention_days=" << result.settings.retention.inventory_days << "\n";
    std::cout << "traffic_retention_days=" << result.settings.retention.traffic_history_days << "\n";
    std::cout << "presence_retention_days=" << result.settings.retention.presence_history_days << "\n";
    std::cout << "log_retention_days=" << result.settings.retention.log_days << "\n";
    if (!output_path.empty()) {
        std::cout << "output=" << output_path << "\n";
    }
    for (const auto& preview : result.redacted_log_preview) {
        std::cout << "redacted_log=" << preview << "\n";
    }
    return 0;
}

int print_simulation_run_command(
    const netsentinel::api::SimulationSuiteConfig& config,
    const std::string& output_path
) {
    const auto result = netsentinel::api::run_end_to_end_simulation(config);
    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Simulation report write failed: " << output_path << "\n";
            return 3;
        }
        out << netsentinel::api::simulation_suite_markdown(result);
    }
    if (!result.success) {
        std::cerr << "Simulation failed: " << result.message << "\n";
        std::cerr << netsentinel::api::simulation_suite_json(result) << "\n";
        return 3;
    }
    std::cout << "E2E_SIMULATION_OK\n";
    std::cout << "mock=" << (result.mock_mode ? "true" : "false") << "\n";
    std::cout << "devices=" << result.devices.size() << "\n";
    std::cout << "stages=" << result.stages.size() << "\n";
    std::cout << "warnings=" << result.warnings.size() << "\n";
    if (!output_path.empty()) {
        std::cout << "output=" << output_path << "\n";
    }
    for (const auto& stage : result.stages) {
        std::cout << "stage=" << stage.stage_id
                  << ",success=" << (stage.success ? "true" : "false")
                  << ",duration_ms=" << stage.duration_ms
                  << ",summary=" << stage.summary << "\n";
    }
    std::cout << netsentinel::api::simulation_suite_json(result) << "\n";
    return 0;
}

int print_release_candidate_command(
    const netsentinel::installer::ReleaseCandidateConfig& config,
    const std::string& output_path,
    const std::string& changelog_path
) {
    const auto readiness = netsentinel::installer::generate_release_candidate_readiness(config);
    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Release candidate report write failed: " << output_path << "\n";
            return 3;
        }
        out << netsentinel::installer::release_candidate_readiness_markdown(readiness);
    }
    if (!changelog_path.empty()) {
        std::ofstream out(changelog_path);
        if (!out) {
            std::cerr << "Release candidate changelog write failed: " << changelog_path << "\n";
            return 3;
        }
        out << netsentinel::installer::release_candidate_changelog_markdown(readiness);
    }
    std::cout << "RELEASE_CANDIDATE_OK\n";
    std::cout << "version=" << readiness.version << "\n";
    std::cout << "release_ready=" << (readiness.release_ready ? "true" : "false") << "\n";
    std::cout << "onboarding_steps=" << readiness.onboarding_steps.size() << "\n";
    std::cout << "safe_defaults=" << readiness.safe_defaults.size() << "\n";
    std::cout << "installer_disclosures=" << readiness.installer_disclosures.size() << "\n";
    std::cout << "checklist_items=" << readiness.checklist.size() << "\n";
    std::cout << "changelog_items=" << readiness.changelog.size() << "\n";
    std::cout << "blockers=" << readiness.blockers.size() << "\n";
    std::cout << "warnings=" << readiness.warnings.size() << "\n";
    if (!output_path.empty()) {
        std::cout << "output=" << output_path << "\n";
    }
    if (!changelog_path.empty()) {
        std::cout << "changelog=" << changelog_path << "\n";
    }
    for (const auto& blocker : readiness.blockers) {
        std::cout << "blocker=" << blocker << "\n";
    }
    return readiness.success ? 0 : 3;
}

int print_final_acceptance_audit_command(const std::string& output_path) {
    const auto audit = netsentinel::api::run_final_acceptance_audit();
    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Final acceptance audit write failed: " << output_path << "\n";
            return 3;
        }
        out << netsentinel::api::acceptance_audit_markdown(audit);
    }
    std::cout << "FINAL_ACCEPTANCE_AUDIT_OK\n";
    std::cout << "release_ready=" << (audit.release_ready ? "true" : "false") << "\n";
    std::cout << "features=" << audit.matrix.size() << "\n";
    std::size_t pass = 0;
    std::size_t partial = 0;
    std::size_t fail = 0;
    for (const auto& row : audit.matrix) {
        if (row.status == "pass") {
            ++pass;
        } else if (row.status == "partial") {
            ++partial;
        } else if (row.status == "fail") {
            ++fail;
        }
    }
    std::cout << "pass=" << pass << "\n";
    std::cout << "partial=" << partial << "\n";
    std::cout << "fail=" << fail << "\n";
    std::cout << "release_blockers=" << audit.release_blockers.size() << "\n";
    if (!output_path.empty()) {
        std::cout << "output=" << output_path << "\n";
    }
    for (const auto& blocker : audit.release_blockers) {
        std::cout << "blocker=" << blocker << "\n";
    }
    std::cout << netsentinel::api::acceptance_audit_json(audit) << "\n";
    return audit.success ? 0 : 3;
}

int print_installer_plan_command(const netsentinel::installer::InstallerPackagingConfig& config) {
    const auto plan = netsentinel::installer::generate_installer_packaging_plan(config);
    if (!plan.success) {
        std::cerr << "Installer plan failed: " << plan.message << "\n";
        return 3;
    }
    std::cout << "INSTALLER_PLAN_OK\n";
    std::cout << "format=" << plan.package_format << "\n";
    std::cout << "install_location=" << plan.install_location << "\n";
    std::cout << "steps=" << plan.packaging_steps.size() << "\n";
    std::cout << "permissions=" << plan.permission_explanations.size() << "\n";
    std::cout << "optional_checks=" << plan.optional_dependency_checks.size() << "\n";
    std::cout << "warnings=" << plan.warnings.size() << "\n";
    std::cout << netsentinel::installer::installer_plan_markdown(plan) << "\n";
    return 0;
}

int print_hardening_simulate_command(const netsentinel::hardening::MockNetworkSimulatorConfig& config) {
    const auto simulation = netsentinel::hardening::generate_mock_network(config);
    if (!simulation.success) {
        std::cerr << "Hardening simulator failed: " << simulation.message << "\n";
        return 3;
    }
    std::cout << "HARDENING_SIMULATION_OK\n";
    std::cout << "subnet=" << simulation.subnet << "\n";
    std::cout << "devices=" << simulation.devices.size() << "\n";
    std::cout << "message=" << simulation.message << "\n";
    const auto preview_count = std::min<std::size_t>(simulation.devices.size(), 8);
    for (std::size_t i = 0; i < preview_count; ++i) {
        const auto& device = simulation.devices[i];
        std::cout << "device=" << device.device_id
                  << " ip=" << device.ip_address
                  << " type=" << device.device_type
                  << " hostname=" << device.hostname
                  << " ports=" << device.open_ports.size()
                  << "\n";
    }
    return 0;
}

int print_hardening_fuzz_command() {
    const auto fuzz = netsentinel::hardening::run_parser_fuzz_smoke();
    if (!fuzz.success) {
        std::cerr << "Hardening parser fuzz failed.\n";
        for (const auto& finding : fuzz.findings) {
            std::cerr << "  " << finding << "\n";
        }
        return 3;
    }
    std::cout << "HARDENING_FUZZ_OK\n";
    std::cout << "cases=" << fuzz.cases_run << "\n";
    std::cout << "accepted=" << fuzz.accepted << "\n";
    std::cout << "rejected=" << fuzz.rejected << "\n";
    return 0;
}

int print_hardening_report_command(const netsentinel::hardening::MockNetworkSimulatorConfig& config) {
    const auto report = netsentinel::hardening::generate_hardening_report(config);
    if (!report.success) {
        std::cerr << "Hardening report failed: " << report.message << "\n";
        std::cerr << netsentinel::hardening::hardening_report_markdown(report) << "\n";
        return 3;
    }
    std::cout << "HARDENING_REPORT_OK\n";
    std::cout << "message=" << report.message << "\n";
    std::cout << "simulation_devices=" << report.simulation.devices.size() << "\n";
    std::cout << "benchmark_count=" << report.benchmarks.size() << "\n";
    std::cout << "fuzz_cases=" << report.fuzz.cases_run << "\n";
    std::cout << netsentinel::hardening::hardening_report_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_sources_command() {
    const auto capabilities = netsentinel::bandwidth::list_planned_bandwidth_source_capabilities();
    std::cout << "BANDWIDTH_SOURCES_OK\n";
    std::cout << "capabilities=" << capabilities.size() << "\n";
    std::cout << "active_sources=1\n";
    std::cout << "note=Prompt 52 exposes contracts and mock telemetry only; no packet capture or router polling is active.\n";
    std::cout << netsentinel::bandwidth::bandwidth_capabilities_markdown(capabilities) << "\n";
    return 0;
}

int print_bandwidth_sample_command(
    const netsentinel::bandwidth::MockBandwidthSourceConfig& config,
    bool mock_requested
) {
    if (!mock_requested) {
        std::cerr << "Bandwidth sample requires --mock in Prompt 52.\n";
        std::cerr << "Real sources are introduced in later prompts and must fail closed until configured.\n";
        return 2;
    }
    const auto status = netsentinel::bandwidth::collect_mock_bandwidth_samples(config);
    if (!status.success) {
        std::cerr << "Bandwidth sample failed: " << status.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(status.error.code) << "\n";
        return 3;
    }
    const auto attributions = netsentinel::bandwidth::build_attribution_results(status.samples);
    std::cout << "BANDWIDTH_SAMPLE_OK\n";
    std::cout << "source=" << status.capability.source_name << "\n";
    std::cout << "samples=" << status.samples.size() << "\n";
    std::cout << "attributions=" << attributions.size() << "\n";
    std::cout << "network_traffic=none\n";
    for (const auto& result : attributions) {
        std::cout << "attribution device=" << result.identity.device_id
                  << " rx_delta_bytes=" << result.rx_delta_bytes
                  << " tx_delta_bytes=" << result.tx_delta_bytes
                  << " confidence=" << netsentinel::bandwidth::to_string(result.confidence)
                  << "\n";
    }
    std::cout << netsentinel::bandwidth::bandwidth_samples_markdown(status) << "\n";
    return 0;
}

int print_bandwidth_npcap_command(const netsentinel::bandwidth::NpcapDetectionConfig& config) {
    const auto report = netsentinel::bandwidth::detect_npcap_capabilities(config);
    std::cout << "NPCAP_CAPABILITY_OK\n";
    std::cout << "installed=" << (report.installed ? "yes" : "no") << "\n";
    std::cout << "driver_service_present=" << (report.driver_service_present ? "yes" : "no") << "\n";
    std::cout << "admin=" << (report.current_user_admin ? "yes" : "no") << "\n";
    std::cout << "capture_available=" << (report.capture_available ? "yes" : "no") << "\n";
    std::cout << "monitor_mode_available=" << (report.monitor_mode_available ? "yes" : "no") << "\n";
    std::cout << "adapters=" << report.adapters.size() << "\n";
    std::cout << "network_traffic=none\n";
    std::cout << netsentinel::bandwidth::npcap_detection_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_local_command(const netsentinel::bandwidth::LocalMachineBandwidthConfig& config) {
    const auto snapshot = netsentinel::bandwidth::collect_local_machine_bandwidth(config);
    if (!snapshot.success) {
        std::cerr << "Local-machine bandwidth failed: " << snapshot.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(snapshot.error.code) << "\n";
        std::cerr << netsentinel::bandwidth::local_machine_bandwidth_markdown(snapshot) << "\n";
        return 3;
    }
    std::cout << "LOCAL_BANDWIDTH_OK\n";
    std::cout << "scope=" << snapshot.scope << "\n";
    std::cout << "samples=" << snapshot.status.samples.size() << "\n";
    std::cout << "rx_total_bytes=" << snapshot.rx_total_bytes << "\n";
    std::cout << "tx_total_bytes=" << snapshot.tx_total_bytes << "\n";
    std::cout << "rx_rate_bps=" << snapshot.rx_rate_bps << "\n";
    std::cout << "tx_rate_bps=" << snapshot.tx_rate_bps << "\n";
    std::cout << "persisted=" << (snapshot.persisted ? "yes" : "no") << "\n";
    std::cout << "storage_message=" << snapshot.storage_message << "\n";
    std::cout << "network_traffic=none\n";
    std::cout << netsentinel::bandwidth::local_machine_bandwidth_markdown(snapshot) << "\n";
    return 0;
}

int print_bandwidth_capture_command(const netsentinel::bandwidth::VisibleLanCaptureConfig& config) {
    const auto report = netsentinel::bandwidth::collect_visible_lan_capture_bandwidth(config);
    if (!report.success) {
        std::cerr << "Visible-LAN capture failed: " << report.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(report.error.code) << "\n";
        std::cerr << netsentinel::bandwidth::visible_lan_capture_markdown(report) << "\n";
        return 3;
    }
    std::cout << "VISIBLE_LAN_CAPTURE_OK\n";
    std::cout << "adapter=" << report.adapter_id << "\n";
    std::cout << "dry_run=" << (report.dry_run ? "yes" : "no") << "\n";
    std::cout << "capture_started=" << (report.capture_started ? "yes" : "no") << "\n";
    std::cout << "samples=" << report.samples.size() << "\n";
    std::cout << "attributions=" << report.attributions.size() << "\n";
    std::cout << "packet_injection=none\n";
    std::cout << "full_network_claim=no\n";
    std::cout << netsentinel::bandwidth::visible_lan_capture_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_snmp_command(const netsentinel::bandwidth::SnmpRouterCounterConfig& config) {
    const auto report = netsentinel::bandwidth::collect_snmp_router_counters(config);
    if (!report.success) {
        std::cerr << "SNMP router counters failed: " << report.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(report.error.code) << "\n";
        std::cerr << netsentinel::bandwidth::snmp_router_counter_markdown(report) << "\n";
        return 3;
    }
    std::cout << "SNMP_BANDWIDTH_OK\n";
    std::cout << "router=" << report.router_ip << "\n";
    std::cout << "read_only=yes\n";
    std::cout << "credential_reference_used=" << (report.credential_reference_used ? "yes" : "no") << "\n";
    std::cout << "network_poll_started=" << (report.network_poll_started ? "yes" : "no") << "\n";
    std::cout << "interfaces=" << report.interfaces.size() << "\n";
    std::cout << "samples=" << report.samples.size() << "\n";
    std::cout << "attributions=" << report.attributions.size() << "\n";
    std::cout << netsentinel::bandwidth::snmp_router_counter_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_upnp_command(const netsentinel::bandwidth::UpnpIgdCounterConfig& config) {
    const auto report = netsentinel::bandwidth::collect_upnp_igd_counters(config);
    if (!report.success) {
        std::cerr << "UPnP/IGD counters failed: " << report.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(report.error.code) << "\n";
        std::cerr << netsentinel::bandwidth::upnp_igd_counter_markdown(report) << "\n";
        return 3;
    }
    std::cout << "UPNP_IGD_BANDWIDTH_OK\n";
    std::cout << "gateway=" << report.gateway << "\n";
    std::cout << "read_only=yes\n";
    std::cout << "mapping_changes_attempted=" << (report.mapping_changes_attempted ? "yes" : "no") << "\n";
    std::cout << "counters_available=" << (report.counters_available ? "yes" : "no") << "\n";
    std::cout << "network_poll_started=" << (report.network_poll_started ? "yes" : "no") << "\n";
    std::cout << "attribution_level=" << (report.network_wide ? "network-wide" : "per-device") << "\n";
    std::cout << "samples=" << report.samples.size() << "\n";
    std::cout << netsentinel::bandwidth::upnp_igd_counter_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_flows_command(const netsentinel::bandwidth::FlowCollectorConfig& config) {
    const auto report = netsentinel::bandwidth::collect_flow_exports(config);
    if (!report.success) {
        std::cerr << "Flow collector failed: " << report.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(report.error.code) << "\n";
        std::cerr << netsentinel::bandwidth::flow_collector_markdown(report) << "\n";
        return 3;
    }
    std::cout << "FLOW_COLLECTOR_OK\n";
    std::cout << "bind=" << report.bind_address << "\n";
    std::cout << "port=" << report.port << "\n";
    std::cout << "explicit_enablement=" << (report.explicit_enablement ? "yes" : "no") << "\n";
    std::cout << "listener_started=" << (report.listener_started ? "yes" : "no") << "\n";
    std::cout << "records=" << report.records.size() << "\n";
    std::cout << "samples=" << report.samples.size() << "\n";
    std::cout << "active_scan_traffic=none\n";
    std::cout << netsentinel::bandwidth::flow_collector_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_plugin_command(const netsentinel::bandwidth::RouterPluginRequest& request) {
    if (request.operation == "list") {
        const auto capabilities = netsentinel::bandwidth::list_router_plugin_capabilities();
        std::cout << "ROUTER_PLUGIN_SDK_OK\n";
        std::cout << "plugins=" << capabilities.size() << "\n";
        std::cout << netsentinel::bandwidth::router_plugin_capabilities_markdown(capabilities) << "\n";
        return 0;
    }
    const auto result = netsentinel::bandwidth::run_router_plugin_request(request);
    if (!result.success) {
        std::cerr << "Router plugin failed: " << result.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(result.error.code) << "\n";
        std::cerr << netsentinel::bandwidth::router_plugin_result_markdown(result) << "\n";
        return result.requires_confirmation ? 2 : 3;
    }
    std::cout << "ROUTER_PLUGIN_ACTION_OK\n";
    std::cout << "plugin=" << result.plugin_id << "\n";
    std::cout << "operation=" << result.operation << "\n";
    std::cout << "applied=" << (result.applied ? "yes" : "no") << "\n";
    std::cout << "reversible=" << (result.reversible ? "yes" : "no") << "\n";
    std::cout << "password_scraping_used=" << (result.password_scraping_used ? "yes" : "no") << "\n";
    std::cout << "telemetry_samples=" << result.telemetry_samples.size() << "\n";
    std::cout << netsentinel::bandwidth::router_plugin_result_markdown(result) << "\n";
    return 0;
}

int print_bandwidth_limit_command(const netsentinel::bandwidth::BandwidthLimitRequest& request) {
    const auto result = netsentinel::bandwidth::run_safe_bandwidth_limit_backend(request);
    if (!result.success) {
        std::cerr << "Bandwidth limit backend failed: " << result.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(result.error.code) << "\n";
        std::cerr << netsentinel::bandwidth::bandwidth_limit_result_markdown(result) << "\n";
        return result.requires_confirmation ? 2 : 3;
    }
    std::cout << "BANDWIDTH_LIMIT_BACKEND_OK\n";
    std::cout << "backend=" << result.backend << "\n";
    std::cout << "action=" << result.action << "\n";
    std::cout << "dry_run=" << (result.dry_run ? "yes" : "no") << "\n";
    std::cout << "applied=" << (result.applied ? "yes" : "no") << "\n";
    std::cout << "reversible=" << (result.reversible ? "yes" : "no") << "\n";
    std::cout << "documented_api_used=" << (result.documented_api_used ? "yes" : "no") << "\n";
    std::cout << "unsafe_method_rejected=" << (result.unsafe_method_rejected ? "yes" : "no") << "\n";
    std::cout << "logged=" << (result.logged ? "yes" : "no") << "\n";
    std::cout << "rollback_id=" << result.rollback_id << "\n";
    std::cout << netsentinel::bandwidth::bandwidth_limit_result_markdown(result) << "\n";
    return 0;
}

int print_bandwidth_openwrt_command(const netsentinel::bandwidth::OpenWrtTelemetryConfig& config) {
    const auto report = netsentinel::bandwidth::collect_openwrt_readonly_telemetry(config);
    if (!report.success) {
        std::cerr << "OpenWrt telemetry failed: " << report.error.user_message << "\n";
        std::cerr << "error_code=" << netsentinel::bandwidth::to_string(report.error.code) << "\n";
        std::cerr << netsentinel::bandwidth::openwrt_telemetry_markdown(report) << "\n";
        return 3;
    }
    std::cout << "OPENWRT_TELEMETRY_OK\n";
    std::cout << "endpoint=" << report.endpoint << "\n";
    std::cout << "transport=" << report.transport << "\n";
    std::cout << "read_only=yes\n";
    std::cout << "credential_reference_used=" << (report.credential_reference_used ? "yes" : "no") << "\n";
    std::cout << "network_request_started=" << (report.network_request_started ? "yes" : "no") << "\n";
    std::cout << "firmware_supported=" << (report.firmware_supported ? "yes" : "no") << "\n";
    std::cout << "devices=" << report.devices.size() << "\n";
    std::cout << "samples=" << report.samples.size() << "\n";
    std::cout << netsentinel::bandwidth::openwrt_telemetry_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_attribute_command(const netsentinel::bandwidth::BandwidthAttributionMergeConfig& config, bool mock_requested) {
    if (!mock_requested) {
        std::cerr << "Bandwidth attribution requires --mock in Prompt 61 until live source orchestration is added.\n";
        return 2;
    }
    const auto samples = netsentinel::bandwidth::mock_bandwidth_attribution_samples();
    const auto report = netsentinel::bandwidth::attribute_bandwidth_per_device(samples, config);
    std::cout << "BANDWIDTH_ATTRIBUTION_OK\n";
    std::cout << "samples=" << samples.size() << "\n";
    std::cout << "devices=" << report.devices.size() << "\n";
    std::cout << "network_only_rx_bytes=" << report.network_only_rx_bytes << "\n";
    std::cout << "network_only_tx_bytes=" << report.network_only_tx_bytes << "\n";
    std::cout << "conflicts=" << report.conflicts.size() << "\n";
    std::cout << netsentinel::bandwidth::bandwidth_attribution_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_anomalies_command(
    const netsentinel::bandwidth::BandwidthAnomalyRuleConfig& config,
    bool mock_requested
) {
    if (!mock_requested) {
        std::cerr << "Bandwidth anomaly analysis requires --mock in Prompt 63 until live history orchestration is added.\n";
        return 2;
    }
    const auto samples = netsentinel::bandwidth::mock_bandwidth_attribution_samples();
    netsentinel::bandwidth::BandwidthAttributionMergeConfig merge_config{};
    merge_config.elapsed_seconds = 30.0;
    const auto current_report = netsentinel::bandwidth::attribute_bandwidth_per_device(samples, merge_config);
    std::vector<netsentinel::bandwidth::PerDeviceBandwidthUsage> baseline;
    for (auto device : current_report.devices) {
        device.rx_bytes = std::min<std::uint64_t>(device.rx_bytes / 8, 80000);
        device.tx_bytes = std::min<std::uint64_t>(device.tx_bytes / 8, 20000);
        baseline.push_back(std::move(device));
    }
    const auto report = netsentinel::bandwidth::analyze_bandwidth_top_talkers_and_anomalies(
        current_report.devices,
        baseline,
        config
    );
    std::cout << "BANDWIDTH_ANOMALIES_OK\n";
    std::cout << "top_talker_limit=" << config.top_talker_limit << "\n";
    std::cout << "top_talkers=" << report.top_talkers.size() << "\n";
    std::cout << "alerts=" << report.alerts.size() << "\n";
    std::cout << "not_malware_detection=yes\n";
    std::cout << "network_traffic=none\n";
    std::cout << netsentinel::bandwidth::bandwidth_anomaly_report_markdown(report) << "\n";
    return 0;
}

int print_bandwidth_rollups_command(
    const std::string& database_path,
    bool mock_requested,
    bool privacy_redact,
    const std::string& retention_cutoff
) {
    if (!mock_requested) {
        std::cerr << "Bandwidth rollup smoke requires --mock in Prompt 62.\n";
        return 2;
    }
    netsentinel::storage::StorageConfig storage_config{};
    storage_config.database_path = database_path.empty() ? "bandwidth_rollups_mock.db" : database_path;
    netsentinel::storage::BandwidthPrivacySettings privacy{};
    privacy.redact_device_identifiers = privacy_redact;
    privacy.store_source_metadata = true;

    const std::vector<std::string> granularities{"minute", "hour", "day"};
    std::size_t stored = 0;
    for (const auto& granularity : granularities) {
        netsentinel::storage::BandwidthRollupRecord record{};
        record.source_name = "attribution-engine";
        record.device_id = "mock-device-" + granularity;
        record.adapter_id = "aggregate";
        record.timestamp_utc = granularity == "minute" ? "2026-05-02T16:00:00Z" : "2026-05-02T17:00:00Z";
        record.rx_total_bytes = 1000 + stored;
        record.tx_total_bytes = 500 + stored;
        record.rx_rate_bps = 100.0 + static_cast<double>(stored);
        record.tx_rate_bps = 50.0 + static_cast<double>(stored);
        record.scope = "per-device";
        record.confidence = "high";
        record.notes = "Prompt 62 mock rollup.";
        record.rollup_granularity = granularity;
        record.source_metadata = "source=mock;granularity=" + granularity;
        const auto appended = netsentinel::storage::append_bandwidth_rollup_with_privacy(record, privacy, storage_config);
        if (!appended) {
            std::cerr << "Bandwidth rollup append failed: " << appended.error().user_message << "\n";
            return 3;
        }
        stored += appended.value();
    }

    std::size_t removed = 0;
    if (!retention_cutoff.empty()) {
        netsentinel::storage::BandwidthRetentionPolicy policy{};
        policy.rollup_granularity = "minute";
        policy.cutoff_utc = retention_cutoff;
        const auto retention = netsentinel::storage::apply_bandwidth_retention(policy, storage_config);
        if (!retention) {
            std::cerr << "Bandwidth retention failed: " << retention.error().user_message << "\n";
            return 3;
        }
        removed = retention.value().removed_count;
    }

    const auto listed = netsentinel::storage::list_bandwidth_rollups(storage_config, {});
    if (!listed) {
        std::cerr << "Bandwidth rollup list failed: " << listed.error().user_message << "\n";
        return 3;
    }
    std::cout << "BANDWIDTH_ROLLUPS_OK\n";
    std::cout << "stored=" << stored << "\n";
    std::cout << "listed=" << listed.value().size() << "\n";
    std::cout << "retention_removed=" << removed << "\n";
    std::cout << "privacy_redact=" << (privacy_redact ? "yes" : "no") << "\n";
    std::cout << "db=" << storage_config.database_path << "\n";
    return 0;
}

int print_timeline_command(const netsentinel::storage::TimelineFilter& filter) {
    const auto events = netsentinel::storage::list_timeline_records(netsentinel::storage::StorageConfig{}, filter);
    if (!events) {
        std::cerr << "Timeline query failed: " << netsentinel::engine::to_string(events.error().code) << "\n";
        std::cerr << events.error().user_message << "\n";
        return 3;
    }
    const auto& rows = events.value();
    std::cout << "Timeline: " << rows.size() << " event(s)\n\n";
    for (const auto& event : rows) {
        std::cout << event.at_utc << " | " << event.device_id << " | " << event.event_type << " | " << event.source << "\n";
        std::cout << "  network: " << (event.network_id.empty() ? "(none)" : event.network_id) << "\n";
        std::cout << "  severity: " << event.severity << "\n";
        if (!event.old_value.empty() || !event.new_value.empty()) {
            std::cout << "  old: " << (event.old_value.empty() ? "(none)" : event.old_value) << "\n";
            std::cout << "  new: " << (event.new_value.empty() ? "(none)" : event.new_value) << "\n";
        }
    }
    return 0;
}

std::string progress_kind_to_text(netsentinel::engine::ScanProgressKind kind) {
    switch (kind) {
        case netsentinel::engine::ScanProgressKind::started:
            return "started";
        case netsentinel::engine::ScanProgressKind::stage_started:
            return "stage-started";
        case netsentinel::engine::ScanProgressKind::stage_progress:
            return "stage-progress";
        case netsentinel::engine::ScanProgressKind::host_result:
            return "host-result";
        case netsentinel::engine::ScanProgressKind::stage_complete:
            return "stage-complete";
        case netsentinel::engine::ScanProgressKind::completed:
            return "completed";
        case netsentinel::engine::ScanProgressKind::cancelled:
            return "cancelled";
        case netsentinel::engine::ScanProgressKind::paused:
            return "paused";
        case netsentinel::engine::ScanProgressKind::failed:
            return "failed";
    }
    return "unknown";
}

void print_scan_progress(const netsentinel::engine::ScanProgressEvent& event) {
    std::cout << "[progress] ";
    std::cout << progress_kind_to_text(event.kind) << " | ";
    std::cout << event.stage << " | ";
    if (!event.target.empty()) {
        std::cout << event.target << " | ";
    }
    if (event.total > 0) {
        std::cout << event.current << "/" << event.total << " | ";
    }
    std::cout << event.message << "\n";
}

int print_interfaces_command(bool use_mock) {
    auto adapters = netsentinel::engine::list_network_adapters(use_mock);
    if (!adapters) {
        std::cerr << "Adapter inventory unavailable: " << netsentinel::engine::to_string(adapters.error().code) << "\n";
        std::cerr << adapters.error().user_message << "\n";
        return 3;
    }

    std::cout << "Adapter inventory (" << (use_mock ? "mock mode" : "live mode") << "):\n";
    std::cout << "Count: " << adapters.value().size() << "\n\n";

    for (std::size_t i = 0; i < adapters.value().size(); ++i) {
        const auto& adapter = adapters.value()[i];
        std::cout << (i + 1) << ". " << adapter.interface_name << "\n";
        std::cout << "  Adapter ID: " << adapter.adapter_id << "\n";
        if (adapter.friendly_name && !adapter.friendly_name->empty()) {
            std::cout << "  Friendly name: " << *adapter.friendly_name << "\n";
        }
        if (adapter.mac_address && !adapter.mac_address->empty()) {
            std::cout << "  MAC: " << *adapter.mac_address << "\n";
        } else {
            std::cout << "  MAC: (unknown)\n";
        }
        std::cout << "  Status: " << (adapter.up ? "up" : "down") << "\n";
        std::cout << "  DHCP: " << (adapter.dhcp_enabled ? "enabled" : "disabled") << "\n";
        std::cout << "  Link speed: " << adapter.link_speed_mbps << " Mbps\n";
        std::cout << "  IPv4: " << join_csv(adapter.ipv4_addresses) << "\n";
        std::cout << "  IPv6: " << join_csv(adapter.ipv6_addresses) << "\n";
        std::cout << "  Gateway: " << (adapter.gateway && !adapter.gateway->empty() ? *adapter.gateway : std::string("(none)")) << "\n";
        std::cout << "  DNS: " << join_csv(adapter.dns_servers) << "\n\n";
    }
    if (adapters.value().empty()) {
        std::cout << "No network adapters were discovered.\n";
        std::cout << "This environment may have disabled network APIs or no active adapters.\n";
    }
    return 0;
}

int print_scope_command(bool use_mock, const std::string& custom_scope, bool confirm, bool allow_non_local) {
    if (!custom_scope.empty()) {
        const auto proposal = netsentinel::engine::propose_scan_scope_from_custom_cidr(custom_scope, allow_non_local, confirm);
        if (!proposal) {
            std::cerr << "Scope proposal failed: " << netsentinel::engine::to_string(proposal.error().code) << "\n";
            std::cerr << proposal.error().user_message << "\n";
            return 3;
        }
        std::cout << "Scan scope proposal:\n";
        std::cout << "  Mode: custom\n";
        std::cout << "  Scope: " << proposal.value().scope_text << "\n";
        std::cout << "  CIDR: " << proposal.value().network_cidr << "\n";
        std::cout << "  Hosts: " << proposal.value().estimated_host_count << "\n";
        std::cout << "  Gateway: " << (proposal.value().gateway.empty() ? "(none)" : proposal.value().gateway) << "\n";
        std::cout << "  First host: " << proposal.value().first_host << "\n";
        std::cout << "  Last host: " << proposal.value().last_host << "\n";
        std::cout << "  Local-only: " << (proposal.value().local_only ? "yes" : "no") << "\n";
        if (!proposal.value().warning.empty()) {
            std::cout << "  Warning: " << proposal.value().warning << "\n";
        }
        return 0;
    }

    const auto adapters = netsentinel::engine::list_network_adapters(use_mock);
    if (!adapters) {
        std::cerr << "Scope proposal failed: " << netsentinel::engine::to_string(adapters.error().code) << "\n";
        std::cerr << adapters.error().user_message << "\n";
        return 3;
    }
    if (adapters.value().empty()) {
        std::cerr << "No adapters available for scope derivation.\n";
        return 4;
    }
    const auto proposal = netsentinel::engine::propose_scan_scope_from_adapter(adapters.value()[0]);
    if (!proposal) {
        std::cerr << "Scope proposal failed: " << netsentinel::engine::to_string(proposal.error().code) << "\n";
        std::cerr << proposal.error().user_message << "\n";
        return 3;
    }
    std::cout << "Scan scope proposal (" << (use_mock ? "mock mode" : "live mode") << "):\n";
    std::cout << "  Adapter: " << adapters.value()[0].interface_name << "\n";
    std::cout << "  Scope: " << proposal.value().scope_text << "\n";
    std::cout << "  CIDR: " << proposal.value().network_cidr << "\n";
    std::cout << "  Hosts: " << proposal.value().estimated_host_count << "\n";
    std::cout << "  Gateway: " << (proposal.value().gateway.empty() ? "(none)" : proposal.value().gateway) << "\n";
    std::cout << "  Local-only: " << (proposal.value().local_only ? "yes" : "no") << "\n";
    if (!proposal.value().warning.empty()) {
        std::cout << "  Warning: " << proposal.value().warning << "\n";
    }
    return 0;
}

int print_arp_scan_command(const std::string& scope, bool mock) {
    const std::string effective_scope = scope.empty() ? "192.168.1.0/24" : scope;
    const netsentinel::engine::ArpDiscoveryRequest request{
        .cidr_or_range = effective_scope,
        .max_host_count = 1024,
        .only_local = true,
        .mock_mode = mock
    };
    const auto devices = netsentinel::engine::discover_arp_devices(request);
    if (!devices) {
        std::cerr << "ARP scan failed: " << netsentinel::engine::to_string(devices.error().code) << "\n";
        std::cerr << devices.error().user_message << "\n";
        return 3;
    }

    std::cout << "ARP scan (" << (mock ? "mock mode" : "live mode") << ")\n";
    std::cout << "Scope: " << effective_scope << "\n";
    std::cout << "Count: " << devices.value().size() << "\n\n";
    for (std::size_t i = 0; i < devices.value().size(); ++i) {
        const auto& device = devices.value()[i];
        std::cout << (i + 1) << ". " << device.ip_address << "\n";
        std::cout << "  MAC: " << device.mac_address << "\n";
        std::cout << "  Latency: " << device.latency_ms << " ms\n";
        std::cout << "  Adapter: " << device.adapter_id << "\n\n";
    }
    return 0;
}

int print_icmp_scan_command(const std::string& scope, bool mock) {
    const auto hosts = netsentinel::engine::discover_icmp_hosts(scope, mock);
    if (!hosts) {
        std::cerr << "ICMP scan failed: " << netsentinel::engine::to_string(hosts.error().code) << "\n";
        std::cerr << hosts.error().user_message << "\n";
        return 3;
    }

    const std::string effective_scope = scope.empty() ? "192.168.1.0/24" : scope;
    std::cout << "ICMP sweep (" << (mock ? "mock mode" : "live mode") << ")\n";
    std::cout << "Scope: " << effective_scope << "\n";
    std::cout << "Count: " << hosts.value().size() << "\n\n";
    for (std::size_t i = 0; i < hosts.value().size(); ++i) {
        const auto& host = hosts.value()[i];
        std::cout << (i + 1) << ". " << host.ip_address << "\n";
        std::cout << "  Ping: " << (host.ping_ok ? "up" : "down") << "\n";
        std::cout << "  Latency: " << host.ping_latency_ms << " ms\n";
        std::cout << "  ARP source: " << (host.from_arp_cache ? "yes" : "no") << "\n";
        std::cout << "  Adapter: " << host.adapter_id << "\n\n";
    }
    return 0;
}

int print_tcp_scan_command(const std::string& scope, bool mock) {
    const auto hosts = netsentinel::engine::discover_tcp_liveness(scope, mock);
    if (!hosts) {
        std::cerr << "TCP scan failed: " << netsentinel::engine::to_string(hosts.error().code) << "\n";
        std::cerr << hosts.error().user_message << "\n";
        return 3;
    }

    const std::string effective_scope = scope.empty() ? "192.168.1.0/24" : scope;
    std::cout << "TCP liveness scan (" << (mock ? "mock mode" : "live mode") << ")\n";
    std::cout << "Scope: " << effective_scope << "\n";
    std::cout << "Count: " << hosts.value().size() << "\n\n";
    for (std::size_t i = 0; i < hosts.value().size(); ++i) {
        const auto& host = hosts.value()[i];
        std::cout << (i + 1) << ". " << host.ip_address << "\n";
        std::cout << "  ICMP: " << (host.icmp_up ? "up" : "down") << "\n";
        std::cout << "  ICMP latency: " << host.icmp_latency_ms << " ms\n";
        for (std::size_t j = 0; j < host.ports.size(); ++j) {
            const auto& port = host.ports[j];
            std::string state = "closed";
            if (port.open) {
                state = "open";
            } else if (port.timed_out) {
                state = "timeout";
            } else if (port.error) {
                state = "error";
            }
            std::cout << "  Port " << port.port << ": " << state << " (" << port.latency_ms << " ms)\n";
        }
        std::cout << "\n";
    }
    return 0;
}

int print_netbios_scan_command(const std::string& scope, bool mock) {
    const std::string effective_scope = scope.empty() ? "192.168.1.0/24" : scope;
    const auto arp_request = netsentinel::engine::ArpDiscoveryRequest{
        .cidr_or_range = effective_scope,
        .max_host_count = 16,
        .only_local = true,
        .mock_mode = mock
    };
    const auto hosts = netsentinel::engine::discover_arp_devices(arp_request);
    if (!hosts) {
        std::cerr << "NetBIOS scan failed: " << netsentinel::engine::to_string(hosts.error().code) << "\n";
        std::cerr << hosts.error().user_message << "\n";
        return 3;
    }
    std::cout << "NetBIOS scan (" << (mock ? "mock mode" : "live mode") << ")\n";
    std::cout << "Scope: " << effective_scope << "\n";
    std::cout << "Hosts to query: " << hosts.value().size() << "\n\n";
    const netsentinel::engine::NetBiosDiscoveryConfig config{
        .timeout_ms = 500,
        .cache_ttl_ms = 5 * 60 * 1000,
        .cache_enabled = true,
        .mock_mode = mock
    };
    std::size_t resolved = 0;
    for (std::size_t i = 0; i < hosts.value().size(); ++i) {
        const auto& host = hosts.value()[i];
        const auto result = netsentinel::engine::resolve_netbios_name_for_ip(host.ip_address, config);
        std::cout << (i + 1) << ". " << host.ip_address << "\n";
        if (result) {
            if (result.value().resolved) {
                ++resolved;
                std::cout << "  Name: " << (result.value().device_name.empty() ? "(empty)" : result.value().device_name) << "\n";
                std::cout << "  Workgroup: " << (result.value().workgroup.empty() ? "(none)" : result.value().workgroup) << "\n";
            } else {
                std::cout << "  Name: (not found)\n";
            }
            std::cout << "  Source: " << result.value().source << "\n";
            std::cout << "  Status: " << (result.value().resolved ? "resolved" : "unresolved") << "\n";
        } else {
            std::cout << "  Status: failed\n";
            std::cout << "  Error: " << result.error().context << "\n";
        }
        std::cout << "\n";
    }
    std::cout << "Resolved names: " << resolved << "\n";
    return 0;
}

int print_mdns_scan_command(bool mock) {
    const netsentinel::engine::MdnsDiscoveryConfig config{
        .query_timeout_ms = 700,
        .response_wait_ms = 700,
        .max_services = 128,
        .mock_mode = mock
    };
    const auto services = netsentinel::engine::discover_mdns_services(config);
    if (!services) {
        std::cerr << "mDNS scan failed: " << netsentinel::engine::to_string(services.error().code) << "\n";
        std::cerr << services.error().user_message << "\n";
        return 3;
    }

    std::cout << "mDNS scan (" << (mock ? "mock mode" : "live mode") << ")\n";
    std::cout << "Services discovered: " << services.value().size() << "\n\n";
    for (std::size_t i = 0; i < services.value().size(); ++i) {
        const auto& service = services.value()[i];
        std::cout << (i + 1) << ". " << service.service_instance << "\n";
        std::cout << "  Service: " << service.service_name << "\n";
        std::cout << "  Type hint: " << service.device_type_hint << "\n";
        std::cout << "  Target: " << (service.target.empty() ? "(none)" : service.target) << "\n";
        std::cout << "  Port: " << service.port << "\n";
        std::cout << "  TTL: " << service.ttl_ms << " ms\n";
    }
    return 0;
}

int print_ssdp_scan_command(bool mock) {
    const netsentinel::engine::SsdpDiscoveryConfig config{
        .query_timeout_ms = 900,
        .response_wait_ms = 900,
        .http_timeout_ms = 600,
        .max_devices = 128,
        .parse_description = true,
        .mock_mode = mock
    };
    const auto devices = netsentinel::engine::discover_ssdp_devices(config);
    if (!devices) {
        std::cerr << "SSDP scan failed: " << netsentinel::engine::to_string(devices.error().code) << "\n";
        std::cerr << devices.error().user_message << "\n";
        return 3;
    }

    std::cout << "SSDP scan (" << (mock ? "mock mode" : "live mode") << ")\n";
    std::cout << "Devices discovered: " << devices.value().size() << "\n\n";
    for (std::size_t i = 0; i < devices.value().size(); ++i) {
        const auto& device = devices.value()[i];
        std::cout << (i + 1) << ". " << (device.friendly_name.empty() ? device.target : device.friendly_name) << "\n";
        std::cout << "  Type: " << (device.device_type.empty() ? "(unknown)" : device.device_type) << "\n";
        std::cout << "  Manufacturer: " << (device.manufacturer.empty() ? "(unknown)" : device.manufacturer) << "\n";
        std::cout << "  Model: " << (device.model_name.empty() ? "(unknown)" : device.model_name) << "\n";
        std::cout << "  Presentation URL: " << (device.presentation_url.empty() ? "(none)" : device.presentation_url) << "\n";
        std::cout << "  Target: " << (device.target.empty() ? "(none)" : device.target) << "\n";
        std::cout << "  Location: " << (device.location.empty() ? "(none)" : device.location) << "\n";
        std::cout << "  TTL: " << device.ttl_ms << " ms\n";
        std::cout << "  Details: " << (device.details.empty() ? "none" : device.details) << "\n";
    }
    return 0;
}

int print_snmp_scan_command(const std::string& target, const std::string& community, const std::string& version, bool mock) {
    const netsentinel::engine::SnmpReadOnlyHintConfig config{
        .target = target,
        .community = community,
        .version = version,
        .response_timeout_ms = 700,
        .mock_mode = mock
    };
    const auto hints = netsentinel::engine::discover_snmp_read_only_hints(config);
    if (!hints) {
        std::cerr << "SNMP scan failed: " << netsentinel::engine::to_string(hints.error().code) << "\n";
        std::cerr << hints.error().user_message << "\n";
        return 3;
    }

    std::cout << "SNMP scan (" << (mock ? "mock mode" : "live mode") << ")\n";
    std::cout << "Target: " << target << "\n";
    std::cout << "Version: " << version << "\n";
    std::cout << "Hints: " << hints.value().size() << "\n\n";
    for (std::size_t i = 0; i < hints.value().size(); ++i) {
        const auto& hint = hints.value()[i];
        std::cout << (i + 1) << ". " << hint.target << "\n";
        std::cout << "  sysDescr: " << (hint.sys_descr.empty() ? "(none)" : hint.sys_descr) << "\n";
        std::cout << "  sysName: " << (hint.sys_name.empty() ? "(none)" : hint.sys_name) << "\n";
        std::cout << "  sysObjectID: " << (hint.sys_object_id.empty() ? "(none)" : hint.sys_object_id) << "\n";
        std::cout << "  Source: " << (hint.source.empty() ? "(none)" : hint.source) << "\n";
        std::cout << "  Confidence: " << hint.confidence << "\n";
        std::cout << "  Details: " << (hint.details.empty() ? "(none)" : hint.details) << "\n";
    }
    return 0;
}

int print_scan_session_command(
    const std::string& scope,
    bool mock,
    std::size_t max_concurrency,
    std::size_t max_qps,
    long long jitter_min_ms,
    long long jitter_max_ms,
    int timeout_seconds,
    const std::string& profile_name,
    std::size_t schedule_interval_minutes,
    const std::vector<std::string>& enabled_probes,
    const std::vector<int>& tcp_port_hints,
    const std::string& snmp_target,
    const std::string& snmp_community,
    const std::string& snmp_version
) {
    const std::string effective_scope = scope.empty() ? "192.168.1.0/24" : scope;
    const netsentinel::engine::ScanProfile profile{
        .profile_id = "cli-session",
        .name = "cli-session",
        .scope = netsentinel::engine::NetworkScope{
            .scope_id = "cli-session-scope",
            .cidr_or_range = effective_scope,
            .notes = "cli session scan",
            .local_only = true,
            .authorized = true,
            .created_epoch_ms = 0
        },
        .enabled = true,
        .timeout_seconds = timeout_seconds,
        .retries = 1
    };
    const netsentinel::engine::ScanDependencies dependencies{
        .permission_granted = true,
        .adapters_available = true
    };
    const netsentinel::engine::ScanCancellation cancellation{};
    const netsentinel::engine::ScanSessionRunOptions options{
        .mock_mode = mock,
        .max_concurrency = max_concurrency,
        .max_qps = max_qps,
        .jitter_ms_min = jitter_min_ms,
        .jitter_ms_max = jitter_max_ms,
        .enabled_probes = enabled_probes,
        .tcp_port_hints = tcp_port_hints,
        .schedule_interval_minutes = schedule_interval_minutes,
        .snmp_target = snmp_target,
        .snmp_community = snmp_community,
        .snmp_version = snmp_version,
        .on_progress = [](const netsentinel::engine::ScanProgressEvent& event) {
            print_scan_progress(event);
        }
    };

    const auto session = netsentinel::engine::run_scan_session(profile, dependencies, cancellation, options);
    if (!session) {
        std::cerr << "Scan session failed: " << netsentinel::engine::to_string(session.error().code) << "\n";
        std::cerr << session.error().user_message << "\n";
        return 3;
    }

    std::cout << "Scan session (" << (mock ? "mock mode" : "live mode") << ")\n";
    std::cout << "Profile: " << profile_name << "\n";
    std::cout << "Schedule minutes: " << schedule_interval_minutes << "\n";
    std::cout << "Scope: " << effective_scope << "\n";
    std::cout << "Session ID: " << session.value().session_id << "\n";
    std::cout << "Status: " << session.value().status_text << "\n";
    std::cout << "Completed: " << (session.value().completed ? "yes" : "no") << "\n";
    std::cout << "Probe results: " << session.value().probe_results.size() << "\n\n";
    const auto saved = netsentinel::storage::save_scan_session(profile, session.value());
    if (saved) {
        std::cout << "Storage: saved as session row " << saved.value() << "\n";
    } else {
        std::cout << "Storage: save failed (" << saved.error().context << ")\n";
    }

    std::size_t printed = 0;
    for (std::size_t i = 0; i < session.value().probe_results.size() && printed < 40; ++i) {
        const auto& result = session.value().probe_results[i];
        std::cout << (i + 1) << ". " << result.probe_name << " " << result.target << "\n";
        std::cout << "  Success: " << (result.success ? "yes" : "no") << "\n";
        std::cout << "  Latency: " << result.response_time_ms << " ms\n";
        std::cout << "  Message: " << result.message << "\n";
        ++printed;
    }
    if (session.value().probe_results.size() > printed) {
        std::cout << "... and " << (session.value().probe_results.size() - printed) << " more probe results\n";
    }
    return 0;
}

bool is_metered_network_detected() {
    const auto* forced = std::getenv("NETSENTINEL_FORCE_METERED");
    if (forced == nullptr) {
        return false;
    }
    const std::string_view value{forced};
    return !(value == "0" || value == "false" || value == "off" || value == "no");
}

std::vector<std::string> collect_live_hosts(const netsentinel::engine::ScanSession& session) {
    std::vector<std::string> out;
    out.reserve(session.probe_results.size());
    for (const auto& result : session.probe_results) {
        if (!result.success || result.target.empty()) {
            continue;
        }
        out.push_back(result.target);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

void emit_host_delta_events(
    std::size_t cycle_index,
    const std::vector<std::string>& previous_hosts,
    const std::vector<std::string>& current_hosts,
    std::size_t& emitted_events
) {
    const std::unordered_set<std::string> previous_set(previous_hosts.begin(), previous_hosts.end());
    const std::unordered_set<std::string> current_set(current_hosts.begin(), current_hosts.end());

    for (const auto& host : current_hosts) {
        if (previous_set.find(host) == previous_set.end()) {
            std::cout << "[monitor][" << cycle_index << "] event=discovered-host target=" << host << "\n";
            ++emitted_events;
        }
    }
    for (const auto& host : previous_hosts) {
        if (current_set.find(host) == current_set.end()) {
            std::cout << "[monitor][" << cycle_index << "] event=lost-host target=" << host << "\n";
            ++emitted_events;
        }
    }
}

std::size_t compute_backoff_interval(
    std::size_t base_interval,
    std::size_t current_interval,
    std::size_t failures,
    bool no_delay_requested
) {
    if (failures == 0) {
        return base_interval;
    }
    if (no_delay_requested) {
        return std::min<std::size_t>(60, std::max<std::size_t>(1, failures));
    }
    const std::size_t base = std::max<std::size_t>(1, base_interval);
    const auto factor = 1ull << std::min<std::size_t>(6, failures + 1);
    return std::min<std::size_t>(480, base * factor);
}

int print_monitor_command(
    const std::string& scope,
    bool mock,
    std::size_t max_concurrency,
    std::size_t max_qps,
    long long jitter_min_ms,
    long long jitter_max_ms,
    int timeout_seconds,
    const std::string& profile_name,
    std::size_t schedule_interval_minutes,
    const std::vector<std::string>& enabled_probes,
    const std::vector<int>& tcp_port_hints,
    std::size_t max_runs,
    bool continuous,
    bool allow_metered,
    std::size_t monitor_interval_minutes,
    const std::string& snmp_target,
    const std::string& snmp_community,
    const std::string& snmp_version
) {
    const std::string effective_scope = scope.empty() ? "192.168.1.0/24" : scope;
    const bool no_delay_requested = monitor_interval_minutes == 0;
    std::size_t base_interval_minutes = monitor_interval_minutes;
    std::size_t current_interval_minutes = monitor_interval_minutes;
    std::size_t executed_runs = 0;
    std::size_t failed_runs = 0;
    std::size_t skipped_metered_runs = 0;
    std::size_t emitted_events = 0;
    std::size_t consecutive_failures = 0;
    std::vector<std::string> prior_live_hosts;
    if (!continuous && max_runs == 0) {
        max_runs = 1;
    }
    if (max_runs == 0 && !continuous) {
        std::cerr << "Invalid monitoring request: max-runs must be greater than zero when not continuous.\n";
        return 2;
    }
    const netsentinel::engine::ScanProfile profile{
        .profile_id = "cli-monitor",
        .name = "cli-monitor",
        .scope = netsentinel::engine::NetworkScope{
            .scope_id = "cli-monitor-scope",
            .cidr_or_range = effective_scope,
            .notes = "cli monitor session",
            .local_only = true,
            .authorized = true,
            .created_epoch_ms = 0
        },
        .enabled = true,
        .timeout_seconds = timeout_seconds,
        .retries = 1
    };
    const netsentinel::engine::ScanDependencies dependencies{
        .permission_granted = true,
        .adapters_available = true
    };
    const netsentinel::engine::ScanCancellation cancellation{};
    const netsentinel::engine::ScanSessionRunOptions run_options{
        .mock_mode = mock,
        .max_concurrency = max_concurrency,
        .max_qps = max_qps,
        .jitter_ms_min = jitter_min_ms,
        .jitter_ms_max = jitter_max_ms,
        .enabled_probes = enabled_probes,
        .tcp_port_hints = tcp_port_hints,
        .schedule_interval_minutes = schedule_interval_minutes,
        .snmp_target = snmp_target,
        .snmp_community = snmp_community,
        .snmp_version = snmp_version
    };

    std::cout << "Monitor session starting\n";
    std::cout << "Profile: " << profile_name << "\n";
    std::cout << "Scope: " << effective_scope << "\n";
    std::cout << "Base interval: " << base_interval_minutes << " minute(s)\n";
    std::cout << "Allow metered: " << (allow_metered ? "yes" : "no") << "\n";
    std::cout << "Continuous: " << (continuous ? "yes" : "no") << "\n";
    if (!continuous) {
        std::cout << "Max runs: " << max_runs << "\n";
    }

    std::size_t cycle_index = 0;
    std::size_t schedule_failures = 0;
    bool metered_mode = !allow_metered && is_metered_network_detected();
    std::optional<std::chrono::system_clock::time_point> expected_next_run;
    const auto tolerance = std::chrono::seconds(60);
    while (continuous || cycle_index < max_runs) {
        ++cycle_index;
        const auto cycle_start = std::chrono::system_clock::now();
        if (expected_next_run && cycle_start > expected_next_run.value() + tolerance) {
            const auto oversleep_seconds = std::chrono::duration_cast<std::chrono::seconds>(cycle_start - expected_next_run.value()).count();
            std::cout << "[monitor][" << cycle_index << "] event=system-wake duration_s=" << oversleep_seconds << "\n";
            ++emitted_events;
        }

        const bool skip_by_metered = !allow_metered && is_metered_network_detected();
        if (skip_by_metered) {
            ++skipped_metered_runs;
            metered_mode = true;
            std::cout << "[monitor][" << cycle_index << "] skip reason=metered-network\n";
            ++emitted_events;
        } else {
            metered_mode = false;
            const auto session = netsentinel::engine::run_scan_session(profile, dependencies, cancellation, run_options);
            if (!session) {
                ++failed_runs;
                ++consecutive_failures;
                ++schedule_failures;
                std::cerr << "Scan cycle " << cycle_index << " failed: " << netsentinel::engine::to_string(session.error().code) << "\n";
                std::cerr << session.error().user_message << "\n";
            } else {
                ++executed_runs;
                if (session.value().completed) {
                    const auto current_live = collect_live_hosts(session.value());
                    emit_host_delta_events(cycle_index, prior_live_hosts, current_live, emitted_events);
                    prior_live_hosts = current_live;
                    std::cout << "[monitor][" << cycle_index << "] status=completed runs=1 live_hosts=" << current_live.size() << "\n";
                    consecutive_failures = 0;
                    schedule_failures = 0;
                } else {
                    ++failed_runs;
                    ++consecutive_failures;
                    ++schedule_failures;
                    std::cerr << "Scan cycle " << cycle_index << " completed with warning: " << session.value().status_text << "\n";
                }
            }
        }

        current_interval_minutes = compute_backoff_interval(
            base_interval_minutes,
            current_interval_minutes,
            consecutive_failures,
            no_delay_requested
        );
        if (schedule_failures > 2) {
            std::cout << "[monitor][" << cycle_index << "] event=backoff active interval=" << current_interval_minutes << "\n";
            ++emitted_events;
            schedule_failures = 0;
        }

        if (consecutive_failures == 0) {
            current_interval_minutes = base_interval_minutes;
        }

        if (!continuous && cycle_index >= max_runs) {
            break;
        }
        if (no_delay_requested) {
            continue;
        }
        if (current_interval_minutes == 0) {
            continue;
        }
        expected_next_run = cycle_start + std::chrono::minutes(current_interval_minutes);
        std::this_thread::sleep_for(std::chrono::minutes(current_interval_minutes));
        if (expected_next_run && (std::chrono::system_clock::now() > expected_next_run.value())) {
            metered_mode = true;
        }
    }

    const auto total_runs = executed_runs + skipped_metered_runs;
    std::cout << "MONITOR_SUMMARY_OK\n";
    std::cout << "Cycles executed: " << total_runs << "\n";
    std::cout << "Scan runs: " << executed_runs << "\n";
    std::cout << "Skipped (metered): " << skipped_metered_runs << "\n";
    std::cout << "Failed runs: " << failed_runs << "\n";
    std::cout << "Events generated: " << emitted_events << "\n";
    std::cout << "Last status: " << (metered_mode ? "throttled-by-metered" : "running") << "\n";
    if (!continuous) {
        std::cout << "Requested runs: " << max_runs << "\n";
    }
    return 0;
}

int print_tray_status_command(bool use_mock) {
    netsentinel::service::TrayStatus status{};
    const auto result = netsentinel::service::get_tray_status(status, use_mock);
    if (!result.success) {
        std::cerr << "Tray status failed: " << netsentinel::service::to_string(result.code) << "\n";
        std::cerr << result.message << "\n";
        return 3;
    }
    std::cout << "TRAY_STATUS_OK\n";
    std::cout << "running=" << (status.running ? "true" : "false") << "\n";
    std::cout << "mock=" << (status.mock_mode ? "true" : "false") << "\n";
    std::cout << "profile=" << status.profile << "\n";
    std::cout << "scope=" << status.scope << "\n";
    std::cout << "interval=" << status.interval_minutes << "\n";
    std::cout << "mode=" << status.mode << "\n";
    std::cout << "updated=" << (status.last_update_utc.empty() ? "(none)" : status.last_update_utc) << "\n";
    std::cout << "service_optional=" << (status.service_optional ? "true" : "false") << "\n";
    std::cout << "visible_user_control=" << (status.visible_user_control ? "true" : "false") << "\n";
    std::cout << "crash_recovery_enabled=" << (status.crash_recovery_enabled ? "true" : "false") << "\n";
    std::cout << "hidden_persistence=" << (status.hidden_persistence ? "true" : "false") << "\n";
    std::cout << "crash_restart_limit=" << status.crash_restart_limit << "\n";
    std::cout << "crash_restart_count=" << status.crash_restart_count << "\n";
    std::cout << "log_path=" << (status.log_path.empty() ? "(none)" : status.log_path) << "\n";
    std::cout << "notes=" << result.message << "\n";
    return 0;
}

int print_tray_start_command(
    bool use_mock,
    const std::string& profile_name,
    std::size_t interval_minutes,
    const std::string& scope,
    std::size_t restart_limit
) {
    ScanSessionProfilePreset ignored_profile{};
    if (!resolve_scan_profile(profile_name, ignored_profile)) {
        std::cerr << "Invalid tray profile: " << profile_name << "\n";
        std::cerr << "Available profiles: manual, quick, standard, deep-safe, monitor\n";
        return 2;
    }

    netsentinel::service::TrayMonitorConfig config;
    config.profile = profile_name;
    config.scope = scope;
    config.interval_minutes = interval_minutes;
    config.crash_restart_limit = restart_limit;
    config.visible_user_control = true;
    const auto result = netsentinel::service::start_tray_monitoring(config, use_mock);
    if (!result.success) {
        std::cerr << "Tray start failed: " << netsentinel::service::to_string(result.code) << "\n";
        std::cerr << result.message << "\n";
        return 3;
    }
    std::cout << "TRAY_START_OK\n";
    std::cout << "profile=" << profile_name << "\n";
    std::cout << "scope=" << scope << "\n";
    std::cout << "interval=" << interval_minutes << "\n";
    std::cout << "crash_restart_limit=" << restart_limit << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "notes=" << result.message << "\n";
    return 0;
}

int print_tray_stop_command(bool use_mock) {
    const auto result = netsentinel::service::stop_tray_monitoring(use_mock);
    if (!result.success) {
        std::cerr << "Tray stop failed: " << netsentinel::service::to_string(result.code) << "\n";
        std::cerr << result.message << "\n";
        return 3;
    }
    std::cout << "TRAY_STOP_OK\n";
    std::cout << "running=false\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "notes=" << result.message << "\n";
    return 0;
}

int print_tray_cleanup_command(bool use_mock) {
    const auto result = netsentinel::service::cleanup_tray_monitoring(use_mock);
    if (!result.success) {
        std::cerr << "Tray cleanup failed: " << netsentinel::service::to_string(result.code) << "\n";
        std::cerr << result.message << "\n";
        return 3;
    }
    std::cout << "TRAY_CLEANUP_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "notes=" << result.message << "\n";
    return 0;
}

int print_tray_hardening_command(bool use_mock, const std::string& output_path) {
    const auto plan = netsentinel::service::build_tray_hardening_plan(use_mock);
    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Tray hardening report write failed: " << output_path << "\n";
            return 3;
        }
        out << netsentinel::service::tray_hardening_plan_markdown(plan);
    }
    std::cout << "TRAY_HARDENING_OK\n";
    std::cout << "mock=" << (plan.mock_mode ? "true" : "false") << "\n";
    std::cout << "service_optional=" << (plan.service_optional ? "true" : "false") << "\n";
    std::cout << "visible_user_control=" << (plan.visible_user_control ? "true" : "false") << "\n";
    std::cout << "crash_recovery_enabled=" << (plan.crash_recovery_enabled ? "true" : "false") << "\n";
    std::cout << "hidden_persistence_allowed=" << (plan.hidden_persistence_allowed ? "true" : "false") << "\n";
    std::cout << "uninstall_cleanup_available=" << (plan.uninstall_cleanup_available ? "true" : "false") << "\n";
    std::cout << "crash_restart_limit=" << plan.crash_restart_limit << "\n";
    std::cout << "state_path=" << plan.state_path << "\n";
    std::cout << "log_path=" << plan.log_path << "\n";
    std::cout << "controls=" << join_csv(plan.controls) << "\n";
    if (!output_path.empty()) {
        std::cout << "report=" << output_path << "\n";
    }
    return 0;
}

bool parse_alert_kind(const std::string_view kind_text, netsentinel::alerts::AlertKind& kind) {
    if (kind_text == "new-device") {
        kind = netsentinel::alerts::AlertKind::new_device;
        return true;
    }
    if (kind_text == "important-status-change") {
        kind = netsentinel::alerts::AlertKind::important_status_change;
        return true;
    }
    if (kind_text == "outage") {
        kind = netsentinel::alerts::AlertKind::outage;
        return true;
    }
    if (kind_text == "security-finding") {
        kind = netsentinel::alerts::AlertKind::security_finding;
        return true;
    }
    if (kind_text == "scan-failure") {
        kind = netsentinel::alerts::AlertKind::scan_failure;
        return true;
    }
    return false;
}

int print_alerts_test_command(
    bool use_mock,
    const std::string& kind_text,
    const std::string& message,
    const std::string& target,
    bool enable_toast,
    bool enable_email,
    bool enable_webhook,
    const std::string& email_from,
    const std::string& email_to,
    const std::string& webhook_url,
    std::size_t max_events_per_minute
) {
    netsentinel::alerts::AlertKind kind;
    if (!parse_alert_kind(kind_text, kind)) {
        std::cerr << "Invalid alert kind: " << kind_text << "\n";
        std::cerr << "Available kinds: new-device, important-status-change, outage, security-finding, scan-failure\n";
        return 2;
    }
    netsentinel::alerts::AlertRoutingConfig config;
    config.mock_mode = use_mock;
    config.enable_toast = enable_toast;
    config.enable_email = enable_email;
    config.enable_webhook = enable_webhook;
    config.max_events_per_minute = max_events_per_minute;
    config.email_from = email_from;
    config.email_to = email_to;
    config.webhook_url = webhook_url;

    const netsentinel::alerts::AlertEvent event{
        .kind = kind,
        .target_id = target,
        .message = message
    };
    const auto result = netsentinel::alerts::send_alert(config, event);
    if (!result.success) {
        std::cerr << "Alert dispatch failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "ALERT_TEST_OK\n";
    std::cout << "kind=" << netsentinel::alerts::to_string(kind) << "\n";
    std::cout << "target=" << (target.empty() ? "(none)" : target) << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "toast=" << (enable_toast ? "true" : "false") << "\n";
    std::cout << "email=" << (enable_email ? "true" : "false") << "\n";
    std::cout << "webhook=" << (enable_webhook ? "true" : "false") << "\n";
    if (!email_to.empty()) {
        std::cout << "email_to=" << email_to << "\n";
    }
    if (!webhook_url.empty()) {
        std::cout << "webhook_url=" << webhook_url << "\n";
    }
    std::cout << "max_rate_per_minute=" << max_events_per_minute << "\n";
    std::cout << "rate_limited=" << (result.rate_limited ? "true" : "false") << "\n";
    std::cout << "notes=" << result.message << "\n";
    if (use_mock) {
        std::cout << "privacy=local-only stub routing in mock mode.\n";
    } else {
        std::cout << "privacy=non-mock routing is intentionally stubbed and local-first.\n";
    }
    return 0;
}

int print_speed_test_command(
    bool use_mock,
    const std::string& endpoint,
    std::size_t samples,
    std::size_t timeout_ms,
    std::size_t retention_entries
) {
    netsentinel::speedtest::SpeedTestConfig config{};
    config.mock_mode = use_mock;
    config.endpoint = endpoint;
    config.sample_count = samples;
    config.timeout_ms = timeout_ms;
    config.retention_entries = retention_entries;
    const auto result = netsentinel::speedtest::run_speed_test(config);
    if (!result.success) {
        std::cerr << "Speed test failed: " << netsentinel::speedtest::to_string(result.code) << "\n";
        std::cerr << result.message << "\n";
        return 3;
    }
    const auto& sample = result.result.sample;
    std::cout << "SPEED_TEST_OK\n";
    std::cout << "endpoint=" << result.result.endpoint << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "samples=" << samples << "\n";
    std::cout << "timeout_ms=" << timeout_ms << "\n";
    std::cout << "retention=" << retention_entries << "\n";
    std::cout << "latency_ms=" << sample.latency_ms << "\n";
    std::cout << "jitter_ms=" << sample.jitter_ms << "\n";
    std::cout << "download_mbps=" << sample.download_mbps << "\n";
    std::cout << "upload_mbps=" << sample.upload_mbps << "\n";
    std::cout << "notes=" << result.message << "\n";
    std::cout << "notes2=Safe mock mode provides deterministic local-only measurements for now.\n";
    return 0;
}

int print_outage_check_command(
    bool use_mock,
    const std::string& gateway_ip,
    const std::string& dns_host,
    const std::string& external_url,
    const std::string& host_ip,
    std::size_t timeout_ms
) {
    netsentinel::outage::OutageCheckConfig config{};
    config.mock_mode = use_mock;
    config.gateway_ip = gateway_ip;
    config.dns_host = dns_host;
    config.external_url = external_url;
    config.host_ip = host_ip;
    config.timeout_ms = timeout_ms;
    const auto result = netsentinel::outage::run_outage_check(config);
    if (!result.success) {
        std::cerr << "Outage check failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "OUTAGE_CHECK_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "gateway=" << gateway_ip << "\n";
    std::cout << "dns=" << dns_host << "\n";
    std::cout << "external=" << external_url << "\n";
    std::cout << "host=" << host_ip << "\n";
    std::cout << "timeout_ms=" << timeout_ms << "\n";
    std::cout << "classification=" << netsentinel::outage::to_string(result.result.classification) << "\n";
    std::cout << "outage=" << (result.result.outage_detected ? "true" : "false") << "\n";
    std::cout << "message=" << result.result.message << "\n";
    std::cout << "persisted=" << (result.persisted ? "true" : "false") << "\n";
    std::cout << "notes=" << result.message << "\n";
    const auto history = netsentinel::outage::read_outage_history(3);
    std::cout << "timeline_count=" << history.size() << "\n";
    if (!history.empty()) {
        std::cout << "latest_classification=" << history.back().classification << "\n";
    }
    return 0;
}

int print_ping_command(
    bool use_mock,
    const std::string& target,
    std::size_t count,
    std::size_t timeout_ms
) {
    netsentinel::diagnostics::PingConfig config{};
    config.mock_mode = use_mock;
    config.target = target;
    config.count = count;
    config.timeout_ms = timeout_ms;
    const auto result = netsentinel::diagnostics::run_ping(config);
    if (!result.success) {
        std::cerr << "Ping failed: " << result.message << "\n";
        return 3;
    }
    const auto& ping = result.result;
    std::cout << "PING_OK\n";
    std::cout << "target=" << target << "\n";
    std::cout << "count=" << count << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "timeout_ms=" << timeout_ms << "\n";
    std::cout << "reachable=" << (ping.reachable ? "true" : "false") << "\n";
    std::cout << "timed_out=" << (ping.timed_out ? "true" : "false") << "\n";
    std::cout << "avg_latency_ms=" << ping.avg_latency_ms << "\n";
    std::cout << "message=" << ping.message << "\n";
    std::cout << "persisted=" << (result.persisted ? "true" : "false") << "\n";
    const auto history = netsentinel::diagnostics::read_diagnostics_history(3);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_traceroute_command(
    bool use_mock,
    const std::string& target,
    std::size_t max_hops,
    std::size_t timeout_ms
) {
    netsentinel::diagnostics::TracerouteConfig config{};
    config.mock_mode = use_mock;
    config.destination = target;
    config.max_hops = max_hops;
    config.timeout_ms = timeout_ms;
    const auto result = netsentinel::diagnostics::run_traceroute(config);
    if (!result.success) {
        std::cerr << "Traceroute failed: " << result.message << "\n";
        return 3;
    }
    const auto& trace = result.result;
    std::cout << "TRACEROUTE_OK\n";
    std::cout << "destination=" << target << "\n";
    std::cout << "max_hops=" << max_hops << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "timeout_ms=" << timeout_ms << "\n";
    std::cout << "destination_reached=" << (trace.destination_reached ? "true" : "false") << "\n";
    std::cout << "hops=" << trace.hops.size() << "\n";
    for (const auto& hop : trace.hops) {
        std::cout << "hop=" << hop.hop << "," << hop.address << "," << hop.latency_ms << "\n";
    }
    std::cout << "message=" << trace.message << "\n";
    const auto history = netsentinel::diagnostics::read_diagnostics_history(3);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_dns_command(
    bool use_mock,
    const std::string& target,
    bool reverse_lookup,
    const std::string& resolver,
    std::size_t max_records
) {
    netsentinel::diagnostics::DnsLookupConfig config{};
    config.mock_mode = use_mock;
    config.target = target;
    config.reverse = reverse_lookup;
    config.resolver = resolver;
    config.max_records = max_records;
    const auto result = netsentinel::diagnostics::run_dns_lookup(config);
    if (!result.success) {
        std::cerr << "DNS lookup failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "DNS_OK\n";
    std::cout << "target=" << target << "\n";
    std::cout << "mode=" << (reverse_lookup ? "reverse" : "forward") << "\n";
    std::cout << "resolver=" << resolver << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "resolved=" << (result.result.resolved ? "true" : "false") << "\n";
    std::cout << "answers=" << result.result.answers.size() << "\n";
    for (std::size_t i = 0; i < result.result.answers.size() && i < max_records; ++i) {
        std::cout << "answer" << (i + 1) << "=" << result.result.answers[i] << "\n";
    }
    std::cout << "message=" << result.message << "\n";
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_dns_benchmark_command(
    bool use_mock,
    const std::vector<std::string>& resolvers,
    const std::vector<std::string>& queries,
    std::size_t samples,
    std::size_t timeout_ms
) {
    netsentinel::diagnostics::DnsBenchmarkConfig config{};
    config.mock_mode = use_mock;
    config.resolvers = resolvers;
    config.queries = queries;
    config.samples = samples;
    config.timeout_ms = timeout_ms;
    const auto result = netsentinel::diagnostics::run_dns_benchmark(config);
    if (!result.success) {
        std::cerr << "DNS benchmark failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "DNS_BENCHMARK_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "resolver_count=" << result.results.size() << "\n";
    std::cout << "query_count=" << queries.size() << "\n";
    std::cout << "samples=" << samples << "\n";
    std::cout << "timeout_ms=" << timeout_ms << "\n";
    for (std::size_t i = 0; i < result.results.size(); ++i) {
        const auto& item = result.results[i];
        std::cout
            << "result" << i << "="
            << item.resolver << ","
            << "avg_ms=" << item.avg_latency_ms << ","
            << "failure_rate=" << item.failure_rate << ","
            << "consistency=" << item.consistency_score << ","
            << "dnssec=" << (item.dnssec_available ? "true" : "false") << ","
            << "recommendation=" << item.recommendation
            << "\n";
    }
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_dhcp_command(
    bool use_mock,
    const std::string& adapter_filter,
    bool allow_multiple_check
) {
    netsentinel::diagnostics::DhcpDiscoveryConfig config{};
    config.mock_mode = use_mock;
    config.adapter_filter = adapter_filter;
    config.allow_multiple_reply_check = allow_multiple_check;
    const auto result = netsentinel::diagnostics::run_dhcp_discovery(config);
    if (!result.success) {
        std::cerr << "DHCP discovery failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "DHCP_DISCOVERY_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "adapter_filter=" << (adapter_filter.empty() ? "(none)" : adapter_filter) << "\n";
    std::cout << "allow_multiple_check=" << (allow_multiple_check ? "true" : "false") << "\n";
    std::cout << "multiple_reply_detected=" << (result.multiple_reply_detected ? "true" : "false") << "\n";
    std::cout << "adapter_count=" << result.adapters.size() << "\n";
    std::cout << "limitations=" << result.limitations << "\n";
    std::cout << "message=" << result.message << "\n";
    for (std::size_t i = 0; i < result.adapters.size(); ++i) {
        const auto& adapter = result.adapters[i];
        std::cout << "adapter" << i << "="
                  << adapter.adapter_id << ","
                  << adapter.interface_name << ","
                  << "dhcp_enabled=" << (adapter.dhcp_enabled ? "true" : "false") << ","
                  << "server=" << adapter.selected_server << ","
                  << "responses=" << adapter.observed_servers.size() << ","
                  << "multiple=" << (adapter.multiple_responses_detected ? "true" : "false") << ","
                  << adapter.message << "\n";
    }
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_wifi_scan_command(
    bool use_mock,
    bool include_hidden
) {
    netsentinel::diagnostics::WifiScanConfig config{};
    config.mock_mode = use_mock;
    config.include_hidden = include_hidden;
    const auto result = netsentinel::diagnostics::run_wifi_scan(config);
    if (!result.success) {
        std::cerr << "Wi-Fi scan failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "WIFI_SCAN_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "include_hidden=" << (include_hidden ? "true" : "false") << "\n";
    std::cout << "network_count=" << result.networks.size() << "\n";
    std::cout << "connected_ssid=" << (result.connected_ssid.empty() ? "(none)" : result.connected_ssid) << "\n";
    std::cout << "message=" << result.message << "\n";
    for (std::size_t i = 0; i < result.networks.size(); ++i) {
        const auto& network = result.networks[i];
        std::cout
            << "network" << i << "="
            << network.ssid << ","
            << network.bssid << ","
            << "rssi=" << network.rssi_dbm << ","
            << "channel=" << network.channel << ","
            << "band=" << network.band << ","
            << "auth=" << network.auth << ","
            << "cipher=" << network.cipher << ","
            << "quality=" << network.signal_quality << ","
            << "connected=" << (network.connected ? "true" : "false") << ","
            << "hidden=" << (network.hidden ? "true" : "false")
            << "\n";
    }
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_wifi_analysis_command(
    bool use_mock,
    bool include_hidden
) {
    netsentinel::diagnostics::WifiScanConfig config{};
    config.mock_mode = use_mock;
    config.include_hidden = include_hidden;
    const auto result = netsentinel::diagnostics::run_wifi_channel_analysis(config);
    if (!result.success) {
        std::cerr << "Wi-Fi analysis failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "WIFI_ANALYSIS_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "total_networks=" << result.total_networks << "\n";
    std::cout << "crowded_channels=" << result.crowded_channels << "\n";
    std::cout << "weak_signal_count=" << result.weak_signal_count << "\n";
    std::cout << "insecure_network_count=" << result.insecure_network_count << "\n";
    std::cout << "band_count=" << result.band_summaries.size() << "\n";
    for (std::size_t i = 0; i < result.band_summaries.size(); ++i) {
        const auto& item = result.band_summaries[i];
        std::cout << "band" << i << "="
            << item.band << ","
            << "count=" << item.network_count << ","
            << "crowded_channels=" << item.crowded_channels << ","
            << "avg_quality=" << item.average_signal_quality << "\n";
    }
    for (std::size_t i = 0; i < result.security_warnings.size(); ++i) {
        const auto& warning = result.security_warnings[i];
        std::cout << "security_warning" << i << "="
            << warning.ssid << ","
            << warning.bssid << ","
            << warning.reason << "\n";
    }
    for (std::size_t i = 0; i < result.suggestions.size(); ++i) {
        std::cout << "suggestion" << i << "=" << result.suggestions[i] << "\n";
    }
    std::cout << "history_snapshot=" << result.history_snapshot << "\n";
    std::cout << "message=" << result.message << "\n";
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_wifi_environment_command(
    bool use_mock,
    bool include_hidden,
    const std::string& output_path
) {
    netsentinel::diagnostics::WifiScanConfig config{};
    config.mock_mode = use_mock;
    config.include_hidden = include_hidden;
    const auto result = netsentinel::diagnostics::run_wifi_environment_view(config);
    if (!result.success) {
        std::cerr << "Wi-Fi environment view failed: " << result.message << "\n";
        return 3;
    }
    const auto markdown = netsentinel::diagnostics::wifi_environment_markdown(result);
    if (!output_path.empty()) {
        std::ofstream out{output_path, std::ios::trunc};
        if (!out.is_open()) {
            std::cerr << "Failed to write Wi-Fi environment report: " << output_path << "\n";
            return 3;
        }
        out << markdown;
    }
    std::cout << "WIFI_ENVIRONMENT_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "include_hidden=" << (include_hidden ? "true" : "false") << "\n";
    std::cout << "scan_source=" << result.scan_source << "\n";
    std::cout << "network_count=" << result.networks.size() << "\n";
    std::cout << "connected_ssid=" << (result.connected_ssid.empty() ? "(none)" : result.connected_ssid) << "\n";
    std::cout << "recommendations=" << result.channel_recommendations.size() << "\n";
    std::cout << "output=" << (output_path.empty() ? "(stdout)" : output_path) << "\n";
    for (std::size_t i = 0; i < result.networks.size(); ++i) {
        const auto& network = result.networks[i];
        std::cout << "environment_network" << i << "="
            << network.ssid << ","
            << "bssid=" << (network.bssid.empty() ? "(none)" : network.bssid) << ","
            << "band=" << network.band << ","
            << "channel=" << network.channel << ","
            << "rssi=" << network.rssi_dbm << ","
            << "quality=" << network.signal_quality << ","
            << "auth=" << network.auth << ","
            << "overlap=" << network.overlap_count << ","
            << "severity=" << network.overlap_severity << ","
            << "connected=" << (network.connected ? "true" : "false") << "\n";
    }
    for (std::size_t i = 0; i < result.channel_recommendations.size(); ++i) {
        const auto& recommendation = result.channel_recommendations[i];
        std::cout << "channel_recommendation" << i << "="
            << recommendation.band << ","
            << "channel=" << recommendation.channel << ","
            << "severity=" << recommendation.severity << ","
            << recommendation.reason << "\n";
    }
    std::cout << markdown << "\n";
    return 0;
}

int print_wifi_sweetspot_command(
    const netsentinel::diagnostics::WifiSweetSpotConfig& config,
    const std::string& output_path
) {
    const auto result = netsentinel::diagnostics::run_wifi_sweet_spot_logger(config);
    if (!result.success) {
        std::cerr << "Wi-Fi sweet spot logger failed: " << result.message << "\n";
        return 3;
    }
    const auto csv = netsentinel::diagnostics::wifi_sweet_spot_csv(result);
    if (!output_path.empty()) {
        std::ofstream out{output_path, std::ios::trunc};
        if (!out.is_open()) {
            std::cerr << "Failed to write Wi-Fi sweet spot CSV: " << output_path << "\n";
            return 3;
        }
        out << csv;
    }
    std::cout << "WIFI_SWEETSPOT_OK\n";
    std::cout << "location=" << config.location_label << "\n";
    std::cout << "samples=" << result.samples.size() << "\n";
    std::cout << "summaries=" << result.summaries.size() << "\n";
    std::cout << "output=" << (output_path.empty() ? "(stdout)" : output_path) << "\n";
    std::cout << netsentinel::diagnostics::wifi_sweet_spot_markdown(result) << "\n";
    std::cout << "CSV_EXPORT_BEGIN\n" << csv << "CSV_EXPORT_END\n";
    return 0;
}

int print_ports_scan_command(
    bool use_mock,
    const std::vector<std::string>& targets,
    const std::string& preset,
    const std::vector<int>& custom_ports,
    std::size_t concurrency,
    bool banner
) {
    netsentinel::diagnostics::PortScanConfig config{};
    config.mock_mode = use_mock;
    config.targets = targets;
    config.concurrency = concurrency;
    config.banner = banner;
    const auto result = netsentinel::diagnostics::run_port_scan(config, preset, custom_ports);
    if (!result.success) {
        std::cerr << "Port scan failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "PORT_SCAN_OK\n";
    std::cout << "preset=" << result.preset << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "target_count=" << result.results.size() << "\n";
    std::cout << "open_port_count=" << result.open_port_count << "\n";
    for (std::size_t i = 0; i < result.results.size(); ++i) {
        const auto& item = result.results[i];
        std::cout << "target" << i << "=" << item.address << ",open_count=" << item.open_ports.size() << "\n";
        for (std::size_t p = 0; p < item.open_ports.size(); ++p) {
            std::cout << "open" << i << "_" << p << "=" << item.open_ports[p];
            if (banner && p < item.banners.size()) {
                std::cout << ",banner=" << item.banners[p];
            }
            std::cout << "\n";
        }
    }
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_ports_identify_command(
    bool use_mock,
    const std::vector<std::string>& targets,
    const std::string& preset,
    const std::vector<int>& custom_ports,
    std::size_t concurrency
) {
    netsentinel::diagnostics::PortScanConfig config{};
    config.mock_mode = use_mock;
    config.targets = targets;
    config.concurrency = concurrency;
    config.banner = true;
    const auto result = netsentinel::diagnostics::run_service_identification(config, preset, custom_ports);
    if (!result.success) {
        std::cerr << "Service identification failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "PORT_SERVICE_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "observation_count=" << result.observations.size() << "\n";
    for (std::size_t i = 0; i < result.observations.size(); ++i) {
        const auto& item = result.observations[i];
        std::cout << "observation" << i << "="
                  << item.target << ":" << item.port << ","
                  << "service=" << item.service << ","
                  << "protocol=" << item.protocol << ","
                  << "confidence=" << item.confidence_percent << ","
                  << "source=" << item.source << "\n";
        if (!item.detail.empty()) {
            std::cout << "observation" << i << "_detail=" << item.detail << "\n";
        }
    }
    for (std::size_t i = 0; i < result.device_hints.size(); ++i) {
        std::cout << "device_hint" << i << "=" << result.device_hints[i] << "\n";
    }
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_router_security_command(const std::string& gateway, bool use_mock) {
    netsentinel::diagnostics::RouterSecurityConfig config{};
    config.mock_mode = use_mock;
    if (!gateway.empty()) {
        config.gateway = gateway;
    }
    const auto result = netsentinel::diagnostics::run_router_security_check(config);
    if (!result.success) {
        std::cerr << "Router security check failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "ROUTER_SECURITY_OK\n";
    std::cout << "gateway=" << result.gateway << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "risk_score=" << result.risk_score << "\n";
    std::cout << "upnp_exposed=" << (result.upnp_exposed ? "true" : "false") << "\n";
    std::cout << "natpmp_exposed=" << (result.natpmp_exposed ? "true" : "false") << "\n";
    std::cout << "mapping_count=" << result.exposed_mappings.size() << "\n";
    for (std::size_t i = 0; i < result.exposed_mappings.size(); ++i) {
        const auto& mapping = result.exposed_mappings[i];
        std::cout << "mapping" << i << "="
                  << mapping.protocol << ":"
                  << mapping.external_port << "->" << mapping.internal_port
                  << ",service=" << mapping.service
                  << ",detail=" << mapping.detail << "\n";
    }
    std::cout << "finding_count=" << result.findings.size() << "\n";
    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const auto& finding = result.findings[i];
        std::cout << "finding" << i << "="
                  << finding.category << ","
                  << finding.severity << ","
                  << finding.title << ","
                  << finding.detail << ","
                  << finding.risk_score << "\n";
    }
    std::cout << "weak_protocol_count=" << result.weak_protocols.size() << "\n";
    for (std::size_t i = 0; i < result.weak_protocols.size(); ++i) {
        std::cout << "weak_protocol" << i << "=" << result.weak_protocols[i] << "\n";
    }
    std::cout << "tls_protocol_count=" << result.tls_protocols.size() << "\n";
    for (std::size_t i = 0; i < result.tls_protocols.size(); ++i) {
        std::cout << "tls_protocol" << i << "=" << result.tls_protocols[i] << "\n";
    }
    std::cout << "cve_count=" << result.cve_correlations.size() << "\n";
    for (std::size_t i = 0; i < result.cve_correlations.size(); ++i) {
        const auto& cve = result.cve_correlations[i];
        std::cout << "cve" << i << "="
                  << cve.component << ","
                  << cve.firmware << ","
                  << cve.cve << ","
                  << cve.description << "\n";
    }
    if (!result.firmware_version.empty()) {
        std::cout << "firmware=" << result.firmware_version << "\n";
    }
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_router_upnp_management_command(
    const std::string& gateway,
    bool use_mock,
    bool dry_run,
    bool confirm,
    const std::vector<int>& selected_ports
) {
    netsentinel::diagnostics::RouterUpnpNatpmpManagementConfig config{};
    config.mock_mode = use_mock;
    config.dry_run = dry_run;
    config.confirm = confirm;
    config.target_ports = selected_ports;
    if (!gateway.empty()) {
        config.gateway = gateway;
    }

    const auto result = netsentinel::diagnostics::run_router_upnp_natpmp_management(config);
    if (!result.success) {
        std::cerr << "UPnP/NAT-PMP management failed: " << result.message << "\n";
        if (!result.guidance.empty()) {
            for (std::size_t i = 0; i < result.guidance.size(); ++i) {
                std::cerr << "guidance" << i << "=" << result.guidance[i] << "\n";
            }
        }
        if (result.confirm_required) {
            std::cerr << "requirement=confirm-required\n";
        }
        return 3;
    }

    std::cout << "UPNP_NATPMP_MANAGEMENT_OK\n";
    std::cout << "gateway=" << result.gateway << "\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "dry_run=" << (result.dry_run ? "true" : "false") << "\n";
    std::cout << "confirm_required=" << (result.confirm_required ? "true" : "false") << "\n";
    std::cout << "safe_api_available=" << (result.safe_api_available ? "true" : "false") << "\n";
    std::cout << "discovered_count=" << result.discovered_mappings.size() << "\n";
    std::cout << "removable_count=" << result.removable_mappings.size() << "\n";
    for (std::size_t i = 0; i < result.discovered_mappings.size(); ++i) {
        const auto& mapping = result.discovered_mappings[i];
        std::cout << "discovered" << i << "="
                  << mapping.protocol << ":"
                  << mapping.external_port << "->" << mapping.internal_port
                  << ",service=" << mapping.service << "\n";
    }
    for (std::size_t i = 0; i < result.removable_mappings.size(); ++i) {
        const auto& mapping = result.removable_mappings[i];
        std::cout << "removable" << i << "="
                  << mapping.protocol << ":"
                  << mapping.external_port << "->" << mapping.internal_port
                  << ",service=" << mapping.service << "\n";
    }
    for (std::size_t i = 0; i < result.guidance.size(); ++i) {
        std::cout << "guidance" << i << "=" << result.guidance[i] << "\n";
    }
    for (std::size_t i = 0; i < result.applied_mappings.size(); ++i) {
        const auto& mapping = result.applied_mappings[i];
        std::cout << "applied" << i << "="
                  << mapping.protocol << ":"
                  << mapping.external_port << "->" << mapping.internal_port
                  << ",service=" << mapping.service << "\n";
    }
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_hidden_camera_detector_command(
    bool use_mock,
    const std::string& storage_db_path,
    bool include_mdns,
    bool include_ssdp,
    bool include_port_hints,
    bool privacy_mode = true,
    bool rental_mode = false,
    bool include_unknown_iot = true,
    const std::string& output_path = {}
) {
    netsentinel::diagnostics::HiddenCameraDetectorConfig config{};
    config.mock_mode = use_mock;
    config.storage_db_path = storage_db_path;
    config.include_mdns = include_mdns;
    config.include_ssdp = include_ssdp;
    config.include_port_hints = include_port_hints;
    config.privacy_mode = privacy_mode;
    config.rental_mode = rental_mode;
    config.include_unknown_iot = include_unknown_iot;

    const auto result = netsentinel::diagnostics::run_hidden_camera_detector(config);
    if (!result.success) {
        std::cerr << "Hidden camera detector failed: " << result.message << "\n";
        for (std::size_t i = 0; i < result.limitations.size(); ++i) {
            std::cerr << "limitation" << i << "=" << result.limitations[i] << "\n";
        }
        return 3;
    }

    std::cout << "HIDDEN_CAMERA_DETECTOR_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "privacy_mode=" << (privacy_mode ? "true" : "false") << "\n";
    std::cout << "rental_mode=" << (rental_mode ? "true" : "false") << "\n";
    std::cout << "storage_db=" << result.storage_db_path << "\n";
    std::cout << "finding_count=" << result.findings.size() << "\n";
    std::cout << "likely_camera_count=" << result.likely_camera_count << "\n";
    std::cout << "possible_camera_count=" << result.possible_camera_count << "\n";
    std::cout << "unknown_iot_count=" << result.unknown_iot_count << "\n";
    std::cout << "false_positive_warning_count=" << result.false_positive_warning_count << "\n";
    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const auto& finding = result.findings[i];
        std::cout << "finding" << i << "="
                  << finding.device_id << ","
                  << "classification=" << finding.classification << ","
                  << "category=" << finding.checklist_category << ","
                  << "confidence=" << finding.confidence_percent << ","
                  << "risk=" << finding.risk_score << ","
                  << "approved=" << (finding.user_approved ? "true" : "false") << ","
                  << "host=" << finding.hostname << ","
                  << "ip=" << finding.ip_address << ","
                  << "vendor=" << finding.vendor_hint << ","
                  << "type=" << finding.device_type << "\n";
        for (std::size_t p = 0; p < finding.exposed_ports.size(); ++p) {
            std::cout << "finding" << i << "_port" << p << "=" << finding.exposed_ports[p] << "\n";
        }
        for (std::size_t e = 0; e < finding.evidence.size(); ++e) {
            std::cout << "finding" << i << "_evidence" << e << "=" << finding.evidence[e] << "\n";
        }
        for (std::size_t w = 0; w < finding.false_positive_warnings.size(); ++w) {
            std::cout << "finding" << i << "_false_positive_warning" << w << "=" << finding.false_positive_warnings[w] << "\n";
        }
        for (std::size_t c = 0; c < finding.recommended_checks.size(); ++c) {
            std::cout << "finding" << i << "_recommended_check" << c << "=" << finding.recommended_checks[c] << "\n";
        }
    }
    for (std::size_t c = 0; c < result.checklist_report.size(); ++c) {
        std::cout << "checklist" << c << "=" << result.checklist_report[c] << "\n";
    }
    for (std::size_t i = 0; i < result.limitations.size(); ++i) {
        std::cout << "limitation" << i << "=" << result.limitations[i] << "\n";
    }
    if (!output_path.empty()) {
        std::ofstream output{output_path, std::ios::binary};
        if (!output.is_open()) {
            std::cerr << "Unable to write hidden camera report: " << output_path << "\n";
            return 3;
        }
        output << netsentinel::diagnostics::hidden_camera_detector_markdown(result);
        std::cout << "report=" << output_path << "\n";
    }
    std::cout << "message=" << result.message << "\n";
    return 0;
}

int print_device_lifecycle_command(
    bool use_mock,
    const std::string& storage_db_path,
    const std::string& catalog_path,
    const std::string& reference_date_utc,
    bool include_unknown,
    const std::string& output_path
) {
    netsentinel::diagnostics::DeviceLifecycleConfig config{};
    config.mock_mode = use_mock;
    config.storage_db_path = storage_db_path;
    config.catalog_path = catalog_path;
    config.reference_date_utc = reference_date_utc;
    config.include_unknown = include_unknown;

    const auto result = netsentinel::diagnostics::run_device_lifecycle_intelligence(config);
    if (!result.success) {
        std::cerr << "Device lifecycle intelligence failed: " << result.message << "\n";
        for (std::size_t i = 0; i < result.limitations.size(); ++i) {
            std::cerr << "limitation" << i << "=" << result.limitations[i] << "\n";
        }
        return 3;
    }

    std::cout << "DEVICE_LIFECYCLE_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "storage_db=" << result.storage_db_path << "\n";
    std::cout << "catalog=" << result.catalog_path << "\n";
    std::cout << "reference_date=" << result.reference_date_utc << "\n";
    std::cout << "device_count=" << result.device_count << "\n";
    std::cout << "finding_count=" << result.finding_count << "\n";
    std::cout << "likely_eol_count=" << result.likely_eol_count << "\n";
    std::cout << "outdated_count=" << result.outdated_count << "\n";
    std::cout << "monitor_count=" << result.monitor_count << "\n";
    std::cout << "unknown_count=" << result.unknown_count << "\n";
    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const auto& finding = result.findings[i];
        std::cout << "finding" << i << "="
                  << finding.device_id << ","
                  << "status=" << finding.lifecycle_status << ","
                  << "severity=" << finding.severity << ","
                  << "confidence=" << finding.confidence_percent << ","
                  << "host=" << finding.hostname << ","
                  << "ip=" << finding.ip_address << ","
                  << "vendor=" << finding.vendor_hint << ","
                  << "type=" << finding.device_type << ","
                  << "matched_vendor=" << finding.matched_vendor << ","
                  << "matched_model=" << finding.matched_model << ","
                  << "source=" << finding.source << "\n";
        for (std::size_t e = 0; e < finding.evidence.size(); ++e) {
            std::cout << "finding" << i << "_evidence" << e << "=" << finding.evidence[e] << "\n";
        }
        for (std::size_t r = 0; r < finding.recommendations.size(); ++r) {
            std::cout << "finding" << i << "_recommendation" << r << "=" << finding.recommendations[r] << "\n";
        }
    }
    for (std::size_t i = 0; i < result.limitations.size(); ++i) {
        std::cout << "limitation" << i << "=" << result.limitations[i] << "\n";
    }
    if (!output_path.empty()) {
        std::ofstream output{output_path, std::ios::binary};
        if (!output.is_open()) {
            std::cerr << "Unable to write lifecycle report: " << output_path << "\n";
            return 3;
        }
        output << netsentinel::diagnostics::device_lifecycle_markdown(result);
        std::cout << "report=" << output_path << "\n";
    }
    std::cout << "message=" << result.message << "\n";
    return 0;
}

int print_cve_cpe_correlation_command(
    bool use_mock,
    const std::string& storage_db_path,
    const std::string& catalog_path,
    bool include_possible_matches,
    const std::string& output_path
) {
    netsentinel::diagnostics::CveCpeCorrelationConfig config{};
    config.mock_mode = use_mock;
    config.storage_db_path = storage_db_path;
    config.catalog_path = catalog_path;
    config.include_possible_matches = include_possible_matches;

    const auto result = netsentinel::diagnostics::run_cve_cpe_correlation(config);
    if (!result.success) {
        std::cerr << "CPE/CVE correlation failed: " << result.message << "\n";
        for (std::size_t i = 0; i < result.limitations.size(); ++i) {
            std::cerr << "limitation" << i << "=" << result.limitations[i] << "\n";
        }
        return 3;
    }

    std::cout << "CVE_CPE_CORRELATION_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "storage_db=" << result.storage_db_path << "\n";
    std::cout << "catalog=" << result.catalog_path << "\n";
    std::cout << "device_count=" << result.device_count << "\n";
    std::cout << "match_count=" << result.match_count << "\n";
    std::cout << "possible_match_count=" << result.possible_match_count << "\n";
    std::cout << "strong_version_match_count=" << result.strong_version_match_count << "\n";
    for (std::size_t i = 0; i < result.matches.size(); ++i) {
        const auto& match = result.matches[i];
        std::cout << "match" << i << "="
                  << match.device_id << ","
                  << "cve=" << match.cve << ","
                  << "cpe=" << match.cpe << ","
                  << "label=" << match.match_label << ","
                  << "version_evidence=" << (match.version_evidence ? "true" : "false") << ","
                  << "confidence=" << match.confidence_percent << ","
                  << "severity=" << match.severity << ","
                  << "host=" << match.hostname << ","
                  << "ip=" << match.ip_address << ","
                  << "source=" << match.source << "\n";
        for (std::size_t e = 0; e < match.evidence.size(); ++e) {
            std::cout << "match" << i << "_evidence" << e << "=" << match.evidence[e] << "\n";
        }
        for (std::size_t r = 0; r < match.recommendations.size(); ++r) {
            std::cout << "match" << i << "_recommendation" << r << "=" << match.recommendations[r] << "\n";
        }
    }
    for (std::size_t i = 0; i < result.limitations.size(); ++i) {
        std::cout << "limitation" << i << "=" << result.limitations[i] << "\n";
    }
    if (!output_path.empty()) {
        std::ofstream output{output_path, std::ios::binary};
        if (!output.is_open()) {
            std::cerr << "Unable to write CPE/CVE report: " << output_path << "\n";
            return 3;
        }
        output << netsentinel::diagnostics::cve_cpe_correlation_markdown(result);
        std::cout << "report=" << output_path << "\n";
    }
    std::cout << "message=" << result.message << "\n";
    return 0;
}

std::vector<std::string> split_cli_csv_values(std::string_view text) {
    std::vector<std::string> values;
    std::string current;
    for (const char ch : text) {
        if (ch == ',') {
            if (!current.empty()) {
                values.push_back(current);
            }
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty()) {
        values.push_back(current);
    }
    return values;
}

int print_local_recognition_command(
    bool use_mock,
    const std::string& inventory_db_path,
    const std::string& recognition_db_path,
    const std::string& import_path,
    const std::string& export_path,
    const std::string& learn_device_id,
    const std::string& learn_hostname,
    const std::string& learn_vendor_hint,
    const std::string& learn_device_type,
    const std::vector<std::string>& learn_labels,
    const std::string& output_path
) {
    netsentinel::diagnostics::LocalRecognitionLearningConfig config{};
    config.mock_mode = use_mock;
    config.inventory_db_path = inventory_db_path;
    config.recognition_db_path = recognition_db_path;
    config.import_path = import_path;
    config.export_path = export_path;
    config.learn_device_id = learn_device_id;
    config.learn_hostname = learn_hostname;
    config.learn_vendor_hint = learn_vendor_hint;
    config.learn_device_type = learn_device_type;
    config.learn_labels = learn_labels;

    const auto result = netsentinel::diagnostics::run_local_recognition_learning(config);
    if (!result.success) {
        std::cerr << "Local recognition learning failed: " << result.message << "\n";
        for (std::size_t i = 0; i < result.limitations.size(); ++i) {
            std::cerr << "limitation" << i << "=" << result.limitations[i] << "\n";
        }
        return 3;
    }

    std::cout << "LOCAL_RECOGNITION_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "inventory_db=" << result.inventory_db_path << "\n";
    std::cout << "recognition_db=" << result.recognition_db_path << "\n";
    std::cout << "rules_loaded=" << result.rules_loaded << "\n";
    std::cout << "rules_imported=" << result.rules_imported << "\n";
    std::cout << "rules_written=" << result.rules_written << "\n";
    std::cout << "suggestions_count=" << result.suggestions_count << "\n";
    for (std::size_t i = 0; i < result.suggestions.size(); ++i) {
        const auto& suggestion = result.suggestions[i];
        std::cout << "suggestion" << i << "="
                  << suggestion.device_id << ","
                  << "host=" << suggestion.hostname << ","
                  << "vendor=" << suggestion.vendor_hint << ","
                  << "current_type=" << suggestion.current_device_type << ","
                  << "suggested_type=" << suggestion.suggested_device_type << ","
                  << "confidence=" << suggestion.confidence_percent << ","
                  << "source=" << suggestion.source << "\n";
        for (std::size_t e = 0; e < suggestion.evidence.size(); ++e) {
            std::cout << "suggestion" << i << "_evidence" << e << "=" << suggestion.evidence[e] << "\n";
        }
    }
    for (std::size_t i = 0; i < result.limitations.size(); ++i) {
        std::cout << "limitation" << i << "=" << result.limitations[i] << "\n";
    }
    if (!output_path.empty()) {
        std::ofstream output{output_path, std::ios::binary};
        if (!output.is_open()) {
            std::cerr << "Unable to write local recognition report: " << output_path << "\n";
            return 3;
        }
        output << netsentinel::diagnostics::local_recognition_learning_markdown(result);
        std::cout << "report=" << output_path << "\n";
    }
    std::cout << "message=" << result.message << "\n";
    return 0;
}

int print_generic_inventory_import_command(
    const std::string& input_path,
    const std::string& output_db_path,
    const std::string& format,
    bool apply,
    const std::string& output_path
) {
    netsentinel::diagnostics::GenericInventoryImportConfig config{};
    config.input_path = input_path;
    config.output_db_path = output_db_path;
    config.format = format;
    config.apply = apply;

    const auto result = netsentinel::diagnostics::run_generic_inventory_import(config);
    if (!result.success) {
        std::cerr << "Generic inventory import failed: " << result.message << "\n";
        for (const auto& warning : result.warnings) {
            std::cerr << "warning=" << warning << "\n";
        }
        return 3;
    }

    std::cout << "GENERIC_IMPORT_OK\n";
    std::cout << "input=" << result.input_path << "\n";
    std::cout << "output_db=" << result.output_db_path << "\n";
    std::cout << "format=" << result.format << "\n";
    std::cout << "preview_only=" << (result.preview_only ? "true" : "false") << "\n";
    std::cout << "rows_read=" << result.rows_read << "\n";
    std::cout << "rows_importable=" << result.rows_importable << "\n";
    std::cout << "rows_written=" << result.rows_written << "\n";
    for (std::size_t i = 0; i < result.devices.size(); ++i) {
        const auto& device = result.devices[i];
        std::cout << "device" << i << "="
                  << device.device_id << ","
                  << "host=" << device.hostname << ","
                  << "ip=" << device.ip_address << ","
                  << "mac=" << device.mac_address << ","
                  << "vendor=" << device.vendor_hint << ","
                  << "type=" << device.device_type << "\n";
    }
    for (std::size_t i = 0; i < result.warnings.size(); ++i) {
        std::cout << "warning" << i << "=" << result.warnings[i] << "\n";
    }
    for (std::size_t i = 0; i < result.limitations.size(); ++i) {
        std::cout << "limitation" << i << "=" << result.limitations[i] << "\n";
    }
    if (!output_path.empty()) {
        std::ofstream output{output_path, std::ios::binary};
        if (!output.is_open()) {
            std::cerr << "Unable to write generic import report: " << output_path << "\n";
            return 3;
        }
        output << netsentinel::diagnostics::generic_inventory_import_markdown(result);
        std::cout << "report=" << output_path << "\n";
    }
    std::cout << "message=" << result.message << "\n";
    return 0;
}

int print_security_health_command(
    bool use_mock,
    const std::string& storage_db_path,
    const std::string& gateway
) {
    netsentinel::diagnostics::SecurityHealthCheckConfig config{};
    config.mock_mode = use_mock;
    config.storage_db_path = storage_db_path;
    if (!gateway.empty()) {
        config.gateway = gateway;
    }

    const auto result = netsentinel::diagnostics::run_security_health_check(config);
    if (!result.success) {
        std::cerr << "Security health check failed: " << result.message << "\n";
        for (std::size_t i = 0; i < result.recommendations.size(); ++i) {
            std::cerr << "recommendation" << i << "=" << result.recommendations[i] << "\n";
        }
        return 3;
    }

    std::cout << "SECURITY_HEALTH_OK\n";
    std::cout << "mock=" << (use_mock ? "true" : "false") << "\n";
    std::cout << "score=" << result.score << "\n";
    std::cout << "grade=" << result.grade << "\n";
    std::cout << "component_count=" << result.components.size() << "\n";
    for (std::size_t i = 0; i < result.components.size(); ++i) {
        const auto& component = result.components[i];
        std::cout << "component" << i << "="
                  << component.name << ","
                  << "penalty=" << component.penalty << ","
                  << "max=" << component.max_penalty << ","
                  << "status=" << component.status << ","
                  << "detail=" << component.detail << "\n";
    }
    for (std::size_t i = 0; i < result.recommendations.size(); ++i) {
        std::cout << "recommendation" << i << "=" << result.recommendations[i] << "\n";
    }
    std::cout << "message=" << result.message << "\n";
    const auto history = netsentinel::diagnostics::read_diagnostics_history(5);
    std::cout << "history_count=" << history.size() << "\n";
    return 0;
}

int print_internet_control_command(const netsentinel::diagnostics::InternetControlConfig& config) {
    const auto result = netsentinel::diagnostics::run_internet_control(config);
    if (!result.success) {
        std::cerr << "Internet control failed: " << result.message << "\n";
        for (const auto& item : result.limitations) {
            std::cerr << "  limitation: " << item << "\n";
        }
        return 3;
    }

    std::cout << "INTERNET_CONTROL_OK\n";
    std::cout << "Backend: " << result.backend << "\n";
    std::cout << "Action: " << result.action << "\n";
    std::cout << "Dry-run: " << (result.dry_run ? "yes" : "no") << "\n";
    std::cout << "Applied: " << (result.applied ? "yes" : "no") << "\n";
    std::cout << "Message: " << result.message << "\n";
    std::cout << "Safety guards:\n";
    for (const auto& guard : result.safety_guards) {
        std::cout << "  - " << guard << "\n";
    }
    std::cout << "Steps:\n";
    for (const auto& step : result.steps) {
        std::cout << "  - [" << step.status << "] " << step.backend << " " << step.action << " " << step.target << ": " << step.detail << "\n";
    }
    if (!result.limitations.empty()) {
        std::cout << "Limitations:\n";
        for (const auto& item : result.limitations) {
            std::cout << "  - " << item << "\n";
        }
    }
    return 0;
}

int print_parental_downtime_command(const netsentinel::diagnostics::ParentalDowntimeConfig& config) {
    const auto result = netsentinel::diagnostics::run_parental_downtime_schedule(config);
    if (!result.success) {
        std::cerr << "Parental downtime failed: " << result.message << "\n";
        for (const auto& item : result.limitations) {
            std::cerr << "  limitation: " << item << "\n";
        }
        return 3;
    }

    std::cout << "PARENTAL_DOWNTIME_OK\n";
    std::cout << "Schedule: " << result.schedule_id << "\n";
    std::cout << "Downtime active: " << (result.downtime_active ? "yes" : "no") << "\n";
    std::cout << "Emergency disabled: " << (result.emergency_disabled ? "yes" : "no") << "\n";
    std::cout << "Advisory only: " << (result.advisory_only ? "yes" : "no") << "\n";
    std::cout << "Message: " << result.message << "\n";
    std::cout << "Decisions:\n";
    for (const auto& decision : result.decisions) {
        const auto& assignment = decision.assignment;
        std::cout << "  - action=" << decision.requested_action
                  << ", target=" << (assignment.target_ip.empty() ? assignment.device_id : assignment.target_ip)
                  << ", user=" << (assignment.user.empty() ? "(none)" : assignment.user)
                  << ", group=" << (assignment.group.empty() ? "(none)" : assignment.group)
                  << ", advisory=" << (decision.advisory_only ? "yes" : "no")
                  << ", backend=" << decision.control.backend
                  << ", detail=" << decision.detail << "\n";
    }
    std::cout << "Audit:\n";
    for (const auto& event : result.audit_events) {
        std::cout << "  - " << event.timestamp_utc
                  << " " << event.event
                  << " " << event.detail << "\n";
    }
    if (!result.limitations.empty()) {
        std::cout << "Limitations:\n";
        for (const auto& item : result.limitations) {
            std::cout << "  - " << item << "\n";
        }
    }
    return 0;
}

int print_usage_policy_command(const netsentinel::diagnostics::UsagePolicyConfig& config) {
    const auto result = netsentinel::diagnostics::evaluate_usage_policy(config);
    if (!result.success) {
        std::cerr << "Usage policy failed: " << result.message << "\n";
        for (const auto& item : result.limitations) {
            std::cerr << "  limitation: " << item << "\n";
        }
        return 3;
    }

    std::cout << "USAGE_POLICY_OK\n";
    std::cout << "Advisory only: " << (result.advisory_only ? "yes" : "no") << "\n";
    std::cout << "No enforcement: yes\n";
    std::cout << "Message: " << result.message << "\n";
    std::cout << "Decisions:\n";
    for (const auto& decision : result.decisions) {
        std::cout << "  - rule=" << decision.rule_id
                  << ", profile=" << decision.profile
                  << ", subject=" << decision.subject
                  << ", state=" << decision.state
                  << ", used_bytes=" << decision.used_bytes
                  << ", quota_bytes=" << decision.quota_bytes
                  << ", remaining_bytes=" << decision.remaining_bytes
                  << ", enforcement_requested=" << (decision.enforcement_requested ? "advisory-only" : "no")
                  << ", detail=" << decision.explanation << "\n";
    }
    if (!result.warnings.empty()) {
        std::cout << "Warnings:\n";
        for (const auto& item : result.warnings) {
            std::cout << "  - " << item << "\n";
        }
    }
    if (!result.limitations.empty()) {
        std::cout << "Limitations:\n";
        for (const auto& item : result.limitations) {
            std::cout << "  - " << item << "\n";
        }
    }
    return 0;
}

int print_autoblock_unknown_devices_command(const netsentinel::bandwidth::AutoblockPolicyConfig& config) {
    const auto result = netsentinel::bandwidth::run_unknown_device_autoblock_policy(config);
    if (!result.success) {
        std::cerr << "Autoblock unknown devices failed: " << result.user_message << "\n";
        std::cerr << netsentinel::bandwidth::autoblock_policy_markdown(result) << "\n";
        return 3;
    }
    std::cout << "AUTOBLOCK_UNKNOWN_DEVICES_OK\n";
    std::cout << "alert_only=" << (result.alert_only ? "yes" : "no") << "\n";
    std::cout << "enforcement_enabled=" << (result.enforcement_enabled ? "yes" : "no") << "\n";
    std::cout << "rollback_button_available=" << (result.rollback_button_available ? "yes" : "no") << "\n";
    std::cout << "alerts=" << result.alerts.size() << "\n";
    std::cout << "decisions=" << result.decisions.size() << "\n";
    std::cout << netsentinel::bandwidth::autoblock_policy_markdown(result) << "\n";
    return 0;
}

void seed_mock_presence_history(const netsentinel::storage::StorageConfig& storage) {
    using namespace netsentinel::storage;
    const auto _ = migrate_schema(storage);
    (void)_;
    DeviceInventoryRecord tablet{};
    tablet.device_id = "family-tablet";
    tablet.hostname = "family-tablet";
    tablet.ip_addresses = {"192.168.50.130"};
    tablet.mac_address = "02:50:00:00:00:30";
    tablet.device_type = "tablet";
    tablet.user_labels = {"tablet"};
    tablet.last_seen_utc = "2026-05-02T12:00:00Z";
    (void)upsert_inventory_record(tablet, storage);

    DeviceInventoryRecord guest{};
    guest.device_id = "guest-phone";
    guest.hostname = "guest-phone";
    guest.ip_addresses = {"192.168.50.223"};
    guest.mac_address = "02:50:00:00:00:23";
    guest.device_type = "phone";
    guest.user_labels = {"guest"};
    guest.last_seen_utc = "2026-05-02T11:30:00Z";
    (void)upsert_inventory_record(guest, storage);

    (void)append_timeline_record({.device_id = "family-tablet", .network_id = "home", .event_type = "join", .source = "mock-presence", .severity = 2, .old_value = "", .new_value = "joined", .at_utc = "2026-05-02T10:00:00Z"}, storage);
    (void)append_timeline_record({.device_id = "family-tablet", .network_id = "home", .event_type = "leave", .source = "mock-presence", .severity = 2, .old_value = "joined", .new_value = "left", .at_utc = "2026-05-02T10:30:00Z"}, storage);
    (void)append_timeline_record({.device_id = "family-tablet", .network_id = "home", .event_type = "join", .source = "mock-presence", .severity = 2, .old_value = "", .new_value = "joined", .at_utc = "2026-05-02T11:00:00Z"}, storage);
    (void)append_timeline_record({.device_id = "guest-phone", .network_id = "home", .event_type = "join", .source = "mock-presence", .severity = 2, .old_value = "", .new_value = "joined", .at_utc = "2026-05-02T09:00:00Z"}, storage);
    (void)append_timeline_record({.device_id = "guest-phone", .network_id = "home", .event_type = "leave", .source = "mock-presence", .severity = 2, .old_value = "joined", .new_value = "left", .at_utc = "2026-05-02T09:15:00Z"}, storage);
}

int print_presence_history_command(
    const netsentinel::storage::StorageConfig& storage,
    const netsentinel::storage::DevicePresenceHistoryConfig& presence_config,
    bool apply_retention,
    bool mock_mode
) {
    if (mock_mode) {
        seed_mock_presence_history(storage);
    }
    if (apply_retention) {
        const auto retention = netsentinel::storage::apply_device_presence_retention(presence_config, storage);
        if (!retention) {
            std::cerr << "Presence retention failed: " << retention.error().user_message << "\n";
            return 3;
        }
        std::cout << "PRESENCE_RETENTION_OK\n";
        std::cout << "cutoff_utc=" << retention.value().cutoff_utc << "\n";
        std::cout << "removed=" << retention.value().removed_count << "\n";
        std::cout << "message=" << retention.value().message << "\n";
    }
    const auto history = netsentinel::storage::build_device_presence_history(presence_config, storage);
    if (!history) {
        std::cerr << "Presence history failed: " << history.error().user_message << "\n";
        return 3;
    }
    std::cout << "PRESENCE_HISTORY_OK\n";
    std::cout << "records=" << history.value().size() << "\n";
    std::cout << "privacy=devices-only; person labels only when explicitly user-assigned\n";
    for (const auto& record : history.value()) {
        std::cout << "- device=" << record.device_id
                  << " network=" << record.network_id
                  << " label=" << record.device_label
                  << " first_seen=" << record.first_seen_utc
                  << " last_seen=" << record.last_seen_utc
                  << " dwell_seconds=" << record.dwell_seconds
                  << " present=" << (record.currently_present ? "yes" : "no")
                  << " user_assigned_person=" << (record.user_assigned_person ? "yes" : "no")
                  << "\n";
        std::cout << "  privacy_notice=" << record.privacy_notice << "\n";
    }
    return 0;
}

int print_presence_notify_command(const netsentinel::alerts::PresenceNotificationConfig& config) {
    const auto result = netsentinel::alerts::evaluate_presence_notifications(config);
    if (!result.success) {
        std::cerr << "Presence notifications failed: " << result.message << "\n";
        return 3;
    }
    std::cout << "PRESENCE_NOTIFY_OK\n";
    std::cout << "opt_in=" << (result.opt_in ? "yes" : "no") << "\n";
    std::cout << "notifications_sent=" << result.notifications_sent << "\n";
    std::cout << "message=" << result.message << "\n";
    for (const auto& decision : result.decisions) {
        std::cout << "- device=" << decision.device_id
                  << " profile=" << decision.profile
                  << " event=" << decision.event
                  << " matched_rule=" << (decision.matched_rule ? "yes" : "no")
                  << " quieted=" << (decision.quieted ? "yes" : "no")
                  << " sent=" << (decision.sent ? "yes" : "no")
                  << "\n";
        std::cout << "  message=" << decision.message << "\n";
        std::cout << "  privacy_notice=" << decision.privacy_notice << "\n";
        if (!decision.dispatch.message.empty()) {
            std::cout << "  dispatch=" << decision.dispatch.message << "\n";
        }
    }
    std::cout << "Limitations:\n";
    for (const auto& limitation : result.limitations) {
        std::cout << "- " << limitation << "\n";
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::cout << "NetSentinel11 v" << ns_core_version() << "\n";
    std::cout << "Platform layer: C17 + C++20\n";

    if (argc <= 1) {
        std::cout << "Run --help for usage.\n\n";
        netsentinel::app::print_safety_contract(std::cout);
        return 0;
    }

    std::string_view cmd{argv[1]};

    if (cmd == "interfaces") {
        bool use_mock = false;
        if (argc == 3) {
            const std::string_view mock_arg{argv[2]};
            if (mock_arg == "--mock") {
                use_mock = true;
            } else {
                std::cerr << "Unknown argument: " << mock_arg << "\n";
                print_usage();
                return 2;
            }
        } else if (argc > 3) {
            std::cerr << "Too many arguments for interfaces command.\n";
            print_usage();
            return 2;
        }
        return print_interfaces_command(use_mock);
    }

    if (cmd == "scope") {
        bool use_mock = false;
        bool confirm = false;
        bool allow_non_local = false;
        std::string custom_scope;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--confirm") {
                confirm = true;
                continue;
            }
            if (arg == "--allow-non-local") {
                allow_non_local = true;
                continue;
            }
            if (arg == "--custom") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --custom.\n";
                    print_usage();
                    return 2;
                }
                custom_scope = argv[++i];
                continue;
            }
            const auto custom_prefix = std::string_view{"--custom="};
            if (arg.rfind(custom_prefix, 0) == 0) {
                custom_scope = arg.substr(custom_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_scope_command(use_mock, custom_scope, confirm, allow_non_local);
    }

    if (cmd == "scan") {
        if (argc < 3) {
            std::cerr << "Missing scan subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "arp" && subcommand != "icmp" && subcommand != "tcp" && subcommand != "netbios" && subcommand != "mdns" && subcommand != "ssdp" && subcommand != "snmp" && subcommand != "session") {
            std::cerr << "Unknown scan subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }
        bool mock = false;
        std::string scope;
        std::size_t max_concurrency = 4;
        std::size_t max_qps = 16;
        long long jitter_min_ms = 0;
        long long jitter_max_ms = 0;
        int timeout_seconds = 10;
        std::string profile_name = "manual";
        std::size_t schedule_interval_minutes = 0;
        std::vector<std::string> enabled_probes;
        std::vector<int> tcp_port_hints;
        bool explicit_concurrency = false;
        bool explicit_qps = false;
        bool explicit_jitter_min = false;
        bool explicit_jitter_max = false;
        bool explicit_timeout = false;
        std::string snmp_target;
        std::string snmp_community;
        std::string snmp_version = "2c";
        ScanSessionProfilePreset profile;
        const auto apply_profile = [&](const ScanSessionProfilePreset& selected) {
            if (!explicit_concurrency) {
                max_concurrency = selected.max_concurrency;
            }
            if (!explicit_qps) {
                max_qps = selected.max_qps;
            }
            if (!explicit_jitter_min) {
                jitter_min_ms = selected.jitter_ms_min;
            }
            if (!explicit_jitter_max) {
                jitter_max_ms = selected.jitter_ms_max;
            }
            if (!explicit_timeout) {
                timeout_seconds = selected.timeout_seconds;
            }
            schedule_interval_minutes = selected.schedule_interval_minutes;
            enabled_probes = selected.enabled_probes;
            tcp_port_hints = selected.tcp_port_hints;
        };
        if (!resolve_scan_profile(profile_name, profile)) {
            std::cerr << "Invalid default profile: " << profile_name << "\n";
            return 2;
        }
        apply_profile(profile);
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                mock = true;
                continue;
            }
            if (arg == "--target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target.\n";
                    print_usage();
                    return 2;
                }
                snmp_target = argv[++i];
                continue;
            }
            if (arg == "--community") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --community.\n";
                    print_usage();
                    return 2;
                }
                snmp_community = argv[++i];
                continue;
            }
            if (arg == "--version") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --version.\n";
                    print_usage();
                    return 2;
                }
                snmp_version = argv[++i];
                continue;
            }
            const auto scope_prefix = std::string_view{"--scope="};
            if (arg.rfind(scope_prefix, 0) == 0) {
                scope = arg.substr(scope_prefix.size());
                continue;
            }
            if (arg == "--scope") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --scope.\n";
                    print_usage();
                    return 2;
                }
                scope = argv[++i];
                continue;
            }
            if (arg == "--concurrency") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --concurrency.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                if (!parse_positive_u64(value, max_concurrency)) {
                    std::cerr << "Invalid value for --concurrency: " << value << "\n";
                    print_usage();
                    return 2;
                }
                explicit_concurrency = true;
                continue;
            }
            if (arg == "--qps") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --qps.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                if (!parse_positive_u64(value, max_qps)) {
                    std::cerr << "Invalid value for --qps: " << value << "\n";
                    print_usage();
                    return 2;
                }
                explicit_qps = true;
                continue;
            }
            const auto concurrency_prefix = std::string_view{"--concurrency="};
            if (arg.rfind(concurrency_prefix, 0) == 0) {
                if (!parse_positive_u64(arg.substr(concurrency_prefix.size()), max_concurrency)) {
                    std::cerr << "Invalid value for --concurrency.\n";
                    print_usage();
                    return 2;
                }
                explicit_concurrency = true;
                continue;
            }
            const auto qps_prefix = std::string_view{"--qps="};
            if (arg.rfind(qps_prefix, 0) == 0) {
                if (!parse_positive_u64(arg.substr(qps_prefix.size()), max_qps)) {
                    std::cerr << "Invalid value for --qps.\n";
                    print_usage();
                    return 2;
                }
                explicit_qps = true;
                continue;
            }
            const auto jitter_min_prefix = std::string_view{"--jitter-min="};
            if (arg.rfind(jitter_min_prefix, 0) == 0) {
                if (!parse_non_negative_i64(arg.substr(jitter_min_prefix.size()), jitter_min_ms)) {
                    std::cerr << "Invalid value for --jitter-min.\n";
                    print_usage();
                    return 2;
                }
                explicit_jitter_min = true;
                continue;
            }
            const auto jitter_max_prefix = std::string_view{"--jitter-max="};
            if (arg.rfind(jitter_max_prefix, 0) == 0) {
                if (!parse_non_negative_i64(arg.substr(jitter_max_prefix.size()), jitter_max_ms)) {
                    std::cerr << "Invalid value for --jitter-max.\n";
                    print_usage();
                    return 2;
                }
                explicit_jitter_max = true;
                continue;
            }
            if (arg == "--jitter-min") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --jitter-min.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                if (!parse_non_negative_i64(value, jitter_min_ms)) {
                    std::cerr << "Invalid value for --jitter-min: " << value << "\n";
                    print_usage();
                    return 2;
                }
                explicit_jitter_min = true;
                continue;
            }
            if (arg == "--jitter-max") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --jitter-max.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                if (!parse_non_negative_i64(value, jitter_max_ms)) {
                    std::cerr << "Invalid value for --jitter-max: " << value << "\n";
                    print_usage();
                    return 2;
                }
                explicit_jitter_max = true;
                continue;
            }
            const auto profile_prefix = std::string_view{"--profile="};
            if (arg.rfind(profile_prefix, 0) == 0) {
                profile_name = arg.substr(profile_prefix.size());
                if (!resolve_scan_profile(profile_name, profile)) {
                    std::cerr << "Invalid profile: " << profile_name << "\n";
                    std::cerr << "Available profiles: manual, quick, standard, deep-safe, monitor\n";
                    print_usage();
                    return 2;
                }
                apply_profile(profile);
                continue;
            }
            if (arg == "--profile") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --profile.\n";
                    print_usage();
                    return 2;
                }
                profile_name = argv[++i];
                if (!resolve_scan_profile(profile_name, profile)) {
                    std::cerr << "Invalid profile: " << profile_name << "\n";
                    std::cerr << "Available profiles: manual, quick, standard, deep-safe, monitor\n";
                    print_usage();
                    return 2;
                }
                apply_profile(profile);
                continue;
            }
            if (arg == "--timeout") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timeout.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                std::size_t parsed_timeout = 0;
                if (!parse_positive_u64(value, parsed_timeout)) {
                    std::cerr << "Invalid value for --timeout: " << value << "\n";
                    print_usage();
                    return 2;
                }
                timeout_seconds = static_cast<int>(parsed_timeout);
                explicit_timeout = true;
                continue;
            }
            const auto timeout_prefix = std::string_view{"--timeout="};
            if (arg.rfind(timeout_prefix, 0) == 0) {
                std::size_t parsed_timeout = 0;
                if (!parse_positive_u64(arg.substr(timeout_prefix.size()), parsed_timeout)) {
                    std::cerr << "Invalid value for --timeout.\n";
                    print_usage();
                    return 2;
                }
                timeout_seconds = static_cast<int>(parsed_timeout);
                explicit_timeout = true;
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        apply_profile(profile);
        if (subcommand == "arp") {
            return print_arp_scan_command(scope, mock);
        }
        if (subcommand == "icmp") {
            return print_icmp_scan_command(scope, mock);
        }
        if (subcommand == "tcp") {
            return print_tcp_scan_command(scope, mock);
        }
        if (subcommand == "netbios") {
            return print_netbios_scan_command(scope, mock);
        }
        if (subcommand == "mdns") {
            return print_mdns_scan_command(mock);
        }
        if (subcommand == "ssdp") {
            return print_ssdp_scan_command(mock);
        }
        if (subcommand == "snmp") {
            if (snmp_target.empty()) {
                std::cerr << "Missing required argument: --target <ipv4>\n";
                print_usage();
                return 2;
            }
            if (snmp_community.empty()) {
                std::cerr << "Missing required argument: --community <string>\n";
                print_usage();
                return 2;
            }
            if (snmp_version != "1" && snmp_version != "v1" && snmp_version != "2c" && snmp_version != "v2c") {
                std::cerr << "Invalid SNMP version: " << snmp_version << "\n";
                print_usage();
                return 2;
            }
            return print_snmp_scan_command(snmp_target, snmp_community, snmp_version, mock);
        }
        return print_scan_session_command(
            scope,
            mock,
            max_concurrency,
            max_qps,
            jitter_min_ms,
            jitter_max_ms,
            timeout_seconds,
            profile_name,
            schedule_interval_minutes,
            enabled_probes,
            tcp_port_hints,
            snmp_target,
            snmp_community,
            snmp_version
        );
    }

    if (cmd == "monitor") {
        bool mock = false;
        std::string scope;
        std::size_t max_concurrency = 4;
        std::size_t max_qps = 16;
        long long jitter_min_ms = 0;
        long long jitter_max_ms = 0;
        int timeout_seconds = 10;
        std::string profile_name = "manual";
        std::size_t schedule_interval_minutes = 0;
        std::vector<std::string> enabled_probes;
        std::vector<int> tcp_port_hints;
        bool explicit_concurrency = false;
        bool explicit_qps = false;
        bool explicit_jitter_min = false;
        bool explicit_jitter_max = false;
        bool explicit_timeout = false;
        bool explicit_interval = false;
        std::size_t monitor_interval_minutes = 0;
        bool continuous = false;
        bool allow_metered = false;
        std::size_t max_runs = 1;
        bool explicit_runs = false;
        std::string snmp_target;
        std::string snmp_community;
        std::string snmp_version = "2c";
        ScanSessionProfilePreset profile;

        const auto apply_profile = [&](const ScanSessionProfilePreset& selected) {
            if (!explicit_concurrency) {
                max_concurrency = selected.max_concurrency;
            }
            if (!explicit_qps) {
                max_qps = selected.max_qps;
            }
            if (!explicit_jitter_min) {
                jitter_min_ms = selected.jitter_ms_min;
            }
            if (!explicit_jitter_max) {
                jitter_max_ms = selected.jitter_ms_max;
            }
            if (!explicit_timeout) {
                timeout_seconds = selected.timeout_seconds;
            }
            if (!explicit_interval) {
                monitor_interval_minutes = selected.schedule_interval_minutes;
            }
            enabled_probes = selected.enabled_probes;
            tcp_port_hints = selected.tcp_port_hints;
        };

        if (!resolve_scan_profile(profile_name, profile)) {
            std::cerr << "Invalid default profile: " << profile_name << "\n";
            return 2;
        }
        apply_profile(profile);

        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                mock = true;
                continue;
            }
            if (arg == "--scope") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --scope.\n";
                    print_usage();
                    return 2;
                }
                scope = argv[++i];
                continue;
            }
            const auto scope_prefix = std::string_view{"--scope="};
            if (arg.rfind(scope_prefix, 0) == 0) {
                scope = arg.substr(scope_prefix.size());
                continue;
            }
            if (arg == "--concurrency") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --concurrency.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                if (!parse_positive_u64(value, max_concurrency)) {
                    std::cerr << "Invalid value for --concurrency: " << value << "\n";
                    print_usage();
                    return 2;
                }
                explicit_concurrency = true;
                continue;
            }
            const auto concurrency_prefix = std::string_view{"--concurrency="};
            if (arg.rfind(concurrency_prefix, 0) == 0) {
                if (!parse_positive_u64(arg.substr(concurrency_prefix.size()), max_concurrency)) {
                    std::cerr << "Invalid value for --concurrency.\n";
                    print_usage();
                    return 2;
                }
                explicit_concurrency = true;
                continue;
            }
            if (arg == "--qps") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --qps.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                if (!parse_positive_u64(value, max_qps)) {
                    std::cerr << "Invalid value for --qps: " << value << "\n";
                    print_usage();
                    return 2;
                }
                explicit_qps = true;
                continue;
            }
            const auto qps_prefix = std::string_view{"--qps="};
            if (arg.rfind(qps_prefix, 0) == 0) {
                if (!parse_positive_u64(arg.substr(qps_prefix.size()), max_qps)) {
                    std::cerr << "Invalid value for --qps.\n";
                    print_usage();
                    return 2;
                }
                explicit_qps = true;
                continue;
            }
            const auto jitter_min_prefix = std::string_view{"--jitter-min="};
            if (arg.rfind(jitter_min_prefix, 0) == 0) {
                if (!parse_non_negative_i64(arg.substr(jitter_min_prefix.size()), jitter_min_ms)) {
                    std::cerr << "Invalid value for --jitter-min.\n";
                    print_usage();
                    return 2;
                }
                explicit_jitter_min = true;
                continue;
            }
            const auto jitter_max_prefix = std::string_view{"--jitter-max="};
            if (arg.rfind(jitter_max_prefix, 0) == 0) {
                if (!parse_non_negative_i64(arg.substr(jitter_max_prefix.size()), jitter_max_ms)) {
                    std::cerr << "Invalid value for --jitter-max.\n";
                    print_usage();
                    return 2;
                }
                explicit_jitter_max = true;
                continue;
            }
            if (arg == "--jitter-min") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --jitter-min.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                if (!parse_non_negative_i64(value, jitter_min_ms)) {
                    std::cerr << "Invalid value for --jitter-min: " << value << "\n";
                    print_usage();
                    return 2;
                }
                explicit_jitter_min = true;
                continue;
            }
            if (arg == "--jitter-max") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --jitter-max.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                if (!parse_non_negative_i64(value, jitter_max_ms)) {
                    std::cerr << "Invalid value for --jitter-max: " << value << "\n";
                    print_usage();
                    return 2;
                }
                explicit_jitter_max = true;
                continue;
            }
            const auto profile_prefix = std::string_view{"--profile="};
            if (arg.rfind(profile_prefix, 0) == 0) {
                profile_name = arg.substr(profile_prefix.size());
                if (!resolve_scan_profile(profile_name, profile)) {
                    std::cerr << "Invalid profile: " << profile_name << "\n";
                    std::cerr << "Available profiles: manual, quick, standard, deep-safe, monitor\n";
                    print_usage();
                    return 2;
                }
                apply_profile(profile);
                continue;
            }
            if (arg == "--profile") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --profile.\n";
                    print_usage();
                    return 2;
                }
                profile_name = argv[++i];
                if (!resolve_scan_profile(profile_name, profile)) {
                    std::cerr << "Invalid profile: " << profile_name << "\n";
                    std::cerr << "Available profiles: manual, quick, standard, deep-safe, monitor\n";
                    print_usage();
                    return 2;
                }
                apply_profile(profile);
                continue;
            }
            const auto interval_prefix = std::string_view{"--interval="};
            if (arg.rfind(interval_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(interval_prefix.size()), monitor_interval_minutes)) {
                    std::cerr << "Invalid value for --interval.\n";
                    print_usage();
                    return 2;
                }
                explicit_interval = true;
                continue;
            }
            if (arg == "--interval") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --interval.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], monitor_interval_minutes)) {
                    std::cerr << "Invalid value for --interval: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                explicit_interval = true;
                continue;
            }
            const auto max_runs_prefix = std::string_view{"--max-runs="};
            if (arg.rfind(max_runs_prefix, 0) == 0) {
                if (!parse_positive_u64(arg.substr(max_runs_prefix.size()), max_runs)) {
                    std::cerr << "Invalid value for --max-runs.\n";
                    print_usage();
                    return 2;
                }
                explicit_runs = true;
                continue;
            }
            if (arg == "--max-runs") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --max-runs.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_positive_u64(argv[++i], max_runs)) {
                    std::cerr << "Invalid value for --max-runs: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                explicit_runs = true;
                continue;
            }
            if (arg == "--continuous") {
                continuous = true;
                continue;
            }
            if (arg == "--allow-metered") {
                allow_metered = true;
                continue;
            }
            if (arg == "--timeout") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timeout.\n";
                    print_usage();
                    return 2;
                }
                const std::string_view value{argv[++i]};
                std::size_t parsed_timeout = 0;
                if (!parse_positive_u64(value, parsed_timeout)) {
                    std::cerr << "Invalid value for --timeout: " << value << "\n";
                    print_usage();
                    return 2;
                }
                timeout_seconds = static_cast<int>(parsed_timeout);
                explicit_timeout = true;
                continue;
            }
            const auto timeout_prefix = std::string_view{"--timeout="};
            if (arg.rfind(timeout_prefix, 0) == 0) {
                std::size_t parsed_timeout = 0;
                if (!parse_positive_u64(arg.substr(timeout_prefix.size()), parsed_timeout)) {
                    std::cerr << "Invalid value for --timeout.\n";
                    print_usage();
                    return 2;
                }
                timeout_seconds = static_cast<int>(parsed_timeout);
                explicit_timeout = true;
                continue;
            }
            if (arg == "--snmp-target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --snmp-target.\n";
                    print_usage();
                    return 2;
                }
                snmp_target = argv[++i];
                continue;
            }
            if (arg == "--snmp-community") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --snmp-community.\n";
                    print_usage();
                    return 2;
                }
                snmp_community = argv[++i];
                continue;
            }
            if (arg == "--snmp-version") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --snmp-version.\n";
                    print_usage();
                    return 2;
                }
                snmp_version = argv[++i];
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        if (continuous && explicit_runs && max_runs > 0) {
            std::cout << "Monitor option --continuous ignores --max-runs.\n";
        }
        if (!continuous && !explicit_runs) {
            max_runs = 1;
        }
        if (!continuous && max_runs == 0) {
            std::cerr << "Invalid monitoring request: max-runs must be greater than zero.\n";
            print_usage();
            return 2;
        }

        if (!explicit_interval) {
            monitor_interval_minutes = schedule_interval_minutes;
        }
        if (enabled_probes.empty()) {
            enabled_probes = {"arp", "icmp", "tcp", "netbios", "mdns", "ssdp"};
        }
        if (tcp_port_hints.empty()) {
            tcp_port_hints = {22, 80, 443, 445, 3389, 8080};
        }

        return print_monitor_command(
            scope,
            mock,
            max_concurrency,
            max_qps,
            jitter_min_ms,
            jitter_max_ms,
            timeout_seconds,
            profile_name,
            schedule_interval_minutes,
            enabled_probes,
            tcp_port_hints,
            max_runs,
            continuous,
            allow_metered,
            monitor_interval_minutes,
            snmp_target,
            snmp_community,
            snmp_version
        );
    }

    if (cmd == "tray") {
        if (argc < 3) {
            std::cerr << "Missing tray subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "status" && subcommand != "start" && subcommand != "stop" &&
            subcommand != "cleanup" && subcommand != "hardening") {
            std::cerr << "Unknown tray subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }

        if (subcommand == "status") {
            bool use_mock = false;
            for (int i = 3; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--mock") {
                    use_mock = true;
                    continue;
                }
                std::cerr << "Unknown argument: " << arg << "\n";
                print_usage();
                return 2;
            }
            return print_tray_status_command(use_mock);
        }

        if (subcommand == "stop") {
            bool use_mock = false;
            for (int i = 3; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--mock") {
                    use_mock = true;
                    continue;
                }
                std::cerr << "Unknown argument: " << arg << "\n";
                print_usage();
                return 2;
            }
            return print_tray_stop_command(use_mock);
        }

        if (subcommand == "cleanup") {
            bool use_mock = false;
            for (int i = 3; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--mock") {
                    use_mock = true;
                    continue;
                }
                std::cerr << "Unknown argument: " << arg << "\n";
                print_usage();
                return 2;
            }
            return print_tray_cleanup_command(use_mock);
        }

        if (subcommand == "hardening") {
            bool use_mock = false;
            std::string output_path;
            for (int i = 3; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--mock") {
                    use_mock = true;
                    continue;
                }
                const auto output_prefix = std::string_view{"--output="};
                if (arg.rfind(output_prefix, 0) == 0) {
                    output_path = arg.substr(output_prefix.size());
                    continue;
                }
                if (arg == "--output") {
                    if (i + 1 >= argc) {
                        std::cerr << "Missing value for --output.\n";
                        print_usage();
                        return 2;
                    }
                    output_path = argv[++i];
                    continue;
                }
                std::cerr << "Unknown argument: " << arg << "\n";
                print_usage();
                return 2;
            }
            return print_tray_hardening_command(use_mock, output_path);
        }

        bool use_mock = false;
        std::string profile_name = "monitor";
        std::size_t interval_minutes = 2;
        std::size_t restart_limit = 3;
        std::string scope = "192.168.1.0/24";
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            const auto profile_prefix = std::string_view{"--profile="};
            if (arg.rfind(profile_prefix, 0) == 0) {
                profile_name = arg.substr(profile_prefix.size());
                continue;
            }
            if (arg == "--profile") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --profile.\n";
                    print_usage();
                    return 2;
                }
                profile_name = argv[++i];
                continue;
            }
            const auto interval_prefix = std::string_view{"--interval="};
            if (arg.rfind(interval_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(interval_prefix.size()), interval_minutes)) {
                    std::cerr << "Invalid value for --interval.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--interval") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --interval.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], interval_minutes)) {
                    std::cerr << "Invalid value for --interval: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            const auto restart_prefix = std::string_view{"--restart-limit="};
            if (arg.rfind(restart_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(restart_prefix.size()), restart_limit)) {
                    std::cerr << "Invalid value for --restart-limit.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--restart-limit") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --restart-limit.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], restart_limit)) {
                    std::cerr << "Invalid value for --restart-limit: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            const auto scope_prefix = std::string_view{"--scope="};
            if (arg.rfind(scope_prefix, 0) == 0) {
                scope = arg.substr(scope_prefix.size());
                continue;
            }
            if (arg == "--scope") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --scope.\n";
                    print_usage();
                    return 2;
                }
                scope = argv[++i];
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_tray_start_command(use_mock, profile_name, interval_minutes, scope, restart_limit);
    }

    if (cmd == "alerts") {
        if (argc < 3) {
            std::cerr << "Missing alerts subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "test") {
            std::cerr << "Unknown alerts subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }
        bool use_mock = false;
        std::string kind;
        std::string target;
        std::string message;
        bool enable_toast = true;
        bool enable_email = false;
        bool enable_webhook = false;
        std::string email_from;
        std::string email_to;
        std::string webhook_url;
        std::size_t max_events_per_minute = 30;
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--toast") {
                enable_toast = true;
                continue;
            }
            if (arg == "--no-toast") {
                enable_toast = false;
                continue;
            }
            if (arg == "--email-from") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --email-from.\n";
                    print_usage();
                    return 2;
                }
                email_from = argv[++i];
                continue;
            }
            if (arg == "--email-to") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --email-to.\n";
                    print_usage();
                    return 2;
                }
                email_to = argv[++i];
                enable_email = true;
                continue;
            }
            if (arg == "--webhook-url") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --webhook-url.\n";
                    print_usage();
                    return 2;
                }
                webhook_url = argv[++i];
                enable_webhook = true;
                continue;
            }
            const auto max_rate_prefix = std::string_view{"--max-rate="};
            if (arg.rfind(max_rate_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(max_rate_prefix.size()), max_events_per_minute)) {
                    std::cerr << "Invalid value for --max-rate.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--max-rate") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --max-rate.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], max_events_per_minute)) {
                    std::cerr << "Invalid value for --max-rate: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--kind") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --kind.\n";
                    print_usage();
                    return 2;
                }
                kind = argv[++i];
                continue;
            }
            const auto kind_prefix = std::string_view{"--kind="};
            if (arg.rfind(kind_prefix, 0) == 0) {
                kind = arg.substr(kind_prefix.size());
                continue;
            }
            if (arg == "--target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target.\n";
                    print_usage();
                    return 2;
                }
                target = argv[++i];
                continue;
            }
            const auto target_prefix = std::string_view{"--target="};
            if (arg.rfind(target_prefix, 0) == 0) {
                target = arg.substr(target_prefix.size());
                continue;
            }
            if (arg == "--message") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --message.\n";
                    print_usage();
                    return 2;
                }
                message = argv[++i];
                continue;
            }
            const auto message_prefix = std::string_view{"--message="};
            if (arg.rfind(message_prefix, 0) == 0) {
                message = arg.substr(message_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        if (kind.empty()) {
            std::cerr << "Missing --kind argument.\n";
            print_usage();
            return 2;
        }
        if (message.empty()) {
            std::cerr << "Missing --message argument.\n";
            print_usage();
            return 2;
        }
        if (enable_email && email_to.empty() && email_from.empty()) {
            std::cerr << "Email channel enabled but no address provided. add --email-to.\n";
            print_usage();
            return 2;
        }
        if (max_events_per_minute == 0) {
            std::cerr << "max-rate must be greater than zero.\n";
            print_usage();
            return 2;
        }
        return print_alerts_test_command(
            use_mock,
            kind,
            message,
            target,
            enable_toast,
            enable_email,
            enable_webhook,
            email_from,
            email_to,
            webhook_url,
            max_events_per_minute
        );
    }

    if (cmd == "speed") {
        if (argc < 3) {
            std::cerr << "Missing speed subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "test") {
            std::cerr << "Unknown speed subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }

        bool use_mock = false;
        std::string endpoint = "https://example.com/100MB.bin";
        std::size_t samples = 4;
        std::size_t timeout_ms = 30000;
        std::size_t retention = 64;
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--endpoint") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --endpoint.\n";
                    print_usage();
                    return 2;
                }
                endpoint = argv[++i];
                continue;
            }
            const auto endpoint_prefix = std::string_view{"--endpoint="};
            if (arg.rfind(endpoint_prefix, 0) == 0) {
                endpoint = arg.substr(endpoint_prefix.size());
                continue;
            }
            if (arg == "--samples") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --samples.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], samples)) {
                    std::cerr << "Invalid value for --samples: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                if (samples == 0) {
                    std::cerr << "samples must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            const auto samples_prefix = std::string_view{"--samples="};
            if (arg.rfind(samples_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(samples_prefix.size()), samples)) {
                    std::cerr << "Invalid value for --samples.\n";
                    print_usage();
                    return 2;
                }
                if (samples == 0) {
                    std::cerr << "samples must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            if (arg == "--timeout-ms") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            const auto timeout_prefix = std::string_view{"--timeout-ms="};
            if (arg.rfind(timeout_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(timeout_prefix.size()), timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--retention") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --retention.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], retention)) {
                    std::cerr << "Invalid value for --retention: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                if (retention == 0) {
                    std::cerr << "retention must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            const auto retention_prefix = std::string_view{"--retention="};
            if (arg.rfind(retention_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(retention_prefix.size()), retention)) {
                    std::cerr << "Invalid value for --retention.\n";
                    print_usage();
                    return 2;
                }
                if (retention == 0) {
                    std::cerr << "retention must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_speed_test_command(use_mock, endpoint, samples, timeout_ms, retention);
    }

    if (cmd == "outage") {
        if (argc < 3) {
            std::cerr << "Missing outage subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "check") {
            std::cerr << "Unknown outage subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }
        bool use_mock = false;
        std::string gateway = "192.168.1.1";
        std::string dns = "8.8.8.8";
        std::string external = "https://example.com";
        std::string host = "192.168.1.10";
        std::size_t timeout_ms = 2000;
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--gateway") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --gateway.\n";
                    print_usage();
                    return 2;
                }
                gateway = argv[++i];
                continue;
            }
            const auto gateway_prefix = std::string_view{"--gateway="};
            if (arg.rfind(gateway_prefix, 0) == 0) {
                gateway = arg.substr(gateway_prefix.size());
                continue;
            }
            if (arg == "--dns") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --dns.\n";
                    print_usage();
                    return 2;
                }
                dns = argv[++i];
                continue;
            }
            const auto dns_prefix = std::string_view{"--dns="};
            if (arg.rfind(dns_prefix, 0) == 0) {
                dns = arg.substr(dns_prefix.size());
                continue;
            }
            if (arg == "--external") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --external.\n";
                    print_usage();
                    return 2;
                }
                external = argv[++i];
                continue;
            }
            const auto external_prefix = std::string_view{"--external="};
            if (arg.rfind(external_prefix, 0) == 0) {
                external = arg.substr(external_prefix.size());
                continue;
            }
            if (arg == "--host") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --host.\n";
                    print_usage();
                    return 2;
                }
                host = argv[++i];
                continue;
            }
            const auto host_prefix = std::string_view{"--host="};
            if (arg.rfind(host_prefix, 0) == 0) {
                host = arg.substr(host_prefix.size());
                continue;
            }
            if (arg == "--timeout-ms") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            const auto timeout_prefix = std::string_view{"--timeout-ms="};
            if (arg.rfind(timeout_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(timeout_prefix.size()), timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        if (timeout_ms == 0) {
            std::cerr << "timeout-ms must be greater than zero.\n";
            return 2;
        }
        return print_outage_check_command(
            use_mock,
            gateway,
            dns,
            external,
            host,
            timeout_ms
        );
    }

    if (cmd == "ping") {
        std::string target = "127.0.0.1";
        std::size_t count = 4;
        std::size_t timeout_ms = 1000;
        bool use_mock = false;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target.\n";
                    print_usage();
                    return 2;
                }
                target = argv[++i];
                continue;
            }
            const auto target_prefix = std::string_view{"--target="};
            if (arg.rfind(target_prefix, 0) == 0) {
                target = arg.substr(target_prefix.size());
                continue;
            }
            if (arg == "--count") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --count.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], count)) {
                    std::cerr << "Invalid value for --count: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                if (count == 0) {
                    std::cerr << "count must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            const auto count_prefix = std::string_view{"--count="};
            if (arg.rfind(count_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(count_prefix.size()), count)) {
                    std::cerr << "Invalid value for --count.\n";
                    print_usage();
                    return 2;
                }
                if (count == 0) {
                    std::cerr << "count must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            if (arg == "--timeout-ms") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            const auto timeout_prefix = std::string_view{"--timeout-ms="};
            if (arg.rfind(timeout_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(timeout_prefix.size()), timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        if (timeout_ms == 0) {
            std::cerr << "timeout-ms must be greater than zero.\n";
            return 2;
        }
        return print_ping_command(use_mock, target, count, timeout_ms);
    }

    if (cmd == "traceroute") {
        std::string destination = "127.0.0.1";
        std::size_t max_hops = 30;
        std::size_t timeout_ms = 1000;
        bool use_mock = false;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target.\n";
                    print_usage();
                    return 2;
                }
                destination = argv[++i];
                continue;
            }
            const auto target_prefix = std::string_view{"--target="};
            if (arg.rfind(target_prefix, 0) == 0) {
                destination = arg.substr(target_prefix.size());
                continue;
            }
            if (arg == "--max-hops") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --max-hops.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], max_hops)) {
                    std::cerr << "Invalid value for --max-hops: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                if (max_hops == 0) {
                    std::cerr << "max-hops must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            const auto max_hops_prefix = std::string_view{"--max-hops="};
            if (arg.rfind(max_hops_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(max_hops_prefix.size()), max_hops)) {
                    std::cerr << "Invalid value for --max-hops.\n";
                    print_usage();
                    return 2;
                }
                if (max_hops == 0) {
                    std::cerr << "max-hops must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            if (arg == "--timeout-ms") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            const auto timeout_prefix = std::string_view{"--timeout-ms="};
            if (arg.rfind(timeout_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(timeout_prefix.size()), timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        if (timeout_ms == 0) {
            std::cerr << "timeout-ms must be greater than zero.\n";
            return 2;
        }
        return print_traceroute_command(use_mock, destination, max_hops, timeout_ms);
    }

    if (cmd == "dns") {
        bool use_mock = false;
        bool reverse_lookup = false;
        std::string target = "localhost";
        std::string resolver = "8.8.8.8";
        std::size_t max_records = 10;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--reverse") {
                reverse_lookup = true;
                continue;
            }
            if (arg == "--target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target.\n";
                    print_usage();
                    return 2;
                }
                target = argv[++i];
                continue;
            }
            const auto target_prefix = std::string_view{"--target="};
            if (arg.rfind(target_prefix, 0) == 0) {
                target = arg.substr(target_prefix.size());
                continue;
            }
            if (arg == "--resolver") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --resolver.\n";
                    print_usage();
                    return 2;
                }
                resolver = argv[++i];
                continue;
            }
            const auto resolver_prefix = std::string_view{"--resolver="};
            if (arg.rfind(resolver_prefix, 0) == 0) {
                resolver = arg.substr(resolver_prefix.size());
                continue;
            }
            if (arg == "--max-records") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --max-records.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], max_records)) {
                    std::cerr << "Invalid value for --max-records: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                if (max_records == 0) {
                    std::cerr << "max-records must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            const auto max_records_prefix = std::string_view{"--max-records="};
            if (arg.rfind(max_records_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(max_records_prefix.size()), max_records)) {
                    std::cerr << "Invalid value for --max-records.\n";
                    print_usage();
                    return 2;
                }
                if (max_records == 0) {
                    std::cerr << "max-records must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_dns_command(use_mock, target, reverse_lookup, resolver, max_records);
    }

    if (cmd == "dns-benchmark") {
        bool use_mock = false;
        std::vector<std::string> resolvers;
        std::vector<std::string> queries;
        std::size_t samples = 3;
        std::size_t timeout_ms = 1000;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--resolver") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --resolver.\n";
                    print_usage();
                    return 2;
                }
                resolvers.push_back(argv[++i]);
                continue;
            }
            const auto resolver_prefix = std::string_view{"--resolver="};
            if (arg.rfind(resolver_prefix, 0) == 0) {
                resolvers.push_back(std::string{arg.substr(resolver_prefix.size())});
                continue;
            }
            if (arg == "--query") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --query.\n";
                    print_usage();
                    return 2;
                }
                queries.push_back(argv[++i]);
                continue;
            }
            const auto query_prefix = std::string_view{"--query="};
            if (arg.rfind(query_prefix, 0) == 0) {
                queries.push_back(std::string{arg.substr(query_prefix.size())});
                continue;
            }
            if (arg == "--samples") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --samples.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], samples)) {
                    std::cerr << "Invalid value for --samples: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                if (samples == 0) {
                    std::cerr << "samples must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            const auto samples_prefix = std::string_view{"--samples="};
            if (arg.rfind(samples_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(samples_prefix.size()), samples)) {
                    std::cerr << "Invalid value for --samples.\n";
                    print_usage();
                    return 2;
                }
                if (samples == 0) {
                    std::cerr << "samples must be greater than zero.\n";
                    return 2;
                }
                continue;
            }
            if (arg == "--timeout-ms") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms: " << argv[i] << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            const auto timeout_prefix = std::string_view{"--timeout-ms="};
            if (arg.rfind(timeout_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(timeout_prefix.size()), timeout_ms)) {
                    std::cerr << "Invalid value for --timeout-ms.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        if (timeout_ms == 0) {
            std::cerr << "timeout-ms must be greater than zero.\n";
            return 2;
        }
        return print_dns_benchmark_command(use_mock, resolvers, queries, samples, timeout_ms);
    }

    if (cmd == "dhcp") {
        bool use_mock = false;
        bool allow_multiple_check = false;
        std::string adapter_filter;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--allow-multiple-check") {
                allow_multiple_check = true;
                continue;
            }
            if (arg == "--adapter") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --adapter.\n";
                    print_usage();
                    return 2;
                }
                adapter_filter = argv[++i];
                continue;
            }
            const auto adapter_prefix = std::string_view{"--adapter="};
            if (arg.rfind(adapter_prefix, 0) == 0) {
                adapter_filter = arg.substr(adapter_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_dhcp_command(use_mock, adapter_filter, allow_multiple_check);
    }

    if (cmd == "wifi") {
        bool use_mock = false;
        bool include_hidden = false;
        bool analyze = false;
        bool environment = false;
        bool sweetspot = false;
        netsentinel::diagnostics::WifiSweetSpotConfig sweetspot_config{};
        std::string wifi_output_path;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "analyze") {
                analyze = true;
                continue;
            }
            if (arg == "environment") {
                environment = true;
                continue;
            }
            if (arg == "sweetspot") {
                sweetspot = true;
                continue;
            }
            if (arg == "--mock") {
                use_mock = true;
                sweetspot_config.mock_mode = true;
                continue;
            }
            if (arg == "--include-hidden") {
                include_hidden = true;
                sweetspot_config.include_hidden = true;
                continue;
            }
            if (arg == "--location") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --location.\n";
                    print_usage();
                    return 2;
                }
                sweetspot_config.location_label = argv[++i];
                continue;
            }
            const auto location_prefix = std::string_view{"--location="};
            if (arg.rfind(location_prefix, 0) == 0) {
                sweetspot_config.location_label = arg.substr(location_prefix.size());
                continue;
            }
            if (arg == "--timestamp") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timestamp.\n";
                    print_usage();
                    return 2;
                }
                sweetspot_config.timestamp_utc = argv[++i];
                continue;
            }
            const auto timestamp_prefix = std::string_view{"--timestamp="};
            if (arg.rfind(timestamp_prefix, 0) == 0) {
                sweetspot_config.timestamp_utc = arg.substr(timestamp_prefix.size());
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                wifi_output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                wifi_output_path = arg.substr(output_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        if (sweetspot) {
            return print_wifi_sweetspot_command(sweetspot_config, wifi_output_path);
        }
        if (environment) {
            return print_wifi_environment_command(use_mock, include_hidden, wifi_output_path);
        }
        if (analyze) {
            return print_wifi_analysis_command(use_mock, include_hidden);
        }
        return print_wifi_scan_command(use_mock, include_hidden);
    }

    if (cmd == "ports") {
        bool use_mock = false;
        bool banner = false;
        bool identify = false;
        std::size_t concurrency = 8;
        std::string preset = "top";
        std::vector<std::string> targets;
        std::vector<int> custom_ports;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "identify") {
                identify = true;
                continue;
            }
            if (arg == "--target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target.\n";
                    print_usage();
                    return 2;
                }
                targets.push_back(argv[++i]);
                continue;
            }
            if (arg == "--preset") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --preset.\n";
                    print_usage();
                    return 2;
                }
                preset = argv[++i];
                if (preset != "top" && preset != "router" && preset != "camera") {
                    std::cerr << "Unknown preset: " << preset << "\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--ports") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --ports.\n";
                    print_usage();
                    return 2;
                }
                custom_ports.clear();
                const auto raw_ports = split_csv_tokens(argv[++i]);
                for (const auto& raw_port : raw_ports) {
                    std::size_t value = 0;
                    if (!parse_non_negative_u64(raw_port, value) || value == 0 || value > 65535) {
                        std::cerr << "Invalid value in --ports.\n";
                        print_usage();
                        return 2;
                    }
                    custom_ports.push_back(static_cast<int>(value));
                }
                if (custom_ports.empty()) {
                    std::cerr << "Invalid --ports value.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--concurrency") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --concurrency.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], concurrency) || concurrency == 0) {
                    std::cerr << "Invalid value for --concurrency.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--banner") {
                banner = true;
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        if (identify) {
            return print_ports_identify_command(use_mock, targets, preset, custom_ports, concurrency);
        }
        return print_ports_scan_command(use_mock, targets, preset, custom_ports, concurrency, banner);
    }

    if (cmd == "security") {
        bool use_mock = false;
        bool is_router = false;
        bool is_upnp = false;
        bool is_camera = false;
        bool is_lifecycle = false;
        bool is_cve = false;
        bool is_recognize = false;
        bool is_import_inventory = false;
        bool is_health = false;
        bool is_control = false;
        bool is_downtime = false;
        bool is_quota = false;
        bool is_autoblock = false;
        bool quota_custom_rule = false;
        bool dry_run = true;
        bool confirm = false;
        bool include_mdns = true;
        bool include_ssdp = true;
        bool include_port_hints = true;
        bool privacy_mode = true;
        bool rental_mode = false;
        bool include_unknown_iot = true;
        bool lifecycle_include_unknown = true;
        bool cve_include_possible_matches = true;
        bool import_apply = false;
        std::vector<int> mapping_ports;
        std::string gateway;
        std::string output_path;
        std::string storage_db_path;
        std::string lifecycle_catalog_path = "data/device_lifecycle_catalog.json";
        std::string cve_catalog_path = "data/cve_cpe_catalog.json";
        std::string lifecycle_reference_date;
        std::string recognition_db_path = "data/local_recognition_rules.tsv";
        std::string recognition_import_path;
        std::string recognition_export_path;
        std::string learn_device_id;
        std::string learn_hostname;
        std::string learn_vendor_hint;
        std::string learn_device_type;
        std::vector<std::string> learn_labels;
        std::string import_input_path;
        std::string import_output_db_path;
        std::string import_format = "auto";
        netsentinel::diagnostics::InternetControlConfig control_config{};
        netsentinel::diagnostics::ParentalDowntimeConfig downtime_config{};
        netsentinel::diagnostics::ParentalDowntimeAssignment downtime_assignment{};
        netsentinel::diagnostics::UsagePolicyConfig quota_config{};
        netsentinel::diagnostics::UsagePolicyRule quota_rule{};
        netsentinel::bandwidth::AutoblockPolicyConfig autoblock_config{};
        std::string downtime_days = "all";
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "router") {
                is_router = true;
                continue;
            }
            if (arg == "upnp") {
                is_upnp = true;
                continue;
            }
            if (arg == "camera") {
                is_camera = true;
                continue;
            }
            if (arg == "lifecycle") {
                is_lifecycle = true;
                continue;
            }
            if (arg == "cve") {
                is_cve = true;
                continue;
            }
            if (arg == "recognize" || arg == "recognition") {
                is_recognize = true;
                continue;
            }
            if (arg == "import-inventory" || arg == "import") {
                is_import_inventory = true;
                continue;
            }
            if (arg == "health") {
                is_health = true;
                continue;
            }
            if (arg == "control") {
                is_control = true;
                continue;
            }
            if (arg == "downtime") {
                is_downtime = true;
                continue;
            }
            if (arg == "quota") {
                is_quota = true;
                continue;
            }
            if (arg == "autoblock") {
                is_autoblock = true;
                continue;
            }
            if (arg == "--dry-run") {
                dry_run = true;
                continue;
            }
            if (arg == "--apply") {
                dry_run = false;
                import_apply = true;
                continue;
            }
            if (arg == "--confirm") {
                confirm = true;
                continue;
            }
            if (arg == "--mock") {
                use_mock = true;
                continue;
            }
            if (arg == "--backend") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --backend.\n";
                    print_usage();
                    return 2;
                }
                control_config.backend = argv[++i];
                downtime_config.backend = control_config.backend;
                autoblock_config.safe_backend = control_config.backend;
                continue;
            }
            const auto backend_prefix = std::string_view{"--backend="};
            if (arg.rfind(backend_prefix, 0) == 0) {
                control_config.backend = arg.substr(backend_prefix.size());
                downtime_config.backend = control_config.backend;
                autoblock_config.safe_backend = control_config.backend;
                continue;
            }
            if (arg == "--alert-only") {
                autoblock_config.enforcement_enabled = false;
                continue;
            }
            if (arg == "--enforce") {
                autoblock_config.enforcement_enabled = true;
                continue;
            }
            if (arg == "--saved-rule") {
                autoblock_config.saved_rule = true;
                continue;
            }
            if (arg == "--endpoint") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --endpoint.\n";
                    print_usage();
                    return 2;
                }
                autoblock_config.endpoint = argv[++i];
                continue;
            }
            const auto autoblock_endpoint_prefix = std::string_view{"--endpoint="};
            if (arg.rfind(autoblock_endpoint_prefix, 0) == 0) {
                autoblock_config.endpoint = arg.substr(autoblock_endpoint_prefix.size());
                continue;
            }
            if (arg == "--credential-ref") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --credential-ref.\n";
                    print_usage();
                    return 2;
                }
                autoblock_config.credential_reference = argv[++i];
                continue;
            }
            const auto autoblock_credential_ref_prefix = std::string_view{"--credential-ref="};
            if (arg.rfind(autoblock_credential_ref_prefix, 0) == 0) {
                autoblock_config.credential_reference = arg.substr(autoblock_credential_ref_prefix.size());
                continue;
            }
            if (arg == "--rule-id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --rule-id.\n";
                    print_usage();
                    return 2;
                }
                autoblock_config.rule_id = argv[++i];
                continue;
            }
            const auto autoblock_rule_id_prefix = std::string_view{"--rule-id="};
            if (arg.rfind(autoblock_rule_id_prefix, 0) == 0) {
                autoblock_config.rule_id = arg.substr(autoblock_rule_id_prefix.size());
                continue;
            }
            if (arg == "--action") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --action.\n";
                    print_usage();
                    return 2;
                }
                control_config.action = argv[++i];
                continue;
            }
            const auto action_prefix = std::string_view{"--action="};
            if (arg.rfind(action_prefix, 0) == 0) {
                control_config.action = arg.substr(action_prefix.size());
                continue;
            }
            if (arg == "--target-ip") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target-ip.\n";
                    print_usage();
                    return 2;
                }
                control_config.target_ip = argv[++i];
                downtime_assignment.target_ip = control_config.target_ip;
                quota_rule.target_ip = control_config.target_ip;
                quota_custom_rule = true;
                continue;
            }
            const auto target_ip_prefix = std::string_view{"--target-ip="};
            if (arg.rfind(target_ip_prefix, 0) == 0) {
                control_config.target_ip = arg.substr(target_ip_prefix.size());
                downtime_assignment.target_ip = control_config.target_ip;
                quota_rule.target_ip = control_config.target_ip;
                quota_custom_rule = true;
                continue;
            }
            if (arg == "--device-id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --device-id.\n";
                    print_usage();
                    return 2;
                }
                control_config.device_id = argv[++i];
                downtime_assignment.device_id = control_config.device_id;
                quota_rule.device_id = control_config.device_id;
                quota_custom_rule = true;
                continue;
            }
            const auto device_id_prefix = std::string_view{"--device-id="};
            if (arg.rfind(device_id_prefix, 0) == 0) {
                control_config.device_id = arg.substr(device_id_prefix.size());
                downtime_assignment.device_id = control_config.device_id;
                quota_rule.device_id = control_config.device_id;
                quota_custom_rule = true;
                continue;
            }
            if (arg == "--profile") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --profile.\n";
                    print_usage();
                    return 2;
                }
                quota_rule.profile = argv[++i];
                quota_custom_rule = true;
                continue;
            }
            const auto quota_profile_prefix = std::string_view{"--profile="};
            if (arg.rfind(quota_profile_prefix, 0) == 0) {
                quota_rule.profile = arg.substr(quota_profile_prefix.size());
                quota_custom_rule = true;
                continue;
            }
            if (arg == "--method") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --method.\n";
                    print_usage();
                    return 2;
                }
                control_config.requested_method = argv[++i];
                continue;
            }
            const auto method_prefix = std::string_view{"--method="};
            if (arg.rfind(method_prefix, 0) == 0) {
                control_config.requested_method = arg.substr(method_prefix.size());
                continue;
            }
            if (arg == "--download-kbps" || arg == "--upload-kbps") {
                const bool is_download = arg == "--download-kbps";
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for " << arg << ".\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_limit = 0;
                if (!parse_non_negative_u64(argv[++i], parsed_limit) || parsed_limit > 100000000) {
                    std::cerr << "Invalid bandwidth limit value.\n";
                    print_usage();
                    return 2;
                }
                if (is_download) {
                    control_config.download_limit_kbps = static_cast<int>(parsed_limit);
                } else {
                    control_config.upload_limit_kbps = static_cast<int>(parsed_limit);
                }
                continue;
            }
            const auto download_prefix = std::string_view{"--download-kbps="};
            if (arg.rfind(download_prefix, 0) == 0) {
                std::size_t parsed_limit = 0;
                if (!parse_non_negative_u64(arg.substr(download_prefix.size()), parsed_limit) || parsed_limit > 100000000) {
                    std::cerr << "Invalid bandwidth limit value.\n";
                    print_usage();
                    return 2;
                }
                control_config.download_limit_kbps = static_cast<int>(parsed_limit);
                continue;
            }
            const auto upload_prefix = std::string_view{"--upload-kbps="};
            if (arg.rfind(upload_prefix, 0) == 0) {
                std::size_t parsed_limit = 0;
                if (!parse_non_negative_u64(arg.substr(upload_prefix.size()), parsed_limit) || parsed_limit > 100000000) {
                    std::cerr << "Invalid bandwidth limit value.\n";
                    print_usage();
                    return 2;
                }
                control_config.upload_limit_kbps = static_cast<int>(parsed_limit);
                continue;
            }
            if (arg == "--router-plugin") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --router-plugin.\n";
                    print_usage();
                    return 2;
                }
                control_config.router_plugin = argv[++i];
                continue;
            }
            const auto router_plugin_prefix = std::string_view{"--router-plugin="};
            if (arg.rfind(router_plugin_prefix, 0) == 0) {
                control_config.router_plugin = arg.substr(router_plugin_prefix.size());
                continue;
            }
            if (arg == "--router-user") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --router-user.\n";
                    print_usage();
                    return 2;
                }
                control_config.router_username = argv[++i];
                continue;
            }
            const auto router_user_prefix = std::string_view{"--router-user="};
            if (arg.rfind(router_user_prefix, 0) == 0) {
                control_config.router_username = arg.substr(router_user_prefix.size());
                continue;
            }
            if (arg == "--router-password") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --router-password.\n";
                    print_usage();
                    return 2;
                }
                control_config.router_password = argv[++i];
                continue;
            }
            const auto router_password_prefix = std::string_view{"--router-password="};
            if (arg.rfind(router_password_prefix, 0) == 0) {
                control_config.router_password = arg.substr(router_password_prefix.size());
                continue;
            }
            if (arg == "--schedule") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --schedule.\n";
                    print_usage();
                    return 2;
                }
                downtime_config.schedule_id = argv[++i];
                continue;
            }
            const auto schedule_prefix = std::string_view{"--schedule="};
            if (arg.rfind(schedule_prefix, 0) == 0) {
                downtime_config.schedule_id = arg.substr(schedule_prefix.size());
                continue;
            }
            if (arg == "--days") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --days.\n";
                    print_usage();
                    return 2;
                }
                downtime_days = argv[++i];
                quota_rule.schedule_days = downtime_days;
                quota_custom_rule = true;
                continue;
            }
            const auto days_prefix = std::string_view{"--days="};
            if (arg.rfind(days_prefix, 0) == 0) {
                downtime_days = arg.substr(days_prefix.size());
                quota_rule.schedule_days = downtime_days;
                quota_custom_rule = true;
                continue;
            }
            if (arg == "--window") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --window.\n";
                    print_usage();
                    return 2;
                }
                netsentinel::diagnostics::ParentalDowntimeWindow window{};
                if (!parse_downtime_window_arg(argv[++i], downtime_days, window)) {
                    std::cerr << "Invalid value for --window. Use HH:MM-HH:MM.\n";
                    print_usage();
                    return 2;
                }
                downtime_config.windows.push_back(window);
                quota_rule.schedule_days = window.days;
                quota_rule.schedule_window = window.start_local + "-" + window.end_local;
                quota_custom_rule = true;
                continue;
            }
            const auto window_prefix = std::string_view{"--window="};
            if (arg.rfind(window_prefix, 0) == 0) {
                netsentinel::diagnostics::ParentalDowntimeWindow window{};
                if (!parse_downtime_window_arg(arg.substr(window_prefix.size()), downtime_days, window)) {
                    std::cerr << "Invalid value for --window. Use HH:MM-HH:MM.\n";
                    print_usage();
                    return 2;
                }
                downtime_config.windows.push_back(window);
                quota_rule.schedule_days = window.days;
                quota_rule.schedule_window = window.start_local + "-" + window.end_local;
                quota_custom_rule = true;
                continue;
            }
            if (arg == "--now") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --now.\n";
                    print_usage();
                    return 2;
                }
                downtime_config.now_local = argv[++i];
                quota_config.now_local = downtime_config.now_local;
                continue;
            }
            const auto now_prefix = std::string_view{"--now="};
            if (arg.rfind(now_prefix, 0) == 0) {
                downtime_config.now_local = arg.substr(now_prefix.size());
                quota_config.now_local = downtime_config.now_local;
                continue;
            }
            if (arg == "--user") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --user.\n";
                    print_usage();
                    return 2;
                }
                downtime_assignment.user = argv[++i];
                continue;
            }
            const auto user_prefix = std::string_view{"--user="};
            if (arg.rfind(user_prefix, 0) == 0) {
                downtime_assignment.user = arg.substr(user_prefix.size());
                continue;
            }
            if (arg == "--group") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --group.\n";
                    print_usage();
                    return 2;
                }
                downtime_assignment.group = argv[++i];
                quota_rule.group = downtime_assignment.group;
                quota_custom_rule = true;
                continue;
            }
            const auto group_prefix = std::string_view{"--group="};
            if (arg.rfind(group_prefix, 0) == 0) {
                downtime_assignment.group = arg.substr(group_prefix.size());
                quota_rule.group = downtime_assignment.group;
                quota_custom_rule = true;
                continue;
            }
            if (arg == "--quota-mb" || arg == "--warning-mb") {
                const bool is_quota_limit = arg == "--quota-mb";
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for " << arg << ".\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_mb = 0;
                if (!parse_positive_u64(argv[++i], parsed_mb) || parsed_mb > 10485760ULL) {
                    std::cerr << "Invalid quota value.\n";
                    print_usage();
                    return 2;
                }
                const auto bytes = static_cast<std::uint64_t>(parsed_mb) * 1024ULL * 1024ULL;
                if (is_quota_limit) {
                    quota_rule.quota_bytes = bytes;
                } else {
                    quota_rule.warning_threshold_bytes = bytes;
                }
                quota_custom_rule = true;
                continue;
            }
            const auto quota_mb_prefix = std::string_view{"--quota-mb="};
            if (arg.rfind(quota_mb_prefix, 0) == 0) {
                std::size_t parsed_mb = 0;
                if (!parse_positive_u64(arg.substr(quota_mb_prefix.size()), parsed_mb) || parsed_mb > 10485760ULL) {
                    std::cerr << "Invalid quota value.\n";
                    print_usage();
                    return 2;
                }
                quota_rule.quota_bytes = static_cast<std::uint64_t>(parsed_mb) * 1024ULL * 1024ULL;
                quota_custom_rule = true;
                continue;
            }
            const auto warning_mb_prefix = std::string_view{"--warning-mb="};
            if (arg.rfind(warning_mb_prefix, 0) == 0) {
                std::size_t parsed_mb = 0;
                if (!parse_positive_u64(arg.substr(warning_mb_prefix.size()), parsed_mb) || parsed_mb > 10485760ULL) {
                    std::cerr << "Invalid quota value.\n";
                    print_usage();
                    return 2;
                }
                quota_rule.warning_threshold_bytes = static_cast<std::uint64_t>(parsed_mb) * 1024ULL * 1024ULL;
                quota_custom_rule = true;
                continue;
            }
            if (arg == "--label") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --label.\n";
                    print_usage();
                    return 2;
                }
                downtime_assignment.label = argv[++i];
                continue;
            }
            const auto label_prefix = std::string_view{"--label="};
            if (arg.rfind(label_prefix, 0) == 0) {
                downtime_assignment.label = arg.substr(label_prefix.size());
                continue;
            }
            if (arg == "--emergency-disable") {
                downtime_config.emergency_disable = true;
                continue;
            }
            if (arg == "--no-mdns") {
                include_mdns = false;
                continue;
            }
            if (arg == "--no-ssdp") {
                include_ssdp = false;
                continue;
            }
            if (arg == "--no-port-hints") {
                include_port_hints = false;
                continue;
            }
            if (arg == "--privacy-mode") {
                privacy_mode = true;
                continue;
            }
            if (arg == "--rental" || arg == "--rental-mode") {
                rental_mode = true;
                continue;
            }
            if (arg == "--include-unknown-iot") {
                include_unknown_iot = true;
                continue;
            }
            if (arg == "--no-unknown-iot") {
                include_unknown_iot = false;
                continue;
            }
            if (arg == "--no-unknown") {
                lifecycle_include_unknown = false;
                continue;
            }
            if (arg == "--no-possible") {
                cve_include_possible_matches = false;
                continue;
            }
            if (arg == "--catalog") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --catalog.\n";
                    print_usage();
                    return 2;
                }
                lifecycle_catalog_path = argv[++i];
                cve_catalog_path = lifecycle_catalog_path;
                continue;
            }
            const auto catalog_prefix = std::string_view{"--catalog="};
            if (arg.rfind(catalog_prefix, 0) == 0) {
                lifecycle_catalog_path = arg.substr(catalog_prefix.size());
                cve_catalog_path = lifecycle_catalog_path;
                continue;
            }
            if (arg == "--reference-date") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --reference-date.\n";
                    print_usage();
                    return 2;
                }
                lifecycle_reference_date = argv[++i];
                continue;
            }
            const auto reference_date_prefix = std::string_view{"--reference-date="};
            if (arg.rfind(reference_date_prefix, 0) == 0) {
                lifecycle_reference_date = arg.substr(reference_date_prefix.size());
                continue;
            }
            if (arg == "--recognition-db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --recognition-db.\n";
                    print_usage();
                    return 2;
                }
                recognition_db_path = argv[++i];
                continue;
            }
            const auto recognition_db_prefix = std::string_view{"--recognition-db="};
            if (arg.rfind(recognition_db_prefix, 0) == 0) {
                recognition_db_path = arg.substr(recognition_db_prefix.size());
                continue;
            }
            if (arg == "--learn-device-id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --learn-device-id.\n";
                    print_usage();
                    return 2;
                }
                learn_device_id = argv[++i];
                continue;
            }
            const auto learn_device_prefix = std::string_view{"--learn-device-id="};
            if (arg.rfind(learn_device_prefix, 0) == 0) {
                learn_device_id = arg.substr(learn_device_prefix.size());
                continue;
            }
            if (arg == "--learn-hostname") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --learn-hostname.\n";
                    print_usage();
                    return 2;
                }
                learn_hostname = argv[++i];
                continue;
            }
            const auto learn_hostname_prefix = std::string_view{"--learn-hostname="};
            if (arg.rfind(learn_hostname_prefix, 0) == 0) {
                learn_hostname = arg.substr(learn_hostname_prefix.size());
                continue;
            }
            if (arg == "--learn-vendor") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --learn-vendor.\n";
                    print_usage();
                    return 2;
                }
                learn_vendor_hint = argv[++i];
                continue;
            }
            const auto learn_vendor_prefix = std::string_view{"--learn-vendor="};
            if (arg.rfind(learn_vendor_prefix, 0) == 0) {
                learn_vendor_hint = arg.substr(learn_vendor_prefix.size());
                continue;
            }
            if (arg == "--learn-type") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --learn-type.\n";
                    print_usage();
                    return 2;
                }
                learn_device_type = argv[++i];
                continue;
            }
            const auto learn_type_prefix = std::string_view{"--learn-type="};
            if (arg.rfind(learn_type_prefix, 0) == 0) {
                learn_device_type = arg.substr(learn_type_prefix.size());
                continue;
            }
            if (arg == "--learn-labels") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --learn-labels.\n";
                    print_usage();
                    return 2;
                }
                learn_labels = split_cli_csv_values(argv[++i]);
                continue;
            }
            const auto learn_labels_prefix = std::string_view{"--learn-labels="};
            if (arg.rfind(learn_labels_prefix, 0) == 0) {
                learn_labels = split_cli_csv_values(arg.substr(learn_labels_prefix.size()));
                continue;
            }
            if (arg == "--import") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --import.\n";
                    print_usage();
                    return 2;
                }
                recognition_import_path = argv[++i];
                continue;
            }
            const auto import_prefix = std::string_view{"--import="};
            if (arg.rfind(import_prefix, 0) == 0) {
                recognition_import_path = arg.substr(import_prefix.size());
                continue;
            }
            if (arg == "--export") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --export.\n";
                    print_usage();
                    return 2;
                }
                recognition_export_path = argv[++i];
                continue;
            }
            const auto export_prefix = std::string_view{"--export="};
            if (arg.rfind(export_prefix, 0) == 0) {
                recognition_export_path = arg.substr(export_prefix.size());
                continue;
            }
            if (arg == "--input") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --input.\n";
                    print_usage();
                    return 2;
                }
                import_input_path = argv[++i];
                continue;
            }
            const auto input_prefix = std::string_view{"--input="};
            if (arg.rfind(input_prefix, 0) == 0) {
                import_input_path = arg.substr(input_prefix.size());
                continue;
            }
            if (arg == "--output-db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output-db.\n";
                    print_usage();
                    return 2;
                }
                import_output_db_path = argv[++i];
                continue;
            }
            const auto output_db_prefix = std::string_view{"--output-db="};
            if (arg.rfind(output_db_prefix, 0) == 0) {
                import_output_db_path = arg.substr(output_db_prefix.size());
                continue;
            }
            if (arg == "--format") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --format.\n";
                    print_usage();
                    return 2;
                }
                import_format = argv[++i];
                continue;
            }
            const auto format_prefix = std::string_view{"--format="};
            if (arg.rfind(format_prefix, 0) == 0) {
                import_format = arg.substr(format_prefix.size());
                continue;
            }
            if (arg == "--port") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --port.\n";
                    print_usage();
                    return 2;
                }
                std::size_t raw_port = 0;
                if (!parse_non_negative_u64(argv[++i], raw_port) || raw_port == 0 || raw_port > 65535) {
                    std::cerr << "Invalid value for --port.\n";
                    print_usage();
                    return 2;
                }
                mapping_ports.push_back(static_cast<int>(raw_port));
                continue;
            }
            if (arg == "--gateway") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --gateway.\n";
                    print_usage();
                    return 2;
                }
                gateway = argv[++i];
                continue;
            }
            const auto gateway_prefix = std::string_view{"--gateway="};
            if (arg.rfind(gateway_prefix, 0) == 0) {
                gateway = arg.substr(gateway_prefix.size());
                continue;
            }
            if (arg == "--db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --db.\n";
                    print_usage();
                    return 2;
                }
                storage_db_path = argv[++i];
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                output_path = argv[++i];
                continue;
            }
            const auto db_prefix = std::string_view{"--db="};
            if (arg.rfind(db_prefix, 0) == 0) {
                storage_db_path = arg.substr(db_prefix.size());
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                output_path = arg.substr(output_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        const int selected_subcommands = (is_router ? 1 : 0) + (is_upnp ? 1 : 0) + (is_camera ? 1 : 0) + (is_lifecycle ? 1 : 0) + (is_cve ? 1 : 0) + (is_recognize ? 1 : 0) + (is_import_inventory ? 1 : 0) + (is_health ? 1 : 0) + (is_control ? 1 : 0) + (is_downtime ? 1 : 0) + (is_quota ? 1 : 0) + (is_autoblock ? 1 : 0);
        if (selected_subcommands > 1) {
            std::cerr << "Security subcommands are mutually exclusive.\n";
            print_usage();
            return 2;
        }
        if (selected_subcommands == 0) {
            std::cerr << "Unknown security subcommand.\n";
            print_usage();
            return 2;
        }
        if (is_router) {
            return print_router_security_command(gateway, use_mock);
        }
        if (is_camera) {
            return print_hidden_camera_detector_command(use_mock, storage_db_path, include_mdns, include_ssdp, include_port_hints, privacy_mode, rental_mode, include_unknown_iot, output_path);
        }
        if (is_lifecycle) {
            return print_device_lifecycle_command(use_mock, storage_db_path, lifecycle_catalog_path, lifecycle_reference_date, lifecycle_include_unknown, output_path);
        }
        if (is_cve) {
            return print_cve_cpe_correlation_command(use_mock, storage_db_path, cve_catalog_path, cve_include_possible_matches, output_path);
        }
        if (is_recognize) {
            return print_local_recognition_command(use_mock, storage_db_path, recognition_db_path, recognition_import_path, recognition_export_path, learn_device_id, learn_hostname, learn_vendor_hint, learn_device_type, learn_labels, output_path);
        }
        if (is_import_inventory) {
            return print_generic_inventory_import_command(import_input_path, import_output_db_path, import_format, import_apply, output_path);
        }
        if (is_health) {
            return print_security_health_command(use_mock, storage_db_path, gateway);
        }
        if (is_control) {
            control_config.mock_mode = use_mock;
            control_config.dry_run = dry_run;
            control_config.confirm = confirm;
            return print_internet_control_command(control_config);
        }
        if (is_downtime) {
            if (downtime_config.windows.empty()) {
                netsentinel::diagnostics::ParentalDowntimeWindow window{};
                window.days = downtime_days;
                downtime_config.windows.push_back(window);
            }
            if (downtime_assignment.target_ip.empty() &&
                downtime_assignment.device_id.empty() &&
                downtime_assignment.user.empty() &&
                downtime_assignment.group.empty() &&
                downtime_assignment.label.empty()) {
                std::cerr << "Missing downtime assignment. Provide --target-ip, --device-id, --user, --group, or --label.\n";
                print_usage();
                return 2;
            }
            downtime_config.mock_mode = use_mock;
            downtime_config.dry_run = dry_run;
            downtime_config.confirm = confirm;
            if (downtime_config.backend.empty()) {
                downtime_config.backend = "advisory";
            }
            downtime_config.assignments.push_back(downtime_assignment);
            return print_parental_downtime_command(downtime_config);
        }
        if (is_quota) {
            quota_config.mock_mode = use_mock;
            if (quota_custom_rule) {
                if (quota_rule.rule_id.empty()) {
                    quota_rule.rule_id = "cli-quota";
                }
                quota_config.rules.push_back(quota_rule);
            }
            return print_usage_policy_command(quota_config);
        }
        if (is_autoblock) {
            autoblock_config.mock_mode = use_mock;
            autoblock_config.dry_run = dry_run;
            autoblock_config.confirmed = confirm;
            return print_autoblock_unknown_devices_command(autoblock_config);
        }
        return print_router_upnp_management_command(gateway, use_mock, dry_run, confirm, mapping_ports);
    }

    if (cmd == "inventory") {
        if (argc < 3) {
            std::cerr << "Missing inventory subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand == "list") {
            bool include_hidden = false;
            if (argc > 3 && std::string_view{argv[3]} != "--all") {
                std::cerr << "Unknown argument: " << argv[3] << "\n";
                print_usage();
                return 2;
            }
            if (argc == 4) {
                include_hidden = true;
            }
            if (argc > 4) {
                std::cerr << "Too many arguments for inventory list.\n";
                print_usage();
                return 2;
            }
            return print_inventory_list_command(include_hidden);
        }
        if (subcommand == "show") {
            if (argc != 4) {
                std::cerr << "Missing device-id.\n";
                print_usage();
                return 2;
            }
            return print_inventory_show_command(argv[3]);
        }
        if (subcommand == "edit") {
            if (argc < 4) {
                std::cerr << "Missing device-id.\n";
                print_usage();
                return 2;
            }
            std::string device_type;
            std::string labels_csv;
            int importance = 0;
            bool set_importance = false;
            bool hide_value_set = false;
            bool hide_value = false;
            bool stale_value_set = false;
            bool stale_value = false;

            for (int i = 4; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--type") {
                    if (i + 1 >= argc) {
                        std::cerr << "Missing value for --type.\n";
                        print_usage();
                        return 2;
                    }
                    device_type = argv[++i];
                    continue;
                }
                if (arg == "--labels") {
                    if (i + 1 >= argc) {
                        std::cerr << "Missing value for --labels.\n";
                        print_usage();
                        return 2;
                    }
                    labels_csv = argv[++i];
                    continue;
                }
                if (arg == "--importance") {
                    if (i + 1 >= argc) {
                        std::cerr << "Missing value for --importance.\n";
                        print_usage();
                        return 2;
                    }
                    const std::string_view importance_arg{argv[++i]};
                    long long parsed = 0;
                    if (!parse_non_negative_i64(importance_arg, parsed) || parsed > 100) {
                        std::cerr << "Invalid value for --importance: " << importance_arg << "\n";
                        print_usage();
                        return 2;
                    }
                    importance = static_cast<int>(parsed);
                    set_importance = true;
                    continue;
                }
                if (arg == "--hide") {
                    if (i + 1 >= argc) {
                        std::cerr << "Missing value for --hide.\n";
                        print_usage();
                        return 2;
                    }
                    const std::string_view hide_arg{argv[++i]};
                    if (!parse_bool_flag(hide_arg, hide_value)) {
                        std::cerr << "Invalid value for --hide: " << hide_arg << "\n";
                        print_usage();
                        return 2;
                    }
                    hide_value_set = true;
                    continue;
                }
                if (arg == "--stale") {
                    if (i + 1 >= argc) {
                        std::cerr << "Missing value for --stale.\n";
                        print_usage();
                        return 2;
                    }
                    const std::string_view stale_arg{argv[++i]};
                    if (!parse_bool_flag(stale_arg, stale_value)) {
                        std::cerr << "Invalid value for --stale: " << stale_arg << "\n";
                        print_usage();
                        return 2;
                    }
                    stale_value_set = true;
                    continue;
                }
                std::cerr << "Unknown argument: " << arg << "\n";
                print_usage();
                return 2;
            }
            return print_inventory_edit_command(
                argv[3],
                device_type,
                labels_csv,
                importance,
                set_importance,
                hide_value_set,
                hide_value,
                stale_value_set,
                stale_value
            );
        }
        if (subcommand == "hide") {
            if (argc < 4) {
                std::cerr << "Missing device-id.\n";
                print_usage();
                return 2;
            }
            bool hide_value = true;
            if (argc == 5) {
                if (std::string_view{argv[4]} == "--off") {
                    hide_value = false;
                } else {
                    std::cerr << "Unknown argument: " << argv[4] << "\n";
                    print_usage();
                    return 2;
                }
            } else if (argc > 5) {
                std::cerr << "Too many arguments for inventory hide.\n";
                print_usage();
                return 2;
            }
            return print_inventory_hide_command(argv[3], hide_value);
        }
        if (subcommand == "mark-stale") {
            if (argc < 4) {
                std::cerr << "Missing device-id.\n";
                print_usage();
                return 2;
            }
            bool stale_value = true;
            if (argc == 5) {
                if (std::string_view{argv[4]} == "--off") {
                    stale_value = false;
                } else {
                    std::cerr << "Unknown argument: " << argv[4] << "\n";
                    print_usage();
                    return 2;
                }
            } else if (argc > 5) {
                std::cerr << "Too many arguments for inventory mark-stale.\n";
                print_usage();
                return 2;
            }
            return print_inventory_mark_stale_command(argv[3], stale_value);
        }
        if (subcommand == "hide-stale") {
            if (argc != 3) {
                std::cerr << "Too many arguments for inventory hide-stale.\n";
                print_usage();
                return 2;
            }
            return print_inventory_hide_stale_command();
        }
        if (subcommand == "export") {
            if (argc != 3) {
                std::cerr << "Too many arguments for inventory export.\n";
                print_usage();
                return 2;
            }
            return print_inventory_export_command();
        }
        std::cerr << "Unknown inventory subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "workspace") {
        if (argc < 3) {
            std::cerr << "Missing workspace subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        netsentinel::storage::StorageConfig storage_config{};
        netsentinel::storage::NetworkWorkspaceRecord workspace{};
        netsentinel::storage::WorkspaceScanHistoryRecord scan_history{};
        netsentinel::api::ProfessionalSiteRecord professional_site{};
        std::string workspace_id;
        std::string professional_input_path;
        std::string professional_output_path;
        std::string professional_consultant = "local-consultant";
        bool professional_custom_site = false;
        bool professional_mock = false;
        bool monitoring_set = false;
        bool monitoring_value = true;

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --db.\n";
                    print_usage();
                    return 2;
                }
                storage_config.database_path = argv[++i];
                continue;
            }
            const auto db_prefix = std::string_view{"--db="};
            if (arg.rfind(db_prefix, 0) == 0) {
                storage_config.database_path = arg.substr(db_prefix.size());
                continue;
            }
            if (arg == "--id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --id.\n";
                    print_usage();
                    return 2;
                }
                workspace_id = argv[++i];
                workspace.workspace_id = workspace_id;
                scan_history.workspace_id = workspace_id;
                continue;
            }
            const auto id_prefix = std::string_view{"--id="};
            if (arg.rfind(id_prefix, 0) == 0) {
                workspace_id = arg.substr(id_prefix.size());
                workspace.workspace_id = workspace_id;
                scan_history.workspace_id = workspace_id;
                continue;
            }
            if (arg == "--gateway-mac") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --gateway-mac.\n";
                    print_usage();
                    return 2;
                }
                workspace.key.gateway_mac = argv[++i];
                continue;
            }
            const auto gateway_mac_prefix = std::string_view{"--gateway-mac="};
            if (arg.rfind(gateway_mac_prefix, 0) == 0) {
                workspace.key.gateway_mac = arg.substr(gateway_mac_prefix.size());
                continue;
            }
            if (arg == "--subnet") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --subnet.\n";
                    print_usage();
                    return 2;
                }
                workspace.key.subnet = argv[++i];
                continue;
            }
            const auto subnet_prefix = std::string_view{"--subnet="};
            if (arg.rfind(subnet_prefix, 0) == 0) {
                workspace.key.subnet = arg.substr(subnet_prefix.size());
                continue;
            }
            if (arg == "--ssid") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --ssid.\n";
                    print_usage();
                    return 2;
                }
                workspace.key.ssid = argv[++i];
                continue;
            }
            const auto ssid_prefix = std::string_view{"--ssid="};
            if (arg.rfind(ssid_prefix, 0) == 0) {
                workspace.key.ssid = arg.substr(ssid_prefix.size());
                continue;
            }
            if (arg == "--label") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --label.\n";
                    print_usage();
                    return 2;
                }
                workspace.key.user_label = argv[++i];
                continue;
            }
            const auto label_prefix = std::string_view{"--label="};
            if (arg.rfind(label_prefix, 0) == 0) {
                workspace.key.user_label = arg.substr(label_prefix.size());
                continue;
            }
            if (arg == "--monitoring") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --monitoring.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_bool_flag(argv[++i], monitoring_value)) {
                    std::cerr << "Invalid value for --monitoring.\n";
                    print_usage();
                    return 2;
                }
                monitoring_set = true;
                continue;
            }
            const auto monitoring_prefix = std::string_view{"--monitoring="};
            if (arg.rfind(monitoring_prefix, 0) == 0) {
                if (!parse_bool_flag(arg.substr(monitoring_prefix.size()), monitoring_value)) {
                    std::cerr << "Invalid value for --monitoring.\n";
                    print_usage();
                    return 2;
                }
                monitoring_set = true;
                continue;
            }
            if (arg == "--limit") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --limit.\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_limit = 0;
                if (!parse_non_negative_u64(argv[++i], parsed_limit)) {
                    std::cerr << "Invalid value for --limit.\n";
                    print_usage();
                    return 2;
                }
                workspace.settings.monitored_network_limit = parsed_limit;
                storage_config.monitored_network_limit = parsed_limit == 0 ? storage_config.monitored_network_limit : parsed_limit;
                continue;
            }
            const auto limit_prefix = std::string_view{"--limit="};
            if (arg.rfind(limit_prefix, 0) == 0) {
                std::size_t parsed_limit = 0;
                if (!parse_non_negative_u64(arg.substr(limit_prefix.size()), parsed_limit)) {
                    std::cerr << "Invalid value for --limit.\n";
                    print_usage();
                    return 2;
                }
                workspace.settings.monitored_network_limit = parsed_limit;
                storage_config.monitored_network_limit = parsed_limit == 0 ? storage_config.monitored_network_limit : parsed_limit;
                continue;
            }
            if (arg == "--profile") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --profile.\n";
                    print_usage();
                    return 2;
                }
                workspace.settings.scan_profile = argv[++i];
                continue;
            }
            const auto profile_prefix = std::string_view{"--profile="};
            if (arg.rfind(profile_prefix, 0) == 0) {
                workspace.settings.scan_profile = arg.substr(profile_prefix.size());
                continue;
            }
            if (arg == "--notes") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --notes.\n";
                    print_usage();
                    return 2;
                }
                workspace.settings.notes = argv[++i];
                professional_site.notes = workspace.settings.notes;
                continue;
            }
            const auto notes_prefix = std::string_view{"--notes="};
            if (arg.rfind(notes_prefix, 0) == 0) {
                workspace.settings.notes = arg.substr(notes_prefix.size());
                professional_site.notes = workspace.settings.notes;
                continue;
            }
            if (arg == "--mock") {
                professional_mock = true;
                continue;
            }
            if (arg == "--input") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --input.\n";
                    print_usage();
                    return 2;
                }
                professional_input_path = argv[++i];
                continue;
            }
            const auto input_prefix = std::string_view{"--input="};
            if (arg.rfind(input_prefix, 0) == 0) {
                professional_input_path = arg.substr(input_prefix.size());
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                professional_output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                professional_output_path = arg.substr(output_prefix.size());
                continue;
            }
            if (arg == "--consultant") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --consultant.\n";
                    print_usage();
                    return 2;
                }
                professional_consultant = argv[++i];
                continue;
            }
            const auto consultant_prefix = std::string_view{"--consultant="};
            if (arg.rfind(consultant_prefix, 0) == 0) {
                professional_consultant = arg.substr(consultant_prefix.size());
                continue;
            }
            if (arg == "--site") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --site.\n";
                    print_usage();
                    return 2;
                }
                professional_site.site_id = argv[++i];
                professional_custom_site = true;
                continue;
            }
            const auto site_prefix = std::string_view{"--site="};
            if (arg.rfind(site_prefix, 0) == 0) {
                professional_site.site_id = arg.substr(site_prefix.size());
                professional_custom_site = true;
                continue;
            }
            if (arg == "--site-name") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --site-name.\n";
                    print_usage();
                    return 2;
                }
                professional_site.site_name = argv[++i];
                professional_custom_site = true;
                continue;
            }
            const auto site_name_prefix = std::string_view{"--site-name="};
            if (arg.rfind(site_name_prefix, 0) == 0) {
                professional_site.site_name = arg.substr(site_name_prefix.size());
                professional_custom_site = true;
                continue;
            }
            if (arg == "--cidr") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --cidr.\n";
                    print_usage();
                    return 2;
                }
                professional_site.network_cidr = argv[++i];
                professional_custom_site = true;
                continue;
            }
            const auto cidr_prefix = std::string_view{"--cidr="};
            if (arg.rfind(cidr_prefix, 0) == 0) {
                professional_site.network_cidr = arg.substr(cidr_prefix.size());
                professional_custom_site = true;
                continue;
            }
            if (arg == "--owner") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --owner.\n";
                    print_usage();
                    return 2;
                }
                professional_site.owner = argv[++i];
                professional_custom_site = true;
                continue;
            }
            const auto owner_prefix = std::string_view{"--owner="};
            if (arg.rfind(owner_prefix, 0) == 0) {
                professional_site.owner = arg.substr(owner_prefix.size());
                professional_custom_site = true;
                continue;
            }
            if (arg == "--tags") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --tags.\n";
                    print_usage();
                    return 2;
                }
                professional_site.tags = split_csv_tokens(argv[++i]);
                professional_custom_site = true;
                continue;
            }
            const auto tags_prefix = std::string_view{"--tags="};
            if (arg.rfind(tags_prefix, 0) == 0) {
                professional_site.tags = split_csv_tokens(arg.substr(tags_prefix.size()));
                professional_custom_site = true;
                continue;
            }
            if (arg == "--issue-state") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --issue-state.\n";
                    print_usage();
                    return 2;
                }
                professional_site.issue_state = argv[++i];
                professional_custom_site = true;
                continue;
            }
            const auto issue_state_prefix = std::string_view{"--issue-state="};
            if (arg.rfind(issue_state_prefix, 0) == 0) {
                professional_site.issue_state = arg.substr(issue_state_prefix.size());
                professional_custom_site = true;
                continue;
            }
            if (arg == "--template") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --template.\n";
                    print_usage();
                    return 2;
                }
                professional_site.report_template = argv[++i];
                professional_custom_site = true;
                continue;
            }
            const auto template_prefix = std::string_view{"--template="};
            if (arg.rfind(template_prefix, 0) == 0) {
                professional_site.report_template = arg.substr(template_prefix.size());
                professional_custom_site = true;
                continue;
            }
            if (arg == "--scan-id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --scan-id.\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_scan_id = 0;
                if (!parse_non_negative_u64(argv[++i], parsed_scan_id)) {
                    std::cerr << "Invalid value for --scan-id.\n";
                    print_usage();
                    return 2;
                }
                scan_history.scan_id = static_cast<std::int64_t>(parsed_scan_id);
                continue;
            }
            const auto scan_id_prefix = std::string_view{"--scan-id="};
            if (arg.rfind(scan_id_prefix, 0) == 0) {
                std::size_t parsed_scan_id = 0;
                if (!parse_non_negative_u64(arg.substr(scan_id_prefix.size()), parsed_scan_id)) {
                    std::cerr << "Invalid value for --scan-id.\n";
                    print_usage();
                    return 2;
                }
                scan_history.scan_id = static_cast<std::int64_t>(parsed_scan_id);
                continue;
            }
            if (arg == "--status") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --status.\n";
                    print_usage();
                    return 2;
                }
                scan_history.status = argv[++i];
                continue;
            }
            const auto status_prefix = std::string_view{"--status="};
            if (arg.rfind(status_prefix, 0) == 0) {
                scan_history.status = arg.substr(status_prefix.size());
                continue;
            }
            if (arg == "--summary") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --summary.\n";
                    print_usage();
                    return 2;
                }
                scan_history.summary = argv[++i];
                continue;
            }
            const auto summary_prefix = std::string_view{"--summary="};
            if (arg.rfind(summary_prefix, 0) == 0) {
                scan_history.summary = arg.substr(summary_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        if (monitoring_set) {
            workspace.settings.monitoring_enabled = monitoring_value;
        }

        if (subcommand == "list") {
            return print_workspace_list_command(storage_config);
        }
        if (subcommand == "upsert") {
            return print_workspace_upsert_command(storage_config, workspace);
        }
        if (subcommand == "switch") {
            if (workspace_id.empty()) {
                std::cerr << "Missing --id for workspace switch.\n";
                print_usage();
                return 2;
            }
            return print_workspace_switch_command(storage_config, workspace_id);
        }
        if (subcommand == "active") {
            return print_workspace_active_command(storage_config);
        }
        if (subcommand == "record-scan") {
            if (scan_history.workspace_id.empty()) {
                std::cerr << "Missing --id for workspace record-scan.\n";
                print_usage();
                return 2;
            }
            return print_workspace_record_scan_command(storage_config, scan_history);
        }
        if (subcommand == "history") {
            return print_workspace_history_command(storage_config, workspace_id);
        }
        if (subcommand == "pro-export") {
            (void)professional_mock;
            netsentinel::api::ProfessionalWorkspacePack pack{};
            if (professional_custom_site) {
                if (professional_site.site_id.empty()) {
                    professional_site.site_id = workspace_id.empty() ? "client-site" : workspace_id;
                }
                if (professional_site.site_name.empty()) {
                    professional_site.site_name = professional_site.site_id;
                }
                if (professional_site.network_cidr.empty()) {
                    professional_site.network_cidr = workspace.key.subnet.empty() ? "192.168.50.0/24" : workspace.key.subnet;
                }
                if (professional_site.owner.empty()) {
                    professional_site.owner = "Local Owner";
                }
                if (professional_site.tags.empty()) {
                    professional_site.tags = {"local-first", "authorized-before-scan"};
                }
                if (professional_site.issue_state.empty()) {
                    professional_site.issue_state = "monitoring";
                }
                if (professional_site.report_template.empty()) {
                    professional_site.report_template = "technical";
                }
                pack = netsentinel::api::make_single_site_professional_workspace_pack(professional_consultant, professional_site);
            } else {
                pack = netsentinel::api::make_demo_professional_workspace_pack();
                if (!professional_consultant.empty()) {
                    pack.consultant_name = professional_consultant;
                }
            }
            return print_professional_workspace_export_command(pack, professional_output_path);
        }
        if (subcommand == "pro-import") {
            if (professional_input_path.empty()) {
                std::cerr << "Missing --input for workspace pro-import.\n";
                print_usage();
                return 2;
            }
            return print_professional_workspace_import_command(professional_input_path);
        }
        if (subcommand == "pro-report") {
            if (professional_input_path.empty()) {
                std::cerr << "Missing --input for workspace pro-report.\n";
                print_usage();
                return 2;
            }
            return print_professional_workspace_report_command(professional_input_path, professional_output_path);
        }
        std::cerr << "Unknown workspace subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "search") {
        if (argc < 3) {
            std::cerr << "Missing search subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        bool is_devices = subcommand == "devices";
        bool is_filters = subcommand == "filters";
        bool filter_list = false;
        bool filter_save = false;
        bool filter_run = false;
        netsentinel::storage::StorageConfig storage_config{};
        netsentinel::storage::DeviceSearchQuery query{};
        netsentinel::storage::SavedFilterTemplate filter{};
        std::string filter_id;

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "list") {
                filter_list = true;
                continue;
            }
            if (arg == "save") {
                filter_save = true;
                continue;
            }
            if (arg == "run") {
                filter_run = true;
                continue;
            }
            if (arg == "--db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --db.\n";
                    print_usage();
                    return 2;
                }
                storage_config.database_path = argv[++i];
                continue;
            }
            const auto db_prefix = std::string_view{"--db="};
            if (arg.rfind(db_prefix, 0) == 0) {
                storage_config.database_path = arg.substr(db_prefix.size());
                continue;
            }
            if (arg == "--id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --id.\n";
                    print_usage();
                    return 2;
                }
                filter_id = argv[++i];
                filter.filter_id = filter_id;
                continue;
            }
            const auto id_prefix = std::string_view{"--id="};
            if (arg.rfind(id_prefix, 0) == 0) {
                filter_id = arg.substr(id_prefix.size());
                filter.filter_id = filter_id;
                continue;
            }
            if (arg == "--name") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --name.\n";
                    print_usage();
                    return 2;
                }
                filter.name = argv[++i];
                continue;
            }
            const auto name_prefix = std::string_view{"--name="};
            if (arg.rfind(name_prefix, 0) == 0) {
                filter.name = arg.substr(name_prefix.size());
                continue;
            }
            if (arg == "--preset") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --preset.\n";
                    print_usage();
                    return 2;
                }
                query.preset = argv[++i];
                continue;
            }
            const auto preset_prefix = std::string_view{"--preset="};
            if (arg.rfind(preset_prefix, 0) == 0) {
                query.preset = arg.substr(preset_prefix.size());
                continue;
            }
            if (arg == "--vendor") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --vendor.\n";
                    print_usage();
                    return 2;
                }
                query.vendor = argv[++i];
                continue;
            }
            const auto vendor_prefix = std::string_view{"--vendor="};
            if (arg.rfind(vendor_prefix, 0) == 0) {
                query.vendor = arg.substr(vendor_prefix.size());
                continue;
            }
            if (arg == "--os") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --os.\n";
                    print_usage();
                    return 2;
                }
                query.os_guess = argv[++i];
                continue;
            }
            const auto os_prefix = std::string_view{"--os="};
            if (arg.rfind(os_prefix, 0) == 0) {
                query.os_guess = arg.substr(os_prefix.size());
                continue;
            }
            if (arg == "--text") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --text.\n";
                    print_usage();
                    return 2;
                }
                query.text = argv[++i];
                continue;
            }
            const auto text_prefix = std::string_view{"--text="};
            if (arg.rfind(text_prefix, 0) == 0) {
                query.text = arg.substr(text_prefix.size());
                continue;
            }
            if (arg == "--network") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --network.\n";
                    print_usage();
                    return 2;
                }
                query.network_id = argv[++i];
                continue;
            }
            const auto network_prefix = std::string_view{"--network="};
            if (arg.rfind(network_prefix, 0) == 0) {
                query.network_id = arg.substr(network_prefix.size());
                continue;
            }
            if (arg == "--all") {
                query.include_hidden = true;
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        filter.query = query;
        if (is_devices) {
            return print_search_devices_command(storage_config, query);
        }
        if (is_filters) {
            const int selected = (filter_list ? 1 : 0) + (filter_save ? 1 : 0) + (filter_run ? 1 : 0);
            if (selected != 1) {
                std::cerr << "Search filters requires exactly one of list, save, or run.\n";
                print_usage();
                return 2;
            }
            if (filter_list) {
                return print_filter_list_command(storage_config);
            }
            if (filter_save) {
                return print_filter_save_command(storage_config, filter);
            }
            if (filter_id.empty()) {
                std::cerr << "Missing --id for search filters run.\n";
                print_usage();
                return 2;
            }
            return print_filter_run_command(storage_config, filter_id);
        }
        std::cerr << "Unknown search subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "agent") {
        if (argc < 3) {
            std::cerr << "Missing agent subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "protocol") {
            std::cerr << "Unknown agent subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }

        netsentinel::api::AgentCollectorConfig agent_config{};
        agent_config.enabled = true;
        agent_config.mock_mode = true;
        agent_config.collector_id = "netsentinel-desktop";
        agent_config.agent_id = "mock-raspberry-pi";
        agent_config.agent_kind = "raspberry-pi";
        agent_config.server_certificate_fingerprint = "sha256:mock-server-fingerprint";
        agent_config.client_certificate_fingerprint = "sha256:mock-client-fingerprint";
        agent_config.pairing_token = "pair:local-only-prompt79";
        agent_config.pairing_token_signature = "sig:local-only-prompt79";
        std::string output_path;
        auto add_agent_permission = [&agent_config](std::string value) {
            std::size_t start = 0;
            while (start <= value.size()) {
                const auto comma = value.find(',', start);
                const auto end = comma == std::string::npos ? value.size() : comma;
                const auto permission = value.substr(start, end - start);
                if (!permission.empty() &&
                    std::find(agent_config.permissions.begin(), agent_config.permissions.end(), permission) == agent_config.permissions.end()) {
                    agent_config.permissions.push_back(permission);
                }
                if (comma == std::string::npos) {
                    break;
                }
                start = comma + 1;
            }
        };

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                agent_config.mock_mode = true;
                continue;
            }
            if (arg == "--real") {
                agent_config.mock_mode = false;
                continue;
            }
            if (arg == "--collector-id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --collector-id.\n";
                    print_usage();
                    return 2;
                }
                agent_config.collector_id = argv[++i];
                continue;
            }
            const auto collector_prefix = std::string_view{"--collector-id="};
            if (arg.rfind(collector_prefix, 0) == 0) {
                agent_config.collector_id = arg.substr(collector_prefix.size());
                continue;
            }
            if (arg == "--agent-id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --agent-id.\n";
                    print_usage();
                    return 2;
                }
                agent_config.agent_id = argv[++i];
                continue;
            }
            const auto agent_id_prefix = std::string_view{"--agent-id="};
            if (arg.rfind(agent_id_prefix, 0) == 0) {
                agent_config.agent_id = arg.substr(agent_id_prefix.size());
                continue;
            }
            if (arg == "--agent-kind") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --agent-kind.\n";
                    print_usage();
                    return 2;
                }
                agent_config.agent_kind = argv[++i];
                continue;
            }
            const auto agent_kind_prefix = std::string_view{"--agent-kind="};
            if (arg.rfind(agent_kind_prefix, 0) == 0) {
                agent_config.agent_kind = arg.substr(agent_kind_prefix.size());
                continue;
            }
            if (arg == "--server-cert") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --server-cert.\n";
                    print_usage();
                    return 2;
                }
                agent_config.server_certificate_fingerprint = argv[++i];
                continue;
            }
            const auto server_cert_prefix = std::string_view{"--server-cert="};
            if (arg.rfind(server_cert_prefix, 0) == 0) {
                agent_config.server_certificate_fingerprint = arg.substr(server_cert_prefix.size());
                continue;
            }
            if (arg == "--client-cert") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --client-cert.\n";
                    print_usage();
                    return 2;
                }
                agent_config.client_certificate_fingerprint = argv[++i];
                continue;
            }
            const auto client_cert_prefix = std::string_view{"--client-cert="};
            if (arg.rfind(client_cert_prefix, 0) == 0) {
                agent_config.client_certificate_fingerprint = arg.substr(client_cert_prefix.size());
                continue;
            }
            if (arg == "--token") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --token.\n";
                    print_usage();
                    return 2;
                }
                agent_config.pairing_token = argv[++i];
                continue;
            }
            const auto token_prefix = std::string_view{"--token="};
            if (arg.rfind(token_prefix, 0) == 0) {
                agent_config.pairing_token = arg.substr(token_prefix.size());
                continue;
            }
            if (arg == "--signature") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --signature.\n";
                    print_usage();
                    return 2;
                }
                agent_config.pairing_token_signature = argv[++i];
                continue;
            }
            const auto signature_prefix = std::string_view{"--signature="};
            if (arg.rfind(signature_prefix, 0) == 0) {
                agent_config.pairing_token_signature = arg.substr(signature_prefix.size());
                continue;
            }
            if (arg == "--permission") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --permission.\n";
                    print_usage();
                    return 2;
                }
                add_agent_permission(argv[++i]);
                continue;
            }
            const auto permission_prefix = std::string_view{"--permission="};
            if (arg.rfind(permission_prefix, 0) == 0) {
                add_agent_permission(std::string(arg.substr(permission_prefix.size())));
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                output_path = arg.substr(output_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        return print_agent_protocol_command(agent_config, output_path);
    }

    if (cmd == "api") {
        if (argc < 3) {
            std::cerr << "Missing api subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        netsentinel::api::LocalRestApiConfig api_config{};
        netsentinel::api::LocalRestApiRequest api_request{};
        api_request.method = "GET";
        api_request.path = "/v1/networks";
        auto add_api_permission = [&api_config](std::string value) {
            std::size_t start = 0;
            while (start <= value.size()) {
                const auto comma = value.find(',', start);
                const auto end = comma == std::string::npos ? value.size() : comma;
                const auto permission = value.substr(start, end - start);
                if (!permission.empty() &&
                    std::find(api_config.permissions.begin(), api_config.permissions.end(), permission) == api_config.permissions.end()) {
                    api_config.permissions.push_back(permission);
                }
                if (comma == std::string::npos) {
                    break;
                }
                start = comma + 1;
            }
        };
        auto parse_u32_arg = [](std::string value, std::uint32_t& out) {
            try {
                const auto parsed = std::stoul(value);
                out = static_cast<std::uint32_t>(parsed);
                return true;
            } catch (...) {
                return false;
            }
        };

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--enabled") {
                api_config.enabled = true;
                continue;
            }
            if (arg == "--apply") {
                api_config.dry_run = false;
                continue;
            }
            if (arg == "--bind") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --bind.\n";
                    print_usage();
                    return 2;
                }
                api_config.bind_host = argv[++i];
                continue;
            }
            const auto bind_prefix = std::string_view{"--bind="};
            if (arg.rfind(bind_prefix, 0) == 0) {
                api_config.bind_host = arg.substr(bind_prefix.size());
                continue;
            }
            if (arg == "--token") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --token.\n";
                    print_usage();
                    return 2;
                }
                api_config.auth_token = argv[++i];
                api_request.bearer_token = api_config.auth_token;
                continue;
            }
            const auto token_prefix = std::string_view{"--token="};
            if (arg.rfind(token_prefix, 0) == 0) {
                api_config.auth_token = arg.substr(token_prefix.size());
                api_request.bearer_token = api_config.auth_token;
                continue;
            }
            if (arg == "--request-token") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --request-token.\n";
                    print_usage();
                    return 2;
                }
                api_request.bearer_token = argv[++i];
                continue;
            }
            const auto request_token_prefix = std::string_view{"--request-token="};
            if (arg.rfind(request_token_prefix, 0) == 0) {
                api_request.bearer_token = arg.substr(request_token_prefix.size());
                continue;
            }
            if (arg == "--csrf") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --csrf.\n";
                    print_usage();
                    return 2;
                }
                api_config.csrf_token = argv[++i];
                api_request.csrf_token = api_config.csrf_token;
                continue;
            }
            const auto csrf_prefix = std::string_view{"--csrf="};
            if (arg.rfind(csrf_prefix, 0) == 0) {
                api_config.csrf_token = arg.substr(csrf_prefix.size());
                api_request.csrf_token = api_config.csrf_token;
                continue;
            }
            if (arg == "--request-csrf") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --request-csrf.\n";
                    print_usage();
                    return 2;
                }
                api_request.csrf_token = argv[++i];
                continue;
            }
            const auto request_csrf_prefix = std::string_view{"--request-csrf="};
            if (arg.rfind(request_csrf_prefix, 0) == 0) {
                api_request.csrf_token = arg.substr(request_csrf_prefix.size());
                continue;
            }
            if (arg == "--permission") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --permission.\n";
                    print_usage();
                    return 2;
                }
                add_api_permission(argv[++i]);
                continue;
            }
            const auto permission_prefix = std::string_view{"--permission="};
            if (arg.rfind(permission_prefix, 0) == 0) {
                add_api_permission(std::string(arg.substr(permission_prefix.size())));
                continue;
            }
            if (arg == "--rate-limit") {
                if (i + 1 >= argc || !parse_u32_arg(argv[i + 1], api_config.rate_limit_per_minute)) {
                    std::cerr << "Missing or invalid value for --rate-limit.\n";
                    print_usage();
                    return 2;
                }
                ++i;
                continue;
            }
            const auto rate_limit_prefix = std::string_view{"--rate-limit="};
            if (arg.rfind(rate_limit_prefix, 0) == 0) {
                if (!parse_u32_arg(std::string(arg.substr(rate_limit_prefix.size())), api_config.rate_limit_per_minute)) {
                    std::cerr << "Invalid value for --rate-limit.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--requests-in-window") {
                if (i + 1 >= argc || !parse_u32_arg(argv[i + 1], api_request.simulated_requests_in_window)) {
                    std::cerr << "Missing or invalid value for --requests-in-window.\n";
                    print_usage();
                    return 2;
                }
                ++i;
                continue;
            }
            const auto requests_prefix = std::string_view{"--requests-in-window="};
            if (arg.rfind(requests_prefix, 0) == 0) {
                if (!parse_u32_arg(std::string(arg.substr(requests_prefix.size())), api_request.simulated_requests_in_window)) {
                    std::cerr << "Invalid value for --requests-in-window.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--method") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --method.\n";
                    print_usage();
                    return 2;
                }
                api_request.method = argv[++i];
                continue;
            }
            const auto method_prefix = std::string_view{"--method="};
            if (arg.rfind(method_prefix, 0) == 0) {
                api_request.method = arg.substr(method_prefix.size());
                continue;
            }
            if (arg == "--path") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --path.\n";
                    print_usage();
                    return 2;
                }
                api_request.path = argv[++i];
                continue;
            }
            const auto path_prefix = std::string_view{"--path="};
            if (arg.rfind(path_prefix, 0) == 0) {
                api_request.path = arg.substr(path_prefix.size());
                continue;
            }
            if (arg == "--db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --db.\n";
                    print_usage();
                    return 2;
                }
                api_config.storage.database_path = argv[++i];
                continue;
            }
            const auto db_prefix = std::string_view{"--db="};
            if (arg.rfind(db_prefix, 0) == 0) {
                api_config.storage.database_path = arg.substr(db_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        if (subcommand == "status") {
            return print_api_status_command(api_config);
        }
        if (subcommand == "request") {
            return print_api_request_command(api_config, api_request);
        }
        std::cerr << "Unknown api subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "simulation") {
        if (argc < 3) {
            std::cerr << "Missing simulation subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "run") {
            std::cerr << "Unknown simulation subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }
        netsentinel::api::SimulationSuiteConfig simulation_config{};
        simulation_config.mock_mode = false;
        std::string output_path;
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                simulation_config.mock_mode = true;
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                output_path = arg.substr(output_prefix.size());
                continue;
            }
            if (arg == "--max-runtime-ms") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --max-runtime-ms.\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed = 0;
                if (!parse_non_negative_u64(argv[++i], parsed)) {
                    std::cerr << "Invalid value for --max-runtime-ms.\n";
                    print_usage();
                    return 2;
                }
                simulation_config.max_runtime_ms = parsed;
                continue;
            }
            const auto max_runtime_prefix = std::string_view{"--max-runtime-ms="};
            if (arg.rfind(max_runtime_prefix, 0) == 0) {
                std::size_t parsed = 0;
                if (!parse_non_negative_u64(arg.substr(max_runtime_prefix.size()), parsed)) {
                    std::cerr << "Invalid value for --max-runtime-ms.\n";
                    print_usage();
                    return 2;
                }
                simulation_config.max_runtime_ms = parsed;
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_simulation_run_command(simulation_config, output_path);
    }

    if (cmd == "privacy") {
        if (argc < 3) {
            std::cerr << "Missing privacy subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "review") {
            std::cerr << "Unknown privacy subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }
        netsentinel::api::PrivacyReviewRequest privacy_request{};
        privacy_request.settings = netsentinel::api::default_privacy_minimization_settings();
        std::string output_path;
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                privacy_request.log_lines.push_back("scan log router-password=secret token=abc123 target=192.168.50.30 mac=38:7A:0E:A4:EF:84");
                privacy_request.log_lines.push_back("normal log line without private values");
                continue;
            }
            if (arg == "--export") {
                privacy_request.export_requested = true;
                continue;
            }
            if (arg == "--ack-export") {
                privacy_request.export_acknowledged = true;
                continue;
            }
            if (arg == "--report-type") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --report-type.\n";
                    print_usage();
                    return 2;
                }
                privacy_request.report_type = argv[++i];
                continue;
            }
            const auto report_type_prefix = std::string_view{"--report-type="};
            if (arg.rfind(report_type_prefix, 0) == 0) {
                privacy_request.report_type = arg.substr(report_type_prefix.size());
                continue;
            }
            if (arg == "--log-line") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --log-line.\n";
                    print_usage();
                    return 2;
                }
                privacy_request.log_lines.push_back(argv[++i]);
                continue;
            }
            const auto log_line_prefix = std::string_view{"--log-line="};
            if (arg.rfind(log_line_prefix, 0) == 0) {
                privacy_request.log_lines.push_back(std::string(arg.substr(log_line_prefix.size())));
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                output_path = arg.substr(output_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_privacy_review_command(privacy_request, output_path);
    }

    if (cmd == "report") {
        if (argc < 3) {
            std::cerr << "Missing report subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        netsentinel::reports::ReportConfig report_config{};

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                report_config.mock_mode = true;
                continue;
            }
            if (arg == "--type") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --type.\n";
                    print_usage();
                    return 2;
                }
                report_config.report_type = argv[++i];
                continue;
            }
            const auto type_prefix = std::string_view{"--type="};
            if (arg.rfind(type_prefix, 0) == 0) {
                report_config.report_type = arg.substr(type_prefix.size());
                continue;
            }
            if (arg == "--format") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --format.\n";
                    print_usage();
                    return 2;
                }
                report_config.format = argv[++i];
                continue;
            }
            const auto format_prefix = std::string_view{"--format="};
            if (arg.rfind(format_prefix, 0) == 0) {
                report_config.format = arg.substr(format_prefix.size());
                continue;
            }
            if (arg == "--db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --db.\n";
                    print_usage();
                    return 2;
                }
                report_config.storage.database_path = argv[++i];
                continue;
            }
            const auto db_prefix = std::string_view{"--db="};
            if (arg.rfind(db_prefix, 0) == 0) {
                report_config.storage.database_path = arg.substr(db_prefix.size());
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                report_config.output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                report_config.output_path = arg.substr(output_prefix.size());
                continue;
            }
            if (arg == "--gateway") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --gateway.\n";
                    print_usage();
                    return 2;
                }
                report_config.gateway = argv[++i];
                continue;
            }
            const auto gateway_prefix = std::string_view{"--gateway="};
            if (arg.rfind(gateway_prefix, 0) == 0) {
                report_config.gateway = arg.substr(gateway_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        if (subcommand == "generate") {
            return print_report_generate_command(report_config);
        }
        std::cerr << "Unknown report subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "gui") {
        if (argc < 3) {
            std::cerr << "Missing gui subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        netsentinel::ui::GuiShellConfig gui_config{};
        netsentinel::ui::GuiBandwidthDashboardConfig bandwidth_dashboard_config{};
        netsentinel::ui::GuiDeviceListConfig device_list_config{};
        netsentinel::ui::GuiActionRequest action_request{};
        netsentinel::ui::GuiAccessibilityConfig accessibility_config{};
        action_request.mock_mode = false;
        std::string gui_device_id;
        std::string accessibility_output_path;

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--demo") {
                gui_config.demo_mode = true;
                bandwidth_dashboard_config.demo_mode = true;
                continue;
            }
            if (arg == "--db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --db.\n";
                    print_usage();
                    return 2;
                }
                gui_config.storage.database_path = argv[++i];
                bandwidth_dashboard_config.storage.database_path = gui_config.storage.database_path;
                device_list_config.storage.database_path = gui_config.storage.database_path;
                action_request.storage.database_path = gui_config.storage.database_path;
                continue;
            }
            const auto db_prefix = std::string_view{"--db="};
            if (arg.rfind(db_prefix, 0) == 0) {
                gui_config.storage.database_path = arg.substr(db_prefix.size());
                bandwidth_dashboard_config.storage.database_path = gui_config.storage.database_path;
                device_list_config.storage.database_path = gui_config.storage.database_path;
                action_request.storage.database_path = gui_config.storage.database_path;
                continue;
            }
            if (arg == "--gateway") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --gateway.\n";
                    print_usage();
                    return 2;
                }
                gui_config.gateway = argv[++i];
                continue;
            }
            const auto gateway_prefix = std::string_view{"--gateway="};
            if (arg.rfind(gateway_prefix, 0) == 0) {
                gui_config.gateway = arg.substr(gateway_prefix.size());
                continue;
            }
            if (arg == "--id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --id.\n";
                    print_usage();
                    return 2;
                }
                gui_device_id = argv[++i];
                action_request.action_id = gui_device_id;
                continue;
            }
            const auto id_prefix = std::string_view{"--id="};
            if (arg.rfind(id_prefix, 0) == 0) {
                gui_device_id = arg.substr(id_prefix.size());
                action_request.action_id = gui_device_id;
                continue;
            }
            if (arg == "--target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target.\n";
                    print_usage();
                    return 2;
                }
                action_request.target = argv[++i];
                continue;
            }
            const auto target_prefix = std::string_view{"--target="};
            if (arg.rfind(target_prefix, 0) == 0) {
                action_request.target = arg.substr(target_prefix.size());
                continue;
            }
            if (arg == "--token") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --token.\n";
                    print_usage();
                    return 2;
                }
                action_request.api_token = argv[++i];
                continue;
            }
            const auto token_prefix = std::string_view{"--token="};
            if (arg.rfind(token_prefix, 0) == 0) {
                action_request.api_token = arg.substr(token_prefix.size());
                continue;
            }
            if (arg == "--apply") {
                action_request.dry_run = false;
                continue;
            }
            if (arg == "--confirm") {
                action_request.confirmed = true;
                continue;
            }
            if (arg == "--mock") {
                action_request.mock_mode = true;
                bandwidth_dashboard_config.mock_mode = true;
                continue;
            }
            if (arg == "--low-resource") {
                accessibility_config.low_resource_mode = true;
                continue;
            }
            if (arg == "--high-contrast") {
                accessibility_config.high_contrast = true;
                continue;
            }
            if (arg == "--language") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --language.\n";
                    print_usage();
                    return 2;
                }
                accessibility_config.language = argv[++i];
                continue;
            }
            const auto language_prefix = std::string_view{"--language="};
            if (arg.rfind(language_prefix, 0) == 0) {
                accessibility_config.language = arg.substr(language_prefix.size());
                continue;
            }
            if (arg == "--dpi-scale") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --dpi-scale.\n";
                    print_usage();
                    return 2;
                }
                try {
                    accessibility_config.dpi_scale = std::stod(argv[++i]);
                } catch (...) {
                    std::cerr << "Invalid value for --dpi-scale.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            const auto dpi_prefix = std::string_view{"--dpi-scale="};
            if (arg.rfind(dpi_prefix, 0) == 0) {
                try {
                    accessibility_config.dpi_scale = std::stod(std::string(arg.substr(dpi_prefix.size())));
                } catch (...) {
                    std::cerr << "Invalid value for --dpi-scale.\n";
                    print_usage();
                    return 2;
                }
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                accessibility_output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                accessibility_output_path = arg.substr(output_prefix.size());
                continue;
            }
            if (arg == "--report-type") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --report-type.\n";
                    print_usage();
                    return 2;
                }
                action_request.report_type = argv[++i];
                continue;
            }
            const auto report_type_prefix = std::string_view{"--report-type="};
            if (arg.rfind(report_type_prefix, 0) == 0) {
                action_request.report_type = arg.substr(report_type_prefix.size());
                continue;
            }
            if (arg == "--report-format") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --report-format.\n";
                    print_usage();
                    return 2;
                }
                action_request.report_format = argv[++i];
                continue;
            }
            const auto report_format_prefix = std::string_view{"--report-format="};
            if (arg.rfind(report_format_prefix, 0) == 0) {
                action_request.report_format = arg.substr(report_format_prefix.size());
                continue;
            }
            if (arg == "--filter") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --filter.\n";
                    print_usage();
                    return 2;
                }
                device_list_config.preset = argv[++i];
                continue;
            }
            const auto filter_prefix = std::string_view{"--filter="};
            if (arg.rfind(filter_prefix, 0) == 0) {
                device_list_config.preset = arg.substr(filter_prefix.size());
                continue;
            }
            if (arg == "--search") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --search.\n";
                    print_usage();
                    return 2;
                }
                device_list_config.search_text = argv[++i];
                continue;
            }
            const auto search_prefix = std::string_view{"--search="};
            if (arg.rfind(search_prefix, 0) == 0) {
                device_list_config.search_text = arg.substr(search_prefix.size());
                continue;
            }
            if (arg == "--vendor") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --vendor.\n";
                    print_usage();
                    return 2;
                }
                device_list_config.vendor = argv[++i];
                continue;
            }
            const auto vendor_prefix = std::string_view{"--vendor="};
            if (arg.rfind(vendor_prefix, 0) == 0) {
                device_list_config.vendor = arg.substr(vendor_prefix.size());
                continue;
            }
            if (arg == "--network") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --network.\n";
                    print_usage();
                    return 2;
                }
                device_list_config.network_id = argv[++i];
                continue;
            }
            const auto network_prefix = std::string_view{"--network="};
            if (arg.rfind(network_prefix, 0) == 0) {
                device_list_config.network_id = arg.substr(network_prefix.size());
                continue;
            }
            if (arg == "--sort") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --sort.\n";
                    print_usage();
                    return 2;
                }
                device_list_config.sort_by = argv[++i];
                continue;
            }
            const auto sort_prefix = std::string_view{"--sort="};
            if (arg.rfind(sort_prefix, 0) == 0) {
                device_list_config.sort_by = arg.substr(sort_prefix.size());
                continue;
            }
            if (arg == "--all") {
                device_list_config.include_hidden = true;
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        if (subcommand == "shell") {
            return print_gui_shell_command(gui_config);
        }
        if (subcommand == "devices") {
            return print_gui_devices_command(device_list_config);
        }
        if (subcommand == "bandwidth") {
            return print_gui_bandwidth_dashboard_command(bandwidth_dashboard_config);
        }
        if (subcommand == "device") {
            if (gui_device_id.empty()) {
                std::cerr << "Missing --id for gui device.\n";
                print_usage();
                return 2;
            }
            return print_gui_device_detail_command(device_list_config.storage, gui_device_id);
        }
        if (subcommand == "action") {
            if (action_request.action_id.empty()) {
                std::cerr << "Missing --id for gui action.\n";
                print_usage();
                return 2;
            }
            return print_gui_action_command(action_request);
        }
        if (subcommand == "accessibility") {
            return print_gui_accessibility_command(accessibility_config, accessibility_output_path);
        }
        std::cerr << "Unknown gui subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "audit") {
        if (argc < 3) {
            std::cerr << "Missing audit subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "final") {
            std::cerr << "Unknown audit subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }
        std::string output_path;
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                output_path = arg.substr(output_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_final_acceptance_audit_command(output_path);
    }

    if (cmd == "release") {
        if (argc < 3) {
            std::cerr << "Missing release subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        if (subcommand != "candidate") {
            std::cerr << "Unknown release subcommand: " << subcommand << "\n";
            print_usage();
            return 2;
        }
        netsentinel::installer::ReleaseCandidateConfig release_config{};
        std::string output_path;
        std::string changelog_path;
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                release_config.mock_mode = true;
                continue;
            }
            if (arg == "--qt-gui") {
                release_config.qt_gui_available = true;
                continue;
            }
            if (arg == "--npcap") {
                release_config.include_npcap_features = true;
                continue;
            }
            if (arg == "--router-integrations") {
                release_config.include_router_integrations = true;
                continue;
            }
            if (arg == "--no-service") {
                release_config.include_service = false;
                continue;
            }
            if (arg == "--no-tray") {
                release_config.include_tray = false;
                continue;
            }
            if (arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --output.\n";
                    print_usage();
                    return 2;
                }
                output_path = argv[++i];
                continue;
            }
            const auto output_prefix = std::string_view{"--output="};
            if (arg.rfind(output_prefix, 0) == 0) {
                output_path = arg.substr(output_prefix.size());
                continue;
            }
            if (arg == "--changelog") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --changelog.\n";
                    print_usage();
                    return 2;
                }
                changelog_path = argv[++i];
                continue;
            }
            const auto changelog_prefix = std::string_view{"--changelog="};
            if (arg.rfind(changelog_prefix, 0) == 0) {
                changelog_path = arg.substr(changelog_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_release_candidate_command(release_config, output_path, changelog_path);
    }

    if (cmd == "installer") {
        if (argc < 3) {
            std::cerr << "Missing installer subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        netsentinel::installer::InstallerPackagingConfig installer_config{};

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--format") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --format.\n";
                    print_usage();
                    return 2;
                }
                installer_config.package_format = argv[++i];
                continue;
            }
            const auto format_prefix = std::string_view{"--format="};
            if (arg.rfind(format_prefix, 0) == 0) {
                installer_config.package_format = arg.substr(format_prefix.size());
                continue;
            }
            if (arg == "--scope") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --scope.\n";
                    print_usage();
                    return 2;
                }
                installer_config.install_scope = argv[++i];
                continue;
            }
            const auto scope_prefix = std::string_view{"--scope="};
            if (arg.rfind(scope_prefix, 0) == 0) {
                installer_config.install_scope = arg.substr(scope_prefix.size());
                continue;
            }
            if (arg == "--install-location") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --install-location.\n";
                    print_usage();
                    return 2;
                }
                installer_config.install_location = argv[++i];
                continue;
            }
            const auto install_location_prefix = std::string_view{"--install-location="};
            if (arg.rfind(install_location_prefix, 0) == 0) {
                installer_config.install_location = arg.substr(install_location_prefix.size());
                continue;
            }
            if (arg == "--no-service") {
                installer_config.include_service = false;
                continue;
            }
            if (arg == "--no-tray") {
                installer_config.include_tray = false;
                continue;
            }
            if (arg == "--require-npcap") {
                installer_config.require_npcap = true;
                continue;
            }
            if (arg == "--firewall") {
                installer_config.request_firewall_permission = true;
                continue;
            }
            if (arg == "--auto-update") {
                installer_config.enable_auto_update = true;
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        if (subcommand == "plan") {
            return print_installer_plan_command(installer_config);
        }
        std::cerr << "Unknown installer subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "hardening") {
        if (argc < 3) {
            std::cerr << "Missing hardening subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        netsentinel::hardening::MockNetworkSimulatorConfig hardening_config{};

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                continue;
            }
            if (arg == "--subnet") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --subnet.\n";
                    print_usage();
                    return 2;
                }
                hardening_config.subnet = argv[++i];
                continue;
            }
            const auto subnet_prefix = std::string_view{"--subnet="};
            if (arg.rfind(subnet_prefix, 0) == 0) {
                hardening_config.subnet = arg.substr(subnet_prefix.size());
                continue;
            }
            if (arg == "--devices") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --devices.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_positive_u64(argv[++i], hardening_config.device_count)) {
                    std::cerr << "Invalid value for --devices.\n";
                    return 2;
                }
                continue;
            }
            const auto devices_prefix = std::string_view{"--devices="};
            if (arg.rfind(devices_prefix, 0) == 0) {
                if (!parse_positive_u64(arg.substr(devices_prefix.size()), hardening_config.device_count)) {
                    std::cerr << "Invalid value for --devices.\n";
                    return 2;
                }
                continue;
            }
            if (arg == "--seed") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --seed.\n";
                    print_usage();
                    return 2;
                }
                try {
                    hardening_config.seed = static_cast<std::uint32_t>(std::stoul(argv[++i]));
                } catch (...) {
                    std::cerr << "Invalid value for --seed.\n";
                    return 2;
                }
                continue;
            }
            const auto seed_prefix = std::string_view{"--seed="};
            if (arg.rfind(seed_prefix, 0) == 0) {
                try {
                    hardening_config.seed = static_cast<std::uint32_t>(std::stoul(std::string(arg.substr(seed_prefix.size()))));
                } catch (...) {
                    std::cerr << "Invalid value for --seed.\n";
                    return 2;
                }
                continue;
            }
            if (arg == "--no-cameras") {
                hardening_config.include_cameras = false;
                continue;
            }
            if (arg == "--no-iot") {
                hardening_config.include_iot = false;
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        if (subcommand == "report") {
            return print_hardening_report_command(hardening_config);
        }
        if (subcommand == "simulate") {
            return print_hardening_simulate_command(hardening_config);
        }
        if (subcommand == "fuzz") {
            return print_hardening_fuzz_command();
        }
        std::cerr << "Unknown hardening subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "bandwidth") {
        if (argc < 3) {
            std::cerr << "Missing bandwidth subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        netsentinel::bandwidth::MockBandwidthSourceConfig bandwidth_config{};
        netsentinel::bandwidth::NpcapDetectionConfig npcap_config{};
        netsentinel::bandwidth::LocalMachineBandwidthConfig local_config{};
        netsentinel::bandwidth::VisibleLanCaptureConfig capture_config{};
        netsentinel::bandwidth::SnmpRouterCounterConfig snmp_config{};
        netsentinel::bandwidth::UpnpIgdCounterConfig upnp_config{};
        netsentinel::bandwidth::FlowCollectorConfig flow_config{};
        netsentinel::bandwidth::RouterPluginRequest plugin_request{};
        plugin_request.operation = "list";
        netsentinel::bandwidth::BandwidthLimitRequest limit_request{};
        netsentinel::bandwidth::OpenWrtTelemetryConfig openwrt_config{};
        netsentinel::bandwidth::BandwidthAttributionMergeConfig attribution_config{};
        netsentinel::bandwidth::BandwidthAnomalyRuleConfig anomaly_config{};
        bool rollup_privacy_redact = false;
        std::string rollup_retention_cutoff;
        bool mock_requested = false;

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                mock_requested = true;
                local_config.mock_mode = true;
                capture_config.mock_mode = true;
                snmp_config.mock_mode = true;
                upnp_config.mock_mode = true;
                flow_config.mock_mode = true;
                plugin_request.mock_mode = true;
                limit_request.mock_mode = true;
                openwrt_config.mock_mode = true;
                continue;
            }
            if (arg == "--timestamp") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --timestamp.\n";
                    print_usage();
                    return 2;
                }
                bandwidth_config.timestamp_utc = argv[++i];
                local_config.timestamp_utc = bandwidth_config.timestamp_utc;
                capture_config.timestamp_utc = bandwidth_config.timestamp_utc;
                snmp_config.timestamp_utc = bandwidth_config.timestamp_utc;
                upnp_config.timestamp_utc = bandwidth_config.timestamp_utc;
                continue;
            }
            const auto timestamp_prefix = std::string_view{"--timestamp="};
            if (arg.rfind(timestamp_prefix, 0) == 0) {
                bandwidth_config.timestamp_utc = arg.substr(timestamp_prefix.size());
                local_config.timestamp_utc = bandwidth_config.timestamp_utc;
                capture_config.timestamp_utc = bandwidth_config.timestamp_utc;
                snmp_config.timestamp_utc = bandwidth_config.timestamp_utc;
                upnp_config.timestamp_utc = bandwidth_config.timestamp_utc;
                continue;
            }
            if (arg == "--dry-run") {
                capture_config.dry_run = true;
                snmp_config.dry_run = true;
                upnp_config.dry_run = true;
                flow_config.dry_run = true;
                limit_request.dry_run = true;
                openwrt_config.dry_run = true;
                continue;
            }
            if (arg == "--endpoint") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --endpoint.\n";
                    print_usage();
                    return 2;
                }
                openwrt_config.endpoint = argv[++i];
                limit_request.endpoint = openwrt_config.endpoint;
                continue;
            }
            const auto endpoint_prefix = std::string_view{"--endpoint="};
            if (arg.rfind(endpoint_prefix, 0) == 0) {
                openwrt_config.endpoint = arg.substr(endpoint_prefix.size());
                limit_request.endpoint = openwrt_config.endpoint;
                continue;
            }
            if (arg == "--transport") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --transport.\n";
                    print_usage();
                    return 2;
                }
                openwrt_config.transport = argv[++i];
                continue;
            }
            const auto transport_prefix = std::string_view{"--transport="};
            if (arg.rfind(transport_prefix, 0) == 0) {
                openwrt_config.transport = arg.substr(transport_prefix.size());
                continue;
            }
            if (arg == "--unsupported-firmware") {
                openwrt_config.mock_unsupported_firmware = true;
                continue;
            }
            if (arg == "--enable") {
                flow_config.enabled = true;
                continue;
            }
            if (arg == "--bind") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --bind.\n";
                    print_usage();
                    return 2;
                }
                flow_config.bind_address = argv[++i];
                continue;
            }
            const auto bind_prefix = std::string_view{"--bind="};
            if (arg.rfind(bind_prefix, 0) == 0) {
                flow_config.bind_address = arg.substr(bind_prefix.size());
                continue;
            }
            if (arg == "--port") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --port.\n";
                    print_usage();
                    return 2;
                }
                std::size_t port = 0;
                if (!parse_positive_u64(argv[++i], port) || port > 65535) {
                    std::cerr << "Invalid value for --port.\n";
                    return 2;
                }
                flow_config.port = static_cast<std::uint16_t>(port);
                continue;
            }
            const auto port_prefix = std::string_view{"--port="};
            if (arg.rfind(port_prefix, 0) == 0) {
                std::size_t port = 0;
                if (!parse_positive_u64(arg.substr(port_prefix.size()), port) || port > 65535) {
                    std::cerr << "Invalid value for --port.\n";
                    return 2;
                }
                flow_config.port = static_cast<std::uint16_t>(port);
                continue;
            }
            if (arg == "--confirm") {
                capture_config.confirmed = true;
                capture_config.dry_run = false;
                plugin_request.confirmed = true;
                limit_request.confirmed = true;
                continue;
            }
            if (arg == "--apply") {
                plugin_request.dry_run = false;
                limit_request.dry_run = false;
                continue;
            }
            if (arg == "--backend") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --backend.\n";
                    print_usage();
                    return 2;
                }
                limit_request.backend = argv[++i];
                continue;
            }
            const auto bandwidth_backend_prefix = std::string_view{"--backend="};
            if (arg.rfind(bandwidth_backend_prefix, 0) == 0) {
                limit_request.backend = arg.substr(bandwidth_backend_prefix.size());
                continue;
            }
            if (arg == "--action") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --action.\n";
                    print_usage();
                    return 2;
                }
                limit_request.action = argv[++i];
                continue;
            }
            const auto bandwidth_action_prefix = std::string_view{"--action="};
            if (arg.rfind(bandwidth_action_prefix, 0) == 0) {
                limit_request.action = arg.substr(bandwidth_action_prefix.size());
                continue;
            }
            if (arg == "--operation") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --operation.\n";
                    print_usage();
                    return 2;
                }
                plugin_request.operation = argv[++i];
                continue;
            }
            const auto operation_prefix = std::string_view{"--operation="};
            if (arg.rfind(operation_prefix, 0) == 0) {
                plugin_request.operation = arg.substr(operation_prefix.size());
                continue;
            }
            if (arg == "--plugin") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --plugin.\n";
                    print_usage();
                    return 2;
                }
                plugin_request.plugin_id = argv[++i];
                continue;
            }
            const auto plugin_prefix = std::string_view{"--plugin="};
            if (arg.rfind(plugin_prefix, 0) == 0) {
                plugin_request.plugin_id = arg.substr(plugin_prefix.size());
                continue;
            }
            if (arg == "--target") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target.\n";
                    print_usage();
                    return 2;
                }
                plugin_request.target_device_id = argv[++i];
                limit_request.target_device_id = plugin_request.target_device_id;
                continue;
            }
            const auto plugin_target_prefix = std::string_view{"--target="};
            if (arg.rfind(plugin_target_prefix, 0) == 0) {
                plugin_request.target_device_id = arg.substr(plugin_target_prefix.size());
                limit_request.target_device_id = plugin_request.target_device_id;
                continue;
            }
            if (arg == "--target-ip") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --target-ip.\n";
                    print_usage();
                    return 2;
                }
                limit_request.target_ip = argv[++i];
                continue;
            }
            const auto bandwidth_target_ip_prefix = std::string_view{"--target-ip="};
            if (arg.rfind(bandwidth_target_ip_prefix, 0) == 0) {
                limit_request.target_ip = arg.substr(bandwidth_target_ip_prefix.size());
                continue;
            }
            if (arg == "--adapter") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --adapter.\n";
                    print_usage();
                    return 2;
                }
                capture_config.adapter_id = argv[++i];
                continue;
            }
            const auto adapter_prefix = std::string_view{"--adapter="};
            if (arg.rfind(adapter_prefix, 0) == 0) {
                capture_config.adapter_id = arg.substr(adapter_prefix.size());
                continue;
            }
            if (arg == "--assume-mirrored") {
                capture_config.assume_mirrored_or_gateway_visible = true;
                continue;
            }
            if (arg == "--router") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --router.\n";
                    print_usage();
                    return 2;
                }
                snmp_config.router_ip = argv[++i];
                continue;
            }
            const auto router_prefix = std::string_view{"--router="};
            if (arg.rfind(router_prefix, 0) == 0) {
                snmp_config.router_ip = arg.substr(router_prefix.size());
                continue;
            }
            if (arg == "--gateway") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --gateway.\n";
                    print_usage();
                    return 2;
                }
                upnp_config.gateway = argv[++i];
                continue;
            }
            const auto upnp_gateway_prefix = std::string_view{"--gateway="};
            if (arg.rfind(upnp_gateway_prefix, 0) == 0) {
                upnp_config.gateway = arg.substr(upnp_gateway_prefix.size());
                continue;
            }
            if (arg == "--no-counters") {
                upnp_config.mock_no_counters = true;
                continue;
            }
            if (arg == "--credential-ref") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --credential-ref.\n";
                    print_usage();
                    return 2;
                }
                snmp_config.credential_reference = argv[++i];
                plugin_request.credential_reference = snmp_config.credential_reference;
                openwrt_config.credential_reference = snmp_config.credential_reference;
                limit_request.credential_reference = snmp_config.credential_reference;
                continue;
            }
            const auto credential_ref_prefix = std::string_view{"--credential-ref="};
            if (arg.rfind(credential_ref_prefix, 0) == 0) {
                snmp_config.credential_reference = arg.substr(credential_ref_prefix.size());
                plugin_request.credential_reference = snmp_config.credential_reference;
                openwrt_config.credential_reference = snmp_config.credential_reference;
                limit_request.credential_reference = snmp_config.credential_reference;
                continue;
            }
            if (arg == "--rule-id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --rule-id.\n";
                    print_usage();
                    return 2;
                }
                limit_request.rule_id = argv[++i];
                continue;
            }
            const auto rule_id_prefix = std::string_view{"--rule-id="};
            if (arg.rfind(rule_id_prefix, 0) == 0) {
                limit_request.rule_id = arg.substr(rule_id_prefix.size());
                continue;
            }
            if (arg == "--saved-rule") {
                limit_request.saved_rule = true;
                continue;
            }
            if (arg == "--download-kbps" || arg == "--upload-kbps") {
                const bool is_download = arg == "--download-kbps";
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for " << arg << ".\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_limit = 0;
                if (!parse_non_negative_u64(argv[++i], parsed_limit) || parsed_limit > 100000000ULL) {
                    std::cerr << "Invalid bandwidth limit value.\n";
                    return 2;
                }
                if (is_download) {
                    limit_request.download_limit_kbps = static_cast<int>(parsed_limit);
                } else {
                    limit_request.upload_limit_kbps = static_cast<int>(parsed_limit);
                }
                continue;
            }
            const auto bandwidth_download_prefix = std::string_view{"--download-kbps="};
            if (arg.rfind(bandwidth_download_prefix, 0) == 0) {
                std::size_t parsed_limit = 0;
                if (!parse_non_negative_u64(arg.substr(bandwidth_download_prefix.size()), parsed_limit) || parsed_limit > 100000000ULL) {
                    std::cerr << "Invalid bandwidth limit value.\n";
                    return 2;
                }
                limit_request.download_limit_kbps = static_cast<int>(parsed_limit);
                continue;
            }
            const auto bandwidth_upload_prefix = std::string_view{"--upload-kbps="};
            if (arg.rfind(bandwidth_upload_prefix, 0) == 0) {
                std::size_t parsed_limit = 0;
                if (!parse_non_negative_u64(arg.substr(bandwidth_upload_prefix.size()), parsed_limit) || parsed_limit > 100000000ULL) {
                    std::cerr << "Invalid bandwidth limit value.\n";
                    return 2;
                }
                limit_request.upload_limit_kbps = static_cast<int>(parsed_limit);
                continue;
            }
            if (arg == "--persist") {
                local_config.persist_rollup = true;
                continue;
            }
            if (arg == "--privacy-redact") {
                rollup_privacy_redact = true;
                continue;
            }
            if (arg == "--retention-cutoff") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --retention-cutoff.\n";
                    print_usage();
                    return 2;
                }
                rollup_retention_cutoff = argv[++i];
                continue;
            }
            const auto retention_cutoff_prefix = std::string_view{"--retention-cutoff="};
            if (arg.rfind(retention_cutoff_prefix, 0) == 0) {
                rollup_retention_cutoff = arg.substr(retention_cutoff_prefix.size());
                continue;
            }
            if (arg == "--db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --db.\n";
                    print_usage();
                    return 2;
                }
                local_config.database_path = argv[++i];
                continue;
            }
            const auto db_prefix = std::string_view{"--db="};
            if (arg.rfind(db_prefix, 0) == 0) {
                local_config.database_path = arg.substr(db_prefix.size());
                continue;
            }
            if (arg == "--previous-rx") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --previous-rx.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], local_config.previous_rx_total_bytes)) {
                    std::cerr << "Invalid value for --previous-rx.\n";
                    return 2;
                }
                upnp_config.previous_rx_total_bytes = local_config.previous_rx_total_bytes;
                local_config.has_previous_totals = true;
                continue;
            }
            if (arg == "--previous-tx") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --previous-tx.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], local_config.previous_tx_total_bytes)) {
                    std::cerr << "Invalid value for --previous-tx.\n";
                    return 2;
                }
                upnp_config.previous_tx_total_bytes = local_config.previous_tx_total_bytes;
                local_config.has_previous_totals = true;
                continue;
            }
            if (arg == "--elapsed-sec") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --elapsed-sec.\n";
                    print_usage();
                    return 2;
                }
                try {
                    local_config.elapsed_seconds = std::stod(argv[++i]);
                } catch (...) {
                    std::cerr << "Invalid value for --elapsed-sec.\n";
                    return 2;
                }
                if (local_config.elapsed_seconds <= 0.0) {
                    std::cerr << "Invalid value for --elapsed-sec.\n";
                    return 2;
                }
                snmp_config.elapsed_seconds = local_config.elapsed_seconds;
                upnp_config.elapsed_seconds = local_config.elapsed_seconds;
                attribution_config.elapsed_seconds = local_config.elapsed_seconds;
                continue;
            }
            if (arg == "--no-low-confidence") {
                bandwidth_config.include_low_confidence_sample = false;
                continue;
            }
            if (arg == "--top") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --top.\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_limit = 0;
                if (!parse_positive_u64(argv[++i], parsed_limit)) {
                    std::cerr << "Invalid top talker limit.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.top_talker_limit = parsed_limit;
                continue;
            }
            const auto top_prefix = std::string_view{"--top="};
            if (arg.rfind(top_prefix, 0) == 0) {
                std::size_t parsed_limit = 0;
                if (!parse_positive_u64(arg.substr(top_prefix.size()), parsed_limit)) {
                    std::cerr << "Invalid top talker limit.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.top_talker_limit = parsed_limit;
                continue;
            }
            if (arg == "--spike-rx") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --spike-rx.\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_bytes = 0;
                if (!parse_non_negative_u64(argv[++i], parsed_bytes)) {
                    std::cerr << "Invalid spike receive threshold.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.spike_rx_threshold_bytes = static_cast<std::uint64_t>(parsed_bytes);
                continue;
            }
            const auto spike_rx_prefix = std::string_view{"--spike-rx="};
            if (arg.rfind(spike_rx_prefix, 0) == 0) {
                std::size_t parsed_bytes = 0;
                if (!parse_non_negative_u64(arg.substr(spike_rx_prefix.size()), parsed_bytes)) {
                    std::cerr << "Invalid spike receive threshold.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.spike_rx_threshold_bytes = static_cast<std::uint64_t>(parsed_bytes);
                continue;
            }
            if (arg == "--upload") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --upload.\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_bytes = 0;
                if (!parse_non_negative_u64(argv[++i], parsed_bytes)) {
                    std::cerr << "Invalid upload threshold.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.unusual_upload_threshold_bytes = static_cast<std::uint64_t>(parsed_bytes);
                continue;
            }
            const auto upload_prefix = std::string_view{"--upload="};
            if (arg.rfind(upload_prefix, 0) == 0) {
                std::size_t parsed_bytes = 0;
                if (!parse_non_negative_u64(arg.substr(upload_prefix.size()), parsed_bytes)) {
                    std::cerr << "Invalid upload threshold.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.unusual_upload_threshold_bytes = static_cast<std::uint64_t>(parsed_bytes);
                continue;
            }
            if (arg == "--quiet-baseline") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --quiet-baseline.\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_bytes = 0;
                if (!parse_non_negative_u64(argv[++i], parsed_bytes)) {
                    std::cerr << "Invalid quiet baseline threshold.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.quiet_device_baseline_bytes = static_cast<std::uint64_t>(parsed_bytes);
                continue;
            }
            const auto quiet_baseline_prefix = std::string_view{"--quiet-baseline="};
            if (arg.rfind(quiet_baseline_prefix, 0) == 0) {
                std::size_t parsed_bytes = 0;
                if (!parse_non_negative_u64(arg.substr(quiet_baseline_prefix.size()), parsed_bytes)) {
                    std::cerr << "Invalid quiet baseline threshold.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.quiet_device_baseline_bytes = static_cast<std::uint64_t>(parsed_bytes);
                continue;
            }
            if (arg == "--quiet-active") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --quiet-active.\n";
                    print_usage();
                    return 2;
                }
                std::size_t parsed_bytes = 0;
                if (!parse_non_negative_u64(argv[++i], parsed_bytes)) {
                    std::cerr << "Invalid quiet-device active threshold.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.quiet_device_active_threshold_bytes = static_cast<std::uint64_t>(parsed_bytes);
                continue;
            }
            const auto quiet_active_prefix = std::string_view{"--quiet-active="};
            if (arg.rfind(quiet_active_prefix, 0) == 0) {
                std::size_t parsed_bytes = 0;
                if (!parse_non_negative_u64(arg.substr(quiet_active_prefix.size()), parsed_bytes)) {
                    std::cerr << "Invalid quiet-device active threshold.\n";
                    print_usage();
                    return 2;
                }
                anomaly_config.quiet_device_active_threshold_bytes = static_cast<std::uint64_t>(parsed_bytes);
                continue;
            }
            if (arg == "--mock-installed") {
                npcap_config.mock_mode = true;
                npcap_config.simulate_installed = true;
                continue;
            }
            if (arg == "--mock-missing") {
                npcap_config.mock_mode = true;
                npcap_config.simulate_installed = false;
                continue;
            }
            if (arg == "--mock-admin") {
                npcap_config.mock_mode = true;
                npcap_config.simulate_admin = true;
                continue;
            }
            if (arg == "--mock-user") {
                npcap_config.mock_mode = true;
                npcap_config.simulate_admin = false;
                continue;
            }
            if (arg == "--no-unsupported-adapter") {
                npcap_config.include_unsupported_adapter = false;
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }

        if (subcommand == "sources") {
            return print_bandwidth_sources_command();
        }
        if (subcommand == "sample") {
            return print_bandwidth_sample_command(bandwidth_config, mock_requested);
        }
        if (subcommand == "npcap") {
            return print_bandwidth_npcap_command(npcap_config);
        }
        if (subcommand == "local") {
            return print_bandwidth_local_command(local_config);
        }
        if (subcommand == "capture") {
            return print_bandwidth_capture_command(capture_config);
        }
        if (subcommand == "snmp") {
            return print_bandwidth_snmp_command(snmp_config);
        }
        if (subcommand == "upnp") {
            return print_bandwidth_upnp_command(upnp_config);
        }
        if (subcommand == "flows") {
            return print_bandwidth_flows_command(flow_config);
        }
        if (subcommand == "plugin") {
            return print_bandwidth_plugin_command(plugin_request);
        }
        if (subcommand == "limit") {
            return print_bandwidth_limit_command(limit_request);
        }
        if (subcommand == "openwrt") {
            return print_bandwidth_openwrt_command(openwrt_config);
        }
        if (subcommand == "attribute") {
            return print_bandwidth_attribute_command(attribution_config, mock_requested);
        }
        if (subcommand == "anomalies") {
            return print_bandwidth_anomalies_command(anomaly_config, mock_requested);
        }
        if (subcommand == "rollups") {
            return print_bandwidth_rollups_command(
                local_config.database_path,
                mock_requested,
                rollup_privacy_redact,
                rollup_retention_cutoff
            );
        }
        std::cerr << "Unknown bandwidth subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (cmd == "timeline") {
        netsentinel::storage::TimelineFilter filter;
        for (int i = 2; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--network") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --network.\n";
                    print_usage();
                    return 2;
                }
                filter.network_id = argv[++i];
                continue;
            }
            if (arg == "--device") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --device.\n";
                    print_usage();
                    return 2;
                }
                filter.device_id = argv[++i];
                continue;
            }
            if (arg == "--type") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --type.\n";
                    print_usage();
                    return 2;
                }
                filter.event_type = argv[++i];
                continue;
            }
            if (arg == "--from") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --from.\n";
                    print_usage();
                    return 2;
                }
                filter.from_utc = argv[++i];
                continue;
            }
            if (arg == "--to") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --to.\n";
                    print_usage();
                    return 2;
                }
                filter.to_utc = argv[++i];
                continue;
            }
            const auto network_prefix = std::string_view{"--network="};
            if (arg.rfind(network_prefix, 0) == 0) {
                filter.network_id = arg.substr(network_prefix.size());
                continue;
            }
            const auto device_prefix = std::string_view{"--device="};
            if (arg.rfind(device_prefix, 0) == 0) {
                filter.device_id = arg.substr(device_prefix.size());
                continue;
            }
            const auto type_prefix = std::string_view{"--type="};
            if (arg.rfind(type_prefix, 0) == 0) {
                filter.event_type = arg.substr(type_prefix.size());
                continue;
            }
            const auto from_prefix = std::string_view{"--from="};
            if (arg.rfind(from_prefix, 0) == 0) {
                filter.from_utc = arg.substr(from_prefix.size());
                continue;
            }
            const auto to_prefix = std::string_view{"--to="};
            if (arg.rfind(to_prefix, 0) == 0) {
                filter.to_utc = arg.substr(to_prefix.size());
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        return print_timeline_command(filter);
    }

    if (cmd == "presence") {
        if (argc < 3) {
            std::cerr << "Missing presence subcommand.\n";
            print_usage();
            return 2;
        }
        const std::string_view subcommand{argv[2]};
        netsentinel::storage::StorageConfig storage{};
        netsentinel::storage::DevicePresenceHistoryConfig presence_config{};
        netsentinel::alerts::PresenceNotificationConfig notify_config{};
        netsentinel::alerts::PresenceNotificationObservation notify_observation{};
        netsentinel::alerts::PresenceNotificationRule notify_rule{};
        bool notify_custom_observation = false;
        bool notify_custom_rule = false;
        bool apply_retention = false;
        bool mock_mode = false;
        for (int i = 3; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--mock") {
                mock_mode = true;
                notify_config.mock_mode = true;
                continue;
            }
            if (arg == "--opt-in") {
                notify_config.opt_in = true;
                continue;
            }
            if (arg == "--profile") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --profile.\n";
                    print_usage();
                    return 2;
                }
                notify_observation.profile = argv[++i];
                notify_rule.profile = notify_observation.profile;
                notify_custom_observation = true;
                notify_custom_rule = true;
                continue;
            }
            const auto presence_profile_prefix = std::string_view{"--profile="};
            if (arg.rfind(presence_profile_prefix, 0) == 0) {
                notify_observation.profile = arg.substr(presence_profile_prefix.size());
                notify_rule.profile = notify_observation.profile;
                notify_custom_observation = true;
                notify_custom_rule = true;
                continue;
            }
            if (arg == "--event") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --event.\n";
                    print_usage();
                    return 2;
                }
                notify_observation.event = argv[++i];
                notify_rule.event = notify_observation.event;
                notify_custom_observation = true;
                notify_custom_rule = true;
                continue;
            }
            const auto presence_event_prefix = std::string_view{"--event="};
            if (arg.rfind(presence_event_prefix, 0) == 0) {
                notify_observation.event = arg.substr(presence_event_prefix.size());
                notify_rule.event = notify_observation.event;
                notify_custom_observation = true;
                notify_custom_rule = true;
                continue;
            }
            if (arg == "--label") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --label.\n";
                    print_usage();
                    return 2;
                }
                notify_observation.device_label = argv[++i];
                notify_custom_observation = true;
                continue;
            }
            const auto presence_label_prefix = std::string_view{"--label="};
            if (arg.rfind(presence_label_prefix, 0) == 0) {
                notify_observation.device_label = arg.substr(presence_label_prefix.size());
                notify_custom_observation = true;
                continue;
            }
            if (arg == "--device-id") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --device-id.\n";
                    print_usage();
                    return 2;
                }
                notify_observation.device_id = argv[++i];
                notify_custom_observation = true;
                continue;
            }
            const auto presence_device_prefix = std::string_view{"--device-id="};
            if (arg.rfind(presence_device_prefix, 0) == 0) {
                notify_observation.device_id = arg.substr(presence_device_prefix.size());
                notify_custom_observation = true;
                continue;
            }
            if (arg == "--quiet-hours") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --quiet-hours.\n";
                    print_usage();
                    return 2;
                }
                const std::string value = argv[++i];
                const auto dash = value.find('-');
                if (dash == std::string::npos) {
                    std::cerr << "Invalid value for --quiet-hours. Use HH:MM-HH:MM.\n";
                    return 2;
                }
                notify_rule.quiet_start_local = value.substr(0, dash);
                notify_rule.quiet_end_local = value.substr(dash + 1);
                notify_custom_rule = true;
                continue;
            }
            const auto quiet_hours_prefix = std::string_view{"--quiet-hours="};
            if (arg.rfind(quiet_hours_prefix, 0) == 0) {
                const std::string value{arg.substr(quiet_hours_prefix.size())};
                const auto dash = value.find('-');
                if (dash == std::string::npos) {
                    std::cerr << "Invalid value for --quiet-hours. Use HH:MM-HH:MM.\n";
                    return 2;
                }
                notify_rule.quiet_start_local = value.substr(0, dash);
                notify_rule.quiet_end_local = value.substr(dash + 1);
                notify_custom_rule = true;
                continue;
            }
            if (arg == "--apply-retention") {
                apply_retention = true;
                continue;
            }
            if (arg == "--include-unlabeled") {
                presence_config.include_unlabeled_devices = true;
                continue;
            }
            if (arg == "--db") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --db.\n";
                    print_usage();
                    return 2;
                }
                storage.database_path = argv[++i];
                continue;
            }
            const auto db_prefix = std::string_view{"--db="};
            if (arg.rfind(db_prefix, 0) == 0) {
                storage.database_path = arg.substr(db_prefix.size());
                continue;
            }
            if (arg == "--network") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --network.\n";
                    print_usage();
                    return 2;
                }
                presence_config.network_id = argv[++i];
                continue;
            }
            const auto network_prefix = std::string_view{"--network="};
            if (arg.rfind(network_prefix, 0) == 0) {
                presence_config.network_id = arg.substr(network_prefix.size());
                continue;
            }
            if (arg == "--now") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --now.\n";
                    print_usage();
                    return 2;
                }
                presence_config.now_utc = argv[++i];
                notify_config.now_local = presence_config.now_utc;
                continue;
            }
            const auto now_prefix = std::string_view{"--now="};
            if (arg.rfind(now_prefix, 0) == 0) {
                presence_config.now_utc = arg.substr(now_prefix.size());
                notify_config.now_local = presence_config.now_utc;
                continue;
            }
            if (arg == "--retention-days") {
                if (i + 1 >= argc) {
                    std::cerr << "Missing value for --retention-days.\n";
                    print_usage();
                    return 2;
                }
                if (!parse_non_negative_u64(argv[++i], presence_config.retention_days)) {
                    std::cerr << "Invalid value for --retention-days.\n";
                    return 2;
                }
                continue;
            }
            const auto retention_days_prefix = std::string_view{"--retention-days="};
            if (arg.rfind(retention_days_prefix, 0) == 0) {
                if (!parse_non_negative_u64(arg.substr(retention_days_prefix.size()), presence_config.retention_days)) {
                    std::cerr << "Invalid value for --retention-days.\n";
                    return 2;
                }
                continue;
            }
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage();
            return 2;
        }
        if (subcommand == "history") {
            return print_presence_history_command(storage, presence_config, apply_retention, mock_mode);
        }
        if (subcommand == "notify") {
            notify_config.mock_mode = mock_mode;
            notify_config.routing.mock_mode = mock_mode;
            notify_config.routing.max_events_per_minute = 100;
            if (notify_custom_observation) {
                if (notify_observation.device_id.empty()) {
                    notify_observation.device_id = "presence-cli-device";
                }
                if (notify_observation.device_label.empty()) {
                    notify_observation.device_label = notify_observation.device_id;
                }
                notify_config.observations.push_back(notify_observation);
            }
            if (notify_custom_rule) {
                if (notify_rule.rule_id.empty()) {
                    notify_rule.rule_id = "presence-cli-rule";
                }
                notify_config.rules.push_back(notify_rule);
            }
            return print_presence_notify_command(notify_config);
        }
        std::cerr << "Unknown presence subcommand: " << subcommand << "\n";
        print_usage();
        return 2;
    }

    if (argc > 2) {
        std::cerr << "Unknown or misplaced arguments.\n";
        print_usage();
        return 2;
    }

    if (cmd == "--help" || cmd == "-h") {
        print_usage();
        return 0;
    }

    if (cmd == "--safety") {
        netsentinel::app::print_safety_contract(std::cout);
        return 0;
    }

    if (cmd == "--deps") {
        print_dependency_status();
        return 0;
    }

    if (cmd == "--smoke") {
        print_dependency_status();
        print_smoke_check();
        return 0;
    }

    std::cerr << "Unknown argument: " << cmd << "\n";
    print_usage();
    return 2;
}
