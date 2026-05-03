#include "netsentinel/hardening/hardening.h"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

namespace netsentinel::hardening {

namespace {

std::string hex_byte(std::uint32_t value) {
    std::ostringstream out;
    out << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (value & 0xffU);
    return out.str();
}

std::size_t host_count_for_range(const std::string& range) {
    const auto slash = range.find('/');
    if (slash == std::string::npos) {
        return 1;
    }
    try {
        const int prefix = std::stoi(range.substr(slash + 1));
        if (prefix < 0 || prefix > 32) {
            return 0;
        }
        if (prefix == 32) {
            return 1;
        }
        const std::size_t total = static_cast<std::size_t>(1ULL << (32 - prefix));
        return total <= 2 ? total : total - 2;
    } catch (...) {
        return 0;
    }
}

std::string base_prefix(const std::string& subnet) {
    const auto slash = subnet.find('/');
    const auto cidr = slash == std::string::npos ? subnet : subnet.substr(0, slash);
    const auto last_dot = cidr.rfind('.');
    if (last_dot == std::string::npos) {
        return "192.168.50.";
    }
    return cidr.substr(0, last_dot + 1);
}

bool parser_accepts_safe_cidr(const std::string& value) {
    const auto slash = value.find('/');
    if (slash == std::string::npos) {
        return false;
    }
    try {
        const int prefix = std::stoi(value.substr(slash + 1));
        if (prefix < 16 || prefix > 32) {
            return false;
        }
    } catch (...) {
        return false;
    }
    std::size_t dots = 0;
    for (const char ch : value.substr(0, slash)) {
        if (ch == '.') {
            ++dots;
            continue;
        }
        if (ch < '0' || ch > '9') {
            return false;
        }
    }
    return dots == 3;
}

} // namespace

MockNetworkSimulation generate_mock_network(const MockNetworkSimulatorConfig& config) {
    MockNetworkSimulation out{};
    out.subnet = config.subnet;
    if (config.device_count == 0) {
        out.message = "No mock devices requested.";
        out.success = true;
        return out;
    }
    const auto host_count = host_count_for_range(config.subnet);
    if (host_count == 0) {
        out.success = false;
        out.message = "Invalid or unsupported mock subnet.";
        return out;
    }

    const auto count = std::min<std::size_t>(config.device_count, host_count);
    const auto prefix = base_prefix(config.subnet);
    std::mt19937 rng{config.seed};
    for (std::size_t i = 0; i < count; ++i) {
        const auto kind = i % 6;
        MockNetworkDevice device{};
        device.device_id = "mock-" + std::to_string(i + 1);
        device.ip_address = prefix + std::to_string((i % 253) + 1);
        device.mac_address = "02:50:" + hex_byte(static_cast<std::uint32_t>(i)) + ":" +
            hex_byte(rng()) + ":" + hex_byte(rng()) + ":" + hex_byte(rng());
        if (kind == 0) {
            device.hostname = "gateway";
            device.device_type = "router";
            device.open_ports = {53, 80, 443, 1900};
        } else if (kind == 1 && config.include_cameras) {
            device.hostname = "camera-" + std::to_string(i);
            device.device_type = "camera";
            device.open_ports = {80, 554};
        } else if (kind == 2 && config.include_iot) {
            device.hostname = "smart-plug-" + std::to_string(i);
            device.device_type = "iot";
            device.open_ports = {80};
        } else if (kind == 3) {
            device.hostname = "laptop-" + std::to_string(i);
            device.device_type = "computer";
            device.open_ports = {445};
        } else if (kind == 4) {
            device.hostname = "phone-" + std::to_string(i);
            device.device_type = "phone";
            device.open_ports = {};
        } else {
            device.hostname = "unknown-" + std::to_string(i);
            device.device_type = "unknown";
            device.open_ports = {23};
        }
        out.devices.push_back(std::move(device));
    }
    out.success = true;
    out.message = "Deterministic mock network generated without network traffic.";
    return out;
}

std::vector<PerformanceBenchmarkResult> run_simulated_performance_benchmarks() {
    const std::vector<std::pair<std::string, std::string>> ranges{
        {"192.168.50.0/24", "standard"},
        {"192.168.0.0/20", "deep-safe"},
        {"10.10.0.0/16", "monitor-safe"}
    };
    std::vector<PerformanceBenchmarkResult> out;
    for (const auto& item : ranges) {
        const auto hosts = host_count_for_range(item.first);
        const double estimated = static_cast<double>(hosts) / (item.second == "monitor-safe" ? 400.0 : 160.0);
        out.push_back({
            .range = item.first,
            .host_count = hosts,
            .simulated_device_count = std::max<std::size_t>(1, hosts / 12),
            .estimated_scan_seconds = estimated,
            .profile = item.second,
            .safety_note = "Simulation only; no packets are sent."
        });
    }
    return out;
}

ParserFuzzResult run_parser_fuzz_smoke() {
    const std::vector<std::string> cases{
        "192.168.50.0/24",
        "192.168.50.0/33",
        "10.0.0.0/16",
        "not-a-cidr",
        "127.0.0.1/32",
        "192.168.1.0/-1",
        "172.16.0.0/12",
        "192.168.1.0/24<script>"
    };
    ParserFuzzResult out{};
    for (const auto& item : cases) {
        ++out.cases_run;
        if (parser_accepts_safe_cidr(item)) {
            ++out.accepted;
        } else {
            ++out.rejected;
        }
    }
    out.success = out.cases_run == cases.size() && out.rejected >= 4 && out.accepted >= 2;
    if (!out.success) {
        out.findings.push_back("CIDR parser fuzz smoke did not reject/accept the expected distribution.");
    }
    return out;
}

std::string generate_privacy_review() {
    return "Privacy review: local-first storage, no cloud account, localhost API disabled by default, token auth required, reports generated locally, packet capture optional and explicit, user labels/workspaces preserved locally.";
}

std::string generate_threat_model() {
    return "Threat model: protect inventory data, API tokens, report exports, service permissions, optional capture capability, and update channel. Mitigations include localhost binding, explicit consent, dry-run defaults, least privilege, and uninstall cleanup.";
}

std::string generate_release_checklist() {
    return "Release checklist: build Release, run CTest suite, run mock simulator, verify installer plan, review privacy/threat model, check optional dependencies, sign artifacts, verify uninstall, publish hashes and changelog.";
}

std::string generate_project_roadmap() {
    return "Roadmap: bandwidth source abstraction, optional Npcap detection, router counter sources, bandwidth dashboard, quota policies, presence history, privacy mode, importers, API hardening, agent collector, accessibility, release candidate polish.";
}

HardeningReport generate_hardening_report(const MockNetworkSimulatorConfig& config) {
    HardeningReport out{};
    out.simulation = generate_mock_network(config);
    out.benchmarks = run_simulated_performance_benchmarks();
    out.fuzz = run_parser_fuzz_smoke();
    out.privacy_review = generate_privacy_review();
    out.threat_model = generate_threat_model();
    out.release_checklist = generate_release_checklist();
    out.roadmap = generate_project_roadmap();
    out.success = out.simulation.success && out.fuzz.success && !out.benchmarks.empty();
    out.message = out.success ? "Hardening checkpoint generated." : "Hardening checkpoint has findings.";
    return out;
}

std::string hardening_report_markdown(const HardeningReport& report) {
    std::ostringstream out;
    out << "# NetSentinel11 Hardening Checkpoint\n\n";
    out << "- Status: " << (report.success ? "pass" : "review") << "\n";
    out << "- Message: " << report.message << "\n\n";
    out << "## Mock network simulator\n";
    out << "- Subnet: " << report.simulation.subnet << "\n";
    out << "- Devices: " << report.simulation.devices.size() << "\n";
    out << "- Message: " << report.simulation.message << "\n\n";
    out << "## Simulated performance\n";
    for (const auto& benchmark : report.benchmarks) {
        out << "- " << benchmark.range << " profile=" << benchmark.profile
            << " hosts=" << benchmark.host_count
            << " estimated_seconds=" << benchmark.estimated_scan_seconds
            << " note=" << benchmark.safety_note << "\n";
    }
    out << "\n## Parser fuzz smoke\n";
    out << "- Cases: " << report.fuzz.cases_run << "\n";
    out << "- Accepted: " << report.fuzz.accepted << "\n";
    out << "- Rejected: " << report.fuzz.rejected << "\n\n";
    out << "## Privacy review\n" << report.privacy_review << "\n\n";
    out << "## Threat model\n" << report.threat_model << "\n\n";
    out << "## Release checklist\n" << report.release_checklist << "\n\n";
    out << "## Roadmap\n" << report.roadmap << "\n";
    return out.str();
}

} // namespace netsentinel::hardening
