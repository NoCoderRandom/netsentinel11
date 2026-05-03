#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace netsentinel::hardening {

struct MockNetworkSimulatorConfig {
    std::string subnet = "192.168.50.0/24";
    std::size_t device_count = 32;
    std::uint32_t seed = 1337;
    bool include_cameras = true;
    bool include_iot = true;
};

struct MockNetworkDevice {
    std::string device_id;
    std::string ip_address;
    std::string mac_address;
    std::string hostname;
    std::string device_type;
    std::vector<int> open_ports{};
};

struct MockNetworkSimulation {
    bool success = false;
    std::string subnet;
    std::vector<MockNetworkDevice> devices{};
    std::string message;
};

struct PerformanceBenchmarkResult {
    std::string range;
    std::size_t host_count = 0;
    std::size_t simulated_device_count = 0;
    double estimated_scan_seconds = 0.0;
    std::string profile;
    std::string safety_note;
};

struct ParserFuzzResult {
    bool success = false;
    std::size_t cases_run = 0;
    std::size_t rejected = 0;
    std::size_t accepted = 0;
    std::vector<std::string> findings{};
};

struct HardeningReport {
    bool success = false;
    MockNetworkSimulation simulation{};
    std::vector<PerformanceBenchmarkResult> benchmarks{};
    ParserFuzzResult fuzz{};
    std::string privacy_review;
    std::string threat_model;
    std::string release_checklist;
    std::string roadmap;
    std::string message;
};

MockNetworkSimulation generate_mock_network(const MockNetworkSimulatorConfig& config);
std::vector<PerformanceBenchmarkResult> run_simulated_performance_benchmarks();
ParserFuzzResult run_parser_fuzz_smoke();
std::string generate_privacy_review();
std::string generate_threat_model();
std::string generate_release_checklist();
std::string generate_project_roadmap();
HardeningReport generate_hardening_report(const MockNetworkSimulatorConfig& config = {});
std::string hardening_report_markdown(const HardeningReport& report);

} // namespace netsentinel::hardening
