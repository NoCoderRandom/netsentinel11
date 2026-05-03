#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace netsentinel::api {

struct SimulationDevice {
    std::string device_id;
    std::string hostname;
    std::string ip_address;
    std::string mac_address;
    std::string device_type;
    std::string owner_group;
    std::vector<std::string> discovery_methods{};
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_bytes = 0;
    bool security_review = false;
    bool guest = false;
};

struct SimulationStageResult {
    std::string stage_id;
    std::string title;
    bool success = false;
    int duration_ms = 0;
    std::string summary;
    std::vector<std::string> evidence{};
};

struct SimulationSuiteConfig {
    bool mock_mode = true;
    std::size_t max_runtime_ms = 2000;
    std::size_t expected_min_devices = 8;
};

struct SimulationSuiteResult {
    bool success = false;
    bool mock_mode = true;
    std::vector<SimulationDevice> devices{};
    std::vector<SimulationStageResult> stages{};
    std::vector<std::string> warnings{};
    std::vector<std::string> performance_targets{};
    std::string message;
};

SimulationSuiteResult run_end_to_end_simulation(const SimulationSuiteConfig& config = {});
std::string simulation_suite_json(const SimulationSuiteResult& result);
std::string simulation_suite_markdown(const SimulationSuiteResult& result);

} // namespace netsentinel::api
