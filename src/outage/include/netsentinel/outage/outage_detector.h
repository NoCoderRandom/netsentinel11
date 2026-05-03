#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace netsentinel::outage {

enum class OutageClass {
    clear = 0,
    gateway_failure,
    dns_failure,
    isp_failure,
    host_failure
};

struct OutageCheckConfig {
    bool mock_mode = true;
    std::string gateway_ip = "192.168.1.1";
    std::string dns_host = "8.8.8.8";
    std::string external_url = "https://example.com";
    std::string host_ip = "192.168.1.10";
    std::size_t timeout_ms = 2000;
};

struct OutageCheckResult {
    bool outage_detected = false;
    OutageClass classification = OutageClass::clear;
    std::string message;
};

struct OutageCheckOperationResult {
    bool success = false;
    bool persisted = false;
    OutageCheckResult result{};
    std::string message;
};

struct OutageTimelinePoint {
    std::string timestamp_utc{};
    std::string source{};
    std::string classification{};
    bool outage_detected = false;
    std::string details{};
};

const char* to_string(OutageClass cls);

OutageCheckOperationResult run_outage_check(const OutageCheckConfig& config);

std::vector<OutageTimelinePoint> read_outage_history(std::size_t max_entries);

} // namespace netsentinel::outage
