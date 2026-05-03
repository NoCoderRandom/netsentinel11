#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace netsentinel::speedtest {

enum class SpeedTestCode {
    ok = 0,
    invalid_endpoint = 1,
    invalid_configuration = 2,
    mock_disabled = 3,
    history_failure = 4
};

struct SpeedTestConfig {
    bool mock_mode = true;
    bool enable_latency = true;
    bool enable_download = true;
    bool enable_upload = true;
    std::size_t sample_count = 4;
    std::size_t timeout_ms = 30000;
    std::size_t retention_entries = 64;
    std::string endpoint = "https://example.com/100MB.bin";
};

struct SpeedSample {
    double latency_ms = 0.0;
    double jitter_ms = 0.0;
    double download_mbps = 0.0;
    double upload_mbps = 0.0;
};

struct SpeedTestResult {
    SpeedSample sample{};
    std::size_t samples = 0;
    std::string endpoint{};
    std::string timestamp_utc{};
};

struct SpeedHistoryPoint {
    std::string timestamp_utc{};
    std::string endpoint{};
    double latency_ms = 0.0;
    double jitter_ms = 0.0;
    double download_mbps = 0.0;
    double upload_mbps = 0.0;
};

struct SpeedTestOperationResult {
    bool success = false;
    SpeedTestCode code = SpeedTestCode::invalid_configuration;
    std::string message{};
    bool rate_limited = false;
    SpeedTestResult result{};
};

const char* to_string(SpeedTestCode code);

SpeedTestOperationResult run_speed_test(const SpeedTestConfig& config);

std::vector<SpeedHistoryPoint> read_speed_history(std::size_t max_entries);

} // namespace netsentinel::speedtest
