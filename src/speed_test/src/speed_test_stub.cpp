#include "netsentinel/speedtest/speed_test.h"

#include <array>
#include <cmath>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <random>
#include <string_view>
#include <vector>

#include <filesystem>

namespace netsentinel::speedtest {

namespace {

std::filesystem::path state_directory() {
    if (const char* override = std::getenv("NETSENTINEL_SPEED_TEST_STATE_DIR")) {
        if (*override != '\0') {
            return std::filesystem::path{override};
        }
    }
    const char* local = std::getenv("LOCALAPPDATA");
    if (local == nullptr || *local == '\0') {
        local = std::getenv("TEMP");
    }
    if (local == nullptr || *local == '\0') {
        local = ".";
    }
    return std::filesystem::path{local} / "NetSentinel11";
}

std::filesystem::path history_path() {
    return state_directory() / "speed-test-history.csv";
}

std::string now_utc_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto utc = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &utc);
#else
    gmtime_r(&utc, &tm);
#endif
    char out[32];
    std::strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string{out};
}

bool validate_config(const SpeedTestConfig& config, std::string& error) {
    if (config.endpoint.empty()) {
        error = "Endpoint is required.";
        return false;
    }
    if (!config.enable_latency && !config.enable_download && !config.enable_upload) {
        error = "At least one metric family must be enabled.";
        return false;
    }
    if (config.sample_count == 0) {
        error = "sample-count must be greater than zero.";
        return false;
    }
    if (config.retention_entries == 0) {
        error = "retention must be greater than zero.";
        return false;
    }
    if (config.endpoint.find("http://") != 0 && config.endpoint.find("https://") != 0) {
        error = "Endpoint must be a URL (http:// or https://).";
        return false;
    }
    return true;
}

std::size_t hash_text(std::string_view text) {
    std::size_t value = 2166136261u;
    for (char ch : text) {
        value ^= static_cast<std::size_t>(ch);
        value *= 16777619u;
    }
    return value;
}

double hash_noise(std::string_view text, std::size_t index, double range) {
    std::size_t seed = hash_text(text) + index * 1315423911u;
    std::mt19937_64 gen(seed);
    std::uniform_real_distribution<double> dist(0.0, range);
    return dist(gen);
}

void append_speed_history(const SpeedTestResult& result) {
    const auto path = history_path();
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out{path, std::ios::app};
    if (!out.is_open()) {
        return;
    }
    out << result.timestamp_utc << ","
        << result.endpoint << ","
        << result.sample.latency_ms << ","
        << result.sample.jitter_ms << ","
        << result.sample.download_mbps << ","
        << result.sample.upload_mbps << "\n";
}

bool prune_history(std::size_t max_entries) {
    const auto path = history_path();
    std::ifstream in{path};
    if (!in.is_open()) {
        return true;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    if (lines.size() <= max_entries) {
        return true;
    }
    const std::size_t keep_from = lines.size() - max_entries;
    std::ofstream out{path, std::ios::trunc};
    if (!out.is_open()) {
        return false;
    }
    for (std::size_t i = keep_from; i < lines.size(); ++i) {
        out << lines[i] << "\n";
    }
    return true;
}

void compute_speed_samples(
    bool include_latency,
    bool include_download,
    bool include_upload,
    std::size_t sample_count,
    const std::string& endpoint,
    SpeedSample& out_sample
) {
    std::vector<double> latencies;
    latencies.reserve(sample_count);
    for (std::size_t i = 0; i < sample_count; ++i) {
        latencies.push_back(include_latency ? (12.0 + hash_noise(endpoint, i, 60.0)) : 0.0);
    }
    double latency_sum = 0.0;
    for (const double value : latencies) {
        latency_sum += value;
    }
    double latency_avg = latencies.empty() ? 0.0 : latency_sum / static_cast<double>(latencies.size());

    double jitter_sum = 0.0;
    if (!latencies.empty()) {
        for (const double value : latencies) {
            const double delta = value - latency_avg;
            jitter_sum += delta * delta;
        }
        jitter_sum = std::sqrt(jitter_sum / static_cast<double>(latencies.size()));
    }
    out_sample.latency_ms = latency_avg;
    out_sample.jitter_ms = jitter_sum;

    if (include_download) {
        out_sample.download_mbps = 35.0 + std::fmod(hash_text(endpoint), 40) + hash_noise(endpoint, 100, 9.0);
    } else {
        out_sample.download_mbps = 0.0;
    }
    if (include_upload) {
        out_sample.upload_mbps = 14.0 + std::fmod(hash_text(endpoint), 20) + hash_noise(endpoint, 200, 6.0);
    } else {
        out_sample.upload_mbps = 0.0;
    }
}

} // namespace

const char* to_string(SpeedTestCode code) {
    switch (code) {
        case SpeedTestCode::ok:
            return "ok";
        case SpeedTestCode::invalid_endpoint:
            return "invalid_endpoint";
        case SpeedTestCode::invalid_configuration:
            return "invalid_configuration";
        case SpeedTestCode::mock_disabled:
            return "mock_disabled";
        case SpeedTestCode::history_failure:
            return "history_failure";
        default:
            return "unknown";
    }
}

SpeedTestOperationResult run_speed_test(const SpeedTestConfig& config) {
    std::string reason;
    if (!validate_config(config, reason)) {
        return SpeedTestOperationResult{
            .success = false,
            .code = SpeedTestCode::invalid_configuration,
            .message = reason
        };
    }

    if (!config.mock_mode) {
        return SpeedTestOperationResult{
            .success = false,
            .code = SpeedTestCode::mock_disabled,
            .message = "Non-mock execution is intentionally disabled in this stage; use --mock."
        };
    }

    SpeedTestResult result;
    result.endpoint = config.endpoint;
    result.samples = config.sample_count;
    result.timestamp_utc = now_utc_iso8601();
    compute_speed_samples(
        config.enable_latency,
        config.enable_download,
        config.enable_upload,
        config.sample_count,
        config.endpoint,
        result.sample
    );
    if (result.sample.latency_ms < 1.0 && config.enable_latency) {
        result.sample.latency_ms = 1.0;
    }

    append_speed_history(result);
    if (!prune_history(config.retention_entries)) {
        return SpeedTestOperationResult{
            .success = false,
            .code = SpeedTestCode::history_failure,
            .message = "Speed test executed but failed to prune history file."
        };
    }

    return SpeedTestOperationResult{
        .success = true,
        .code = SpeedTestCode::ok,
        .message = "mock-speed-test",
        .rate_limited = false,
        .result = result
    };
}

std::vector<SpeedHistoryPoint> read_speed_history(std::size_t max_entries) {
    std::vector<SpeedHistoryPoint> out;
    const auto path = history_path();
    std::ifstream in{path};
    if (!in.is_open()) {
        return out;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    if (lines.size() > max_entries) {
        const auto start = lines.size() - max_entries;
        lines.erase(lines.begin(), lines.begin() + static_cast<std::ptrdiff_t>(start));
    }

    for (const auto& item : lines) {
        SpeedHistoryPoint entry;
        std::array<std::string, 6> cols{};
        std::size_t index = 0;
        std::size_t cursor = 0;
        while (index < cols.size() && cursor <= item.size()) {
            const auto next = item.find(',', cursor);
            if (next == std::string::npos) {
                cols[index] = item.substr(cursor);
                break;
            }
            cols[index] = item.substr(cursor, next - cursor);
            cursor = next + 1;
            ++index;
        }
        if (index < (cols.size() - 1)) {
            continue;
        }
        try {
            entry.timestamp_utc = cols[0];
            entry.endpoint = cols[1];
            entry.latency_ms = std::stod(cols[2]);
            entry.jitter_ms = std::stod(cols[3]);
            entry.download_mbps = std::stod(cols[4]);
            entry.upload_mbps = std::stod(cols[5]);
            out.push_back(entry);
        } catch (...) {
            continue;
        }
    }
    return out;
}

} // namespace netsentinel::speedtest
