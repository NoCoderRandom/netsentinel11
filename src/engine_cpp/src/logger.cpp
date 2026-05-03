#include "netsentinel/engine/logger.h"

#include <array>
#include <chrono>
#include <ctime>
#include <iostream>
#include <mutex>
#include <sstream>

#if NETSENTINEL_HAVE_SPDLOG
#include <spdlog/spdlog.h>
#endif

namespace netsentinel::engine {

std::string to_string(LogLevel level) {
    switch (level) {
        case LogLevel::debug:
            return "DEBUG";
        case LogLevel::info:
            return "INFO";
        case LogLevel::warning:
            return "WARNING";
        case LogLevel::error:
            return "ERROR";
    }
    return "INFO";
}

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

Logger::Logger() = default;

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_level_ = level;
}

void Logger::log(LogLevel level, std::string_view component, std::string_view message) {
    if (static_cast<int>(level) < static_cast<int>(min_level_)) {
        return;
    }

#if NETSENTINEL_HAVE_SPDLOG
    if (level == LogLevel::debug) {
        spdlog::debug("[{}] {}", component, message);
    } else if (level == LogLevel::info) {
        spdlog::info("[{}] {}", component, message);
    } else if (level == LogLevel::warning) {
        spdlog::warn("[{}] {}", component, message);
    } else {
        spdlog::error("[{}] {}", component, message);
    }
#else
    std::array<char, 32> timestamp{};
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &seconds);
#else
    gmtime_r(&seconds, &tm);
#endif
    std::strftime(timestamp.data(), timestamp.size(), "%Y-%m-%dT%H:%M:%SZ", &tm);

    std::ostringstream out;
    out << "[" << timestamp.data() << "] " << to_string(level) << " [" << component << "] " << message << "\n";
    if (level == LogLevel::error || level == LogLevel::warning) {
        std::cerr << out.str();
    } else {
        std::cout << out.str();
    }
#endif
}

void Logger::debug(std::string_view component, std::string_view message) {
    log(LogLevel::debug, component, message);
}

void Logger::info(std::string_view component, std::string_view message) {
    log(LogLevel::info, component, message);
}

void Logger::warning(std::string_view component, std::string_view message) {
    log(LogLevel::warning, component, message);
}

void Logger::error(std::string_view component, std::string_view message) {
    log(LogLevel::error, component, message);
}

ScopedLogLevel::ScopedLogLevel(std::string_view component, std::string_view action, std::string_view result) {
    Logger::instance().info(component, action);
    component_ = std::string(component);
    action_ = std::string(action);
    result_ = std::string(result);
}

ScopedLogLevel::~ScopedLogLevel() {
    Logger::instance().info(component_, action_ + " -> " + result_);
}

} // namespace netsentinel::engine
