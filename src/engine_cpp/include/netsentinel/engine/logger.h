#pragma once

#include <array>
#include <cstdint>
#include <iomanip>
#include <ios>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace netsentinel::engine {

enum class LogLevel : std::uint8_t {
    debug = 0,
    info = 1,
    warning = 2,
    error = 3
};

std::string to_string(LogLevel level);

class Logger {
public:
    static Logger& instance();

    void set_level(LogLevel level);
    void log(LogLevel level, std::string_view component, std::string_view message);

    void debug(std::string_view component, std::string_view message);
    void info(std::string_view component, std::string_view message);
    void warning(std::string_view component, std::string_view message);
    void error(std::string_view component, std::string_view message);

private:
    Logger();
    LogLevel min_level_ = LogLevel::info;
    std::mutex mutex_;
};

class ScopedLogLevel {
public:
    ScopedLogLevel(std::string_view component, std::string_view action, std::string_view result);

    ~ScopedLogLevel();

private:
    std::string component_;
    std::string result_;
    std::string action_;
};

} // namespace netsentinel::engine
