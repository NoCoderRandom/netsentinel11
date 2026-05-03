#include "netsentinel/engine/logger.h"
#include "netsentinel/engine/snmp_read_only_discovery.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

bool is_ipv4_like(std::string_view ip) {
    if (ip.empty()) {
        return false;
    }
    int octets[4] = {0, 0, 0, 0};
    int part = 0;
    int value = 0;
    bool seen_digit = false;
    for (std::size_t i = 0; i <= ip.size(); ++i) {
        if (i == ip.size() || ip[i] == '.') {
            if (!seen_digit) {
                return false;
            }
            if (part >= 4 || value > 255) {
                return false;
            }
            octets[part++] = value;
            value = 0;
            seen_digit = false;
            continue;
        }
        const char ch = ip[i];
        if (ch < '0' || ch > '9') {
            return false;
        }
        value = value * 10 + (ch - '0');
        seen_digit = true;
        if (value > 255) {
            return false;
        }
    }
    return part == 4;
}

std::vector<netsentinel::engine::SnmpReadOnlyHint> collect_mock(const std::string& target, const std::string& community) {
    (void)community;
    return {
        netsentinel::engine::SnmpReadOnlyHint{
            .target = target.empty() ? "127.0.0.1" : target,
            .sys_descr = "Mock SNMP device for deterministic tests",
            .sys_name = target.empty() ? "mock-host" : ("mock-" + target),
            .sys_object_id = "1.3.6.1.4.1.8072.3.2.10",
            .response_time_ms = 25,
            .source = "mock-snmp",
            .confidence = 74,
            .details = "mock mode: deterministic SNMP v1/v2c hints"
        }
    };
}

bool validate_version(const std::string& version) {
    return version == "1" || version == "v1" || version == "2c" || version == "v2c";
}

} // namespace

namespace netsentinel::engine {

Result<std::vector<SnmpReadOnlyHint>> discover_snmp_read_only_hints(const SnmpReadOnlyHintConfig& config) {
    Logger::instance().info("snmp", "starting SNMP read-only hints");

    if (config.target.empty()) {
        return Result<std::vector<SnmpReadOnlyHint>>::fail(
            ErrorCode::invalid_input,
            "invalid snmp request",
            "target must be provided"
        );
    }
    if (config.community.empty()) {
        return Result<std::vector<SnmpReadOnlyHint>>::fail(
            ErrorCode::invalid_input,
            "invalid snmp request",
            "community must be provided for live SNMP read-only query"
        );
    }
    if (!validate_version(config.version)) {
        return Result<std::vector<SnmpReadOnlyHint>>::fail(
            ErrorCode::invalid_input,
            "invalid snmp version",
            "supported versions are v1 and v2c"
        );
    }
    if (config.response_timeout_ms <= 0) {
        return Result<std::vector<SnmpReadOnlyHint>>::fail(
            ErrorCode::invalid_input,
            "invalid snmp timeout",
            "response_timeout_ms must be positive"
        );
    }

    if (!is_ipv4_like(config.target)) {
        return Result<std::vector<SnmpReadOnlyHint>>::fail(
            ErrorCode::invalid_input,
            "invalid snmp target",
            "target must be an IPv4 address"
        );
    }

    if (config.mock_mode) {
        return Result<std::vector<SnmpReadOnlyHint>>::ok(collect_mock(config.target, config.community));
    }

    return Result<std::vector<SnmpReadOnlyHint>>::fail(
        ErrorCode::internal,
        "snmp live mode unavailable",
        "live SNMP is optional and not enabled in this build. Use --mock for smoke verification."
    );
}

} // namespace netsentinel::engine
