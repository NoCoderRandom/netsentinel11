#pragma once

#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct SnmpReadOnlyHintConfig {
    std::string target;
    std::string community;
    std::string version = "2c";
    long long response_timeout_ms = 700;
    bool mock_mode = false;
};

struct SnmpReadOnlyHint {
    std::string target;
    std::string sys_descr;
    std::string sys_name;
    std::string sys_object_id;
    long long response_time_ms = 0;
    std::string source;
    int confidence = 0;
    std::string details;
};

Result<std::vector<SnmpReadOnlyHint>> discover_snmp_read_only_hints(
    const SnmpReadOnlyHintConfig& config = {}
);

} // namespace netsentinel::engine
