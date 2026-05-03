#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct TcpPortHint {
    int port = 0;
    bool open = false;
    bool timed_out = false;
    bool error = false;
    long long latency_ms = 0;
};

struct TcpLivenessHostHint {
    std::string ip_address;
    bool icmp_up = false;
    long long icmp_latency_ms = 0;
    std::string adapter_id;
    std::vector<TcpPortHint> ports;
};

Result<std::vector<TcpLivenessHostHint>> discover_tcp_liveness(
    const std::string& cidr_or_range,
    bool mock_mode,
    bool request_cancel = false
);

} // namespace netsentinel::engine

