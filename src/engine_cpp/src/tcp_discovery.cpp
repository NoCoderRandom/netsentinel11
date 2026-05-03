#include "netsentinel/engine/tcp_discovery.h"
#include "netsentinel/engine/icmp_discovery.h"
#include "netsentinel/engine/logger.h"
#include "netsentinel/engine/netcore_boundary.h"

#include <cstddef>
#include <string>

namespace netsentinel::engine {

namespace {

TcpPortHint build_port_hint(int port, const ProbeExecutionResult& probe) {
    TcpPortHint hint{
        .port = port,
        .open = probe.success,
        .timed_out = probe.timed_out,
        .error = false,
        .latency_ms = probe.elapsed_ms
    };
    return hint;
}

TcpPortHint build_mock_port_hint(const std::string& ip, int port) {
    int sum = static_cast<int>(ip.size() * 17 + port * 31);
    for (char c : ip) {
        sum += static_cast<int>(static_cast<unsigned char>(c));
    }
    const bool open = (sum % 3) == 0;
    return TcpPortHint{
        .port = port,
        .open = open,
        .timed_out = !open && (sum % 7) == 0,
        .error = false,
        .latency_ms = static_cast<long long>(sum % 20)
    };
}

} // namespace

Result<std::vector<TcpLivenessHostHint>> discover_tcp_liveness(
    const std::string& cidr_or_range,
    bool mock_mode,
    bool request_cancel
) {
    Logger::instance().info("tcp_discovery", "starting tcp discovery");

    static const int k_ports[] = {22, 80, 443, 445, 3389, 8080};

    const auto icmp_hosts = discover_icmp_hosts(cidr_or_range, mock_mode, 16, request_cancel);
    if (!icmp_hosts) {
        return Result<std::vector<TcpLivenessHostHint>>::fail(
            icmp_hosts.error().code,
            "tcp discovery blocked by icmp prerequisite",
            "icmp sweep did not return results"
        );
    }

    std::vector<TcpLivenessHostHint> out;
    out.reserve(icmp_hosts.value().size());
    for (const auto& host : icmp_hosts.value()) {
        TcpLivenessHostHint entry{
            .ip_address = host.ip_address,
            .icmp_up = host.ping_ok,
            .icmp_latency_ms = host.ping_latency_ms,
            .adapter_id = host.adapter_id
        };

        for (int port : k_ports) {
            const ProbeBoundaryConfig config{
                .connect_timeout_ms = 250,
                .total_timeout_ms = 600,
                .max_qps = 16
            };
            if (mock_mode) {
                entry.ports.push_back(build_mock_port_hint(host.ip_address, port));
                continue;
            }

            const auto probe = run_tcp_connect_probe(host.ip_address, port, config, request_cancel, false);
            if (!probe) {
                entry.ports.push_back(TcpPortHint{
                    .port = port,
                    .open = false,
                    .timed_out = probe.error().code == ErrorCode::timeout,
                    .error = probe.error().code != ErrorCode::timeout,
                    .latency_ms = 0
                });
                continue;
            }
            entry.ports.push_back(build_port_hint(port, probe.value()));
        }

        out.push_back(std::move(entry));
    }

    Logger::instance().info("tcp_discovery", "completed tcp discovery");
    return Result<std::vector<TcpLivenessHostHint>>::ok(std::move(out));
}

} // namespace netsentinel::engine
