#include "netsentinel/engine/arp_discovery.h"
#include "netsentinel/engine/icmp_discovery.h"
#include "netsentinel/engine/netbios_discovery.h"
#include "netsentinel/engine/mdns_discovery.h"
#include "netsentinel/engine/logger.h"
#include "netsentinel/engine/snmp_read_only_discovery.h"
#include "netsentinel/engine/netcore_boundary.h"
#include "netsentinel/engine/scan_contract.h"
#include "netsentinel/engine/tcp_discovery.h"
#include "netsentinel/engine/ssdp_discovery.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <string>
#include <thread>

namespace {

using ScanProgressKind = netsentinel::engine::ScanProgressKind;
using EngineTcpPortHint = netsentinel::engine::TcpPortHint;
using ArpDiscoveryEntry = netsentinel::engine::ArpDevice;
using IcmpPingHost = netsentinel::engine::IcmpPingHost;
using ProbeExecutionResult = netsentinel::engine::ProbeExecutionResult;
using ProbeResult = netsentinel::engine::ProbeResult;
using TcpPortHint = netsentinel::engine::TcpPortHint;

static constexpr int k_default_tcp_ports[] = {22, 80, 443, 445, 3389, 8080};

std::vector<std::string> default_probe_mix() {
    return {"arp", "icmp", "tcp", "netbios", "mdns", "ssdp", "snmp"};
}

bool is_probe_enabled(const std::vector<std::string>& probes, const std::string& name) {
    if (probes.empty()) {
        return true;
    }
    return std::find(probes.begin(), probes.end(), name) != probes.end();
}

std::vector<int> tcp_ports_for_profile(const std::vector<int>& configured) {
    if (!configured.empty()) {
        return configured;
    }
    std::vector<int> out;
    out.reserve(std::size(k_default_tcp_ports));
    for (const auto port : k_default_tcp_ports) {
        out.push_back(port);
    }
    return out;
}

std::size_t enabled_stage_count(const std::vector<std::string>& probes, bool run_snmp) {
    std::size_t count = 0;
    if (is_probe_enabled(probes, "arp")) {
        ++count;
    }
    if (is_probe_enabled(probes, "icmp")) {
        ++count;
    }
    if (is_probe_enabled(probes, "tcp")) {
        ++count;
    }
    if (is_probe_enabled(probes, "netbios")) {
        ++count;
    }
    if (is_probe_enabled(probes, "mdns")) {
        ++count;
    }
    if (is_probe_enabled(probes, "ssdp")) {
        ++count;
    }
    if (run_snmp && is_probe_enabled(probes, "snmp")) {
        ++count;
    }
    return count;
}

std::string format_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::system_clock::to_time_t(now);
    std::tm tm_snapshot;
#ifdef _WIN32
    gmtime_s(&tm_snapshot, &seconds);
#else
    gmtime_r(&seconds, &tm_snapshot);
#endif
    std::array<char, 32> buffer{};
    std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &tm_snapshot);
    return std::string(buffer.data());
}

void emit_progress(
    const netsentinel::engine::ScanProgressCallback& callback,
    const netsentinel::engine::ScanProgressEvent& event
) {
    if (callback) {
        callback(event);
    }
}

void emit_progress(
    const netsentinel::engine::ScanProgressCallback& callback,
    netsentinel::engine::ScanProgressKind kind,
    const std::string& stage,
    std::size_t stage_index,
    std::size_t stage_total,
    std::size_t current = 0,
    std::size_t total = 0,
    const std::string& target = "",
    const std::string& message = ""
) {
    emit_progress(callback, netsentinel::engine::ScanProgressEvent{
        kind,
        stage,
        stage_index,
        stage_total,
        current,
        total,
        target,
        message
    });
}

bool should_halt(
    const netsentinel::engine::ScanCancellation& cancellation,
    netsentinel::engine::ScanSession& session,
    const netsentinel::engine::ScanProgressCallback& callback
) {
    if (!cancellation.requested && !cancellation.pause_requested) {
        return false;
    }

    session.completed = false;
    session.ended_at_utc = format_timestamp();
    if (cancellation.requested) {
        session.status_text = "cancelled by user";
        emit_progress(
            callback,
            ScanProgressKind::cancelled,
            "orchestration",
            0,
            0,
            0,
            0,
            {},
            "scan requested to stop"
        );
    } else {
        session.status_text = "pause requested";
        emit_progress(
            callback,
            ScanProgressKind::paused,
            "orchestration",
            0,
            0,
            0,
            0,
            {},
            "scan paused safely; progress is safe to resume in a follow-up run"
        );
    }
    return true;
}

long long jitter_for_index(long long min_ms, long long max_ms, std::size_t index) {
    if (max_ms < min_ms) {
        return min_ms;
    }
    if (max_ms == min_ms) {
        return min_ms;
    }
    return min_ms + static_cast<long long>(index % static_cast<std::size_t>(max_ms - min_ms + 1));
}

netsentinel::engine::ProbeResult to_probe_result(
    const std::string& probe_name,
    const netsentinel::engine::ProbeExecutionResult& result,
    const std::string& target,
    const std::string& fallback_error
) {
    return netsentinel::engine::ProbeResult{
        .probe_name = probe_name,
        .target = target,
        .success = result.success,
        .response_time_ms = result.elapsed_ms,
        .message = result.details.empty() ? fallback_error : result.details,
        .error_code = result.timed_out ? "timeout" : (result.success ? "" : "error")
    };
}

EngineTcpPortHint build_mock_tcp_port_hint(const std::string& ip, int port) {
    int sum = static_cast<int>(ip.size() * 17 + port * 31);
    for (const char c : ip) {
        sum += static_cast<int>(static_cast<unsigned char>(c));
    }
    const bool open = (sum % 3) == 0;
    return EngineTcpPortHint{
        .port = port,
        .open = open,
        .timed_out = !open && (sum % 7) == 0,
        .error = false,
        .latency_ms = static_cast<long long>(sum % 20)
    };
}

netsentinel::engine::ProbeExecutionResult convert_error_to_probe(
    const std::string& target,
    const std::string& context,
    bool timeout
) {
    return netsentinel::engine::ProbeExecutionResult{
        .target = target,
        .success = false,
        .timed_out = timeout,
        .cancelled = false,
        .elapsed_ms = 0,
        .details = context
    };
}

} // namespace

namespace netsentinel::engine {

Result<NetworkScope> validate_scope(const NetworkScope& scope) {
    Logger::instance().debug("scan_contract", "validating scope");
    if (scope.cidr_or_range.empty()) {
        return Result<NetworkScope>::fail(
            ErrorCode::invalid_input,
            "empty network scope",
            "scope.cidr_or_range must be non-empty and safe"
        );
    }
    if (!validate_network_like(scope.cidr_or_range)) {
        return Result<NetworkScope>::fail(
            ErrorCode::invalid_input,
            "invalid network scope format",
            "scope must be a safe subnet-like value"
        );
    }
    return Result<NetworkScope>::ok(scope);
}

Result<std::vector<NetworkInterface>> enumerate_adapters(const ScanDependencies& dependencies) {
    Logger::instance().info("scan_contract", "enumerating adapters");
    if (!dependencies.permission_granted) {
        Logger::instance().warning("scan_contract", "adapter enumeration blocked by permissions");
        return Result<std::vector<NetworkInterface>>::fail(
            ErrorCode::permission_denied,
            "permission denied",
            "network-adapter enumeration requires local admin privileges in this environment"
        );
    }
    if (!dependencies.adapters_available) {
        Logger::instance().warning("scan_contract", "no adapters available");
        return Result<std::vector<NetworkInterface>>::fail(
            ErrorCode::adapter_unavailable,
            "no adapter found",
            "requested adapter source is unavailable or disabled"
        );
    }

    std::vector<NetworkInterface> adapters{
        NetworkInterface{
            .interface_id = "if-stub-001",
            .name = "Local Ethernet (stub)",
            .is_up = true
        }
    };
    return Result<std::vector<NetworkInterface>>::ok(std::move(adapters));
}

Result<ScanSession> run_dry_scan(const ScanProfile& profile, const ScanDependencies& dependencies, const ScanCancellation& cancellation) {
    Logger::instance().info("scan_contract", "starting dry run scan");

    const auto scope_result = validate_scope(profile.scope);
    if (!scope_result) {
        Logger::instance().error("scan_contract", "scan aborted: invalid scope");
        return Result<ScanSession>::fail(
            scope_result.error().code,
            scope_result.error().context,
            scope_result.error().details
        );
    }

    if (cancellation.requested) {
        Logger::instance().warning("scan_contract", "scan canceled before enumeration");
        return Result<ScanSession>::fail(
            ErrorCode::cancelled,
            "scan cancelled",
            "user requested cancellation before scan start"
        );
    }

    const auto adapter_result = enumerate_adapters(dependencies);
    if (!adapter_result) {
        Logger::instance().error("scan_contract", "scan aborted: adapters unavailable");
        return Result<ScanSession>::fail(
            adapter_result.error().code,
            adapter_result.error().context,
            adapter_result.error().details
        );
    }

    ScanSession session;
    session.session_id = "scan-stub-001";
    session.profile_name = profile.name;
    session.started_at_utc = format_timestamp();
    session.completed = true;
    session.status_text = "dry-run-complete";
    session.probe_results = {
        ProbeResult{
            .probe_name = "dry-run",
            .target = profile.scope.cidr_or_range,
            .success = true,
            .response_time_ms = 0,
            .message = "No network traffic performed in dry-run mode.",
            .error_code = ""
        }
    };
    Logger::instance().info("scan_contract", "dry run scan finished");
    return Result<ScanSession>::ok(std::move(session));
}

Result<ScanSession> run_scan_session(
    const ScanProfile& profile,
    const ScanDependencies& dependencies,
    const ScanCancellation& cancellation,
    const ScanSessionRunOptions& options
) {
    Logger::instance().info("scan_contract", "starting orchestrated scan session");

    if (options.max_qps == 0) {
        Logger::instance().error("scan_contract", "scan session request rejected: max_qps=0");
        return Result<ScanSession>::fail(
            ErrorCode::invalid_input,
            "invalid scan session options",
            "max_qps must be greater than zero"
        );
    }
    if (options.max_concurrency == 0) {
        Logger::instance().error("scan_contract", "scan session request rejected: max_concurrency=0");
        return Result<ScanSession>::fail(
            ErrorCode::invalid_input,
            "invalid scan session options",
            "max_concurrency must be greater than zero"
        );
    }
    if (options.jitter_ms_min < 0 || options.jitter_ms_max < 0 || options.jitter_ms_max < options.jitter_ms_min) {
        Logger::instance().error("scan_contract", "scan session request rejected: invalid jitter window");
        return Result<ScanSession>::fail(
            ErrorCode::invalid_input,
            "invalid scan session options",
            "jitter settings must be non-negative and min <= max"
        );
    }

    if (cancellation.requested || cancellation.pause_requested) {
        return Result<ScanSession>::fail(
            ErrorCode::cancelled,
            cancellation.requested ? "scan cancelled" : "scan paused",
            cancellation.requested
                ? "user requested cancellation before start"
                : "pause requested before start; no host traffic has been run"
        );
    }

    const auto scope_result = validate_scope(profile.scope);
    if (!scope_result) {
        Logger::instance().error("scan_contract", "scan session aborted: invalid scope");
        return Result<ScanSession>::fail(
            scope_result.error().code,
            scope_result.error().context,
            scope_result.error().details
        );
    }

    const auto adapter_result = enumerate_adapters(dependencies);
    if (!adapter_result) {
        Logger::instance().error("scan_contract", "scan session aborted: adapters unavailable");
        return Result<ScanSession>::fail(
            adapter_result.error().code,
            adapter_result.error().context,
            adapter_result.error().details
        );
    }

    const auto enabled_probes = options.enabled_probes.empty()
        ? default_probe_mix()
        : options.enabled_probes;
    const auto tcp_ports = tcp_ports_for_profile(options.tcp_port_hints);
    const bool run_arp = is_probe_enabled(enabled_probes, "arp");
    const bool run_icmp = is_probe_enabled(enabled_probes, "icmp");
    const bool run_tcp = is_probe_enabled(enabled_probes, "tcp");
    const bool run_netbios = is_probe_enabled(enabled_probes, "netbios");
    const bool run_mdns = is_probe_enabled(enabled_probes, "mdns");
    const bool run_ssdp = is_probe_enabled(enabled_probes, "ssdp");
    const bool run_snmp = !options.snmp_target.empty()
        && !options.snmp_community.empty()
        && is_probe_enabled(enabled_probes, "snmp");
    const std::size_t stage_total = 1 + enabled_stage_count(enabled_probes, run_snmp);
    const std::vector<int> active_tcp_ports = tcp_ports;

    if (!run_arp) {
        Logger::instance().error("scan_contract", "scan session aborted: ARP probe is required for discovery mode");
        return Result<ScanSession>::fail(
            ErrorCode::invalid_input,
            "invalid scan profile",
            "ARP probe must be enabled in profile"
        );
    }

    ScanSession session;
    session.session_id = "scan-session-001";
    session.profile_name = profile.name;
    session.started_at_utc = format_timestamp();
    session.ended_at_utc = session.started_at_utc;
    session.completed = false;
    session.status_text = "starting orchestration";
    std::size_t stage_index = 1;

    const auto callback = options.on_progress;
    emit_progress(
        callback,
        ScanProgressKind::started,
        "orchestration",
        1,
        stage_total,
        0,
        0,
        {},
        "scan session started"
    );

    emit_progress(
        callback,
        ScanProgressKind::stage_started,
        "adapter_check",
        stage_index,
        stage_total,
        0,
        0,
        {},
        "dependency pre-check succeeded"
    );
    emit_progress(
        callback,
        ScanProgressKind::stage_complete,
        "adapter_check",
        stage_index,
        stage_total,
        0,
        0,
        {},
        "using " + std::to_string(adapter_result.value().size()) + " adapter(s) as context"
    );
    ++stage_index;

    std::vector<ArpDiscoveryEntry> arp_entries;
    {
        const ArpDiscoveryRequest arp_request{
            .cidr_or_range = profile.scope.cidr_or_range,
            .max_host_count = 1024,
            .only_local = true,
            .mock_mode = options.mock_mode
        };

        emit_progress(
            callback,
            ScanProgressKind::stage_started,
            "arp",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "discovering ARP hosts in " + arp_request.cidr_or_range
        );

        const auto arp_devices = discover_arp_devices(arp_request);
        if (!arp_devices) {
            session.status_text = "arp stage failed";
            session.ended_at_utc = format_timestamp();
            emit_progress(
                callback,
                ScanProgressKind::failed,
                "arp",
                stage_index,
                stage_total,
                0,
                0,
                {},
                "ARP discovery failed"
            );
            return Result<ScanSession>::fail(
                arp_devices.error().code,
                arp_devices.error().context,
                arp_devices.error().details
            );
        }

        arp_entries = arp_devices.value();
        for (std::size_t i = 0; i < arp_entries.size(); ++i) {
            const auto& entry = arp_entries[i];
            session.probe_results.push_back(ProbeResult{
                .probe_name = "arp",
                .target = entry.ip_address,
                .success = true,
                .response_time_ms = entry.latency_ms,
                .message = "mac=" + entry.mac_address + "; adapter=" + entry.adapter_id,
                .error_code = ""
            });
            emit_progress(
                callback,
                ScanProgressKind::host_result,
                "arp",
                stage_index,
                stage_total,
                i + 1,
                arp_entries.size(),
                entry.ip_address,
                "ARP host discovered"
            );
        }
        emit_progress(
            callback,
            ScanProgressKind::stage_complete,
            "arp",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "ARP stage complete"
        );
        ++stage_index;
    }

    if (should_halt(cancellation, session, callback)) {
        return Result<ScanSession>::ok(std::move(session));
    }

    const std::size_t profile_timeout_ms = static_cast<std::size_t>(std::max(1000, profile.timeout_seconds * 1000));
    const unsigned int icmp_connect_ms = static_cast<unsigned int>(
        std::min<std::size_t>(500, std::max<std::size_t>(50, profile_timeout_ms / 10))
    );
    const unsigned int icmp_total_ms = static_cast<unsigned int>(
        std::min<std::size_t>(5000, std::max<std::size_t>(500, profile_timeout_ms / 2))
    );
    ProbeBoundaryConfig icmp_config{
        .connect_timeout_ms = icmp_connect_ms,
        .total_timeout_ms = icmp_total_ms,
        .max_qps = static_cast<unsigned int>(options.max_qps)
    };

    std::vector<IcmpPingHost> icmp_hosts;
    icmp_hosts.reserve(arp_entries.size());
    if (run_icmp) {
        emit_progress(
            callback,
            ScanProgressKind::stage_started,
            "icmp",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "running ICMP probes against ARP hosts"
        );

        for (std::size_t chunk = 0; chunk < arp_entries.size(); chunk += std::max<std::size_t>(1, options.max_concurrency)) {
            if (should_halt(cancellation, session, callback)) {
                return Result<ScanSession>::ok(std::move(session));
            }

            const std::size_t chunk_end = std::min(chunk + std::max<std::size_t>(1, options.max_concurrency), arp_entries.size());
            std::vector<std::future<std::pair<std::size_t, ProbeExecutionResult>>> futures;
            futures.reserve(chunk_end - chunk);

            for (std::size_t i = chunk; i < chunk_end; ++i) {
                const auto& host = arp_entries[i];
                const auto host_jitter = jitter_for_index(options.jitter_ms_min, options.jitter_ms_max, i);
                futures.push_back(std::async(std::launch::async, [&, i, host_jitter, target = host.ip_address]() {
                    if (host_jitter > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(host_jitter));
                    }
                    if (options.mock_mode) {
                        auto probe = run_stub_probe(target, icmp_config, false);
                        if (probe) {
                            return std::make_pair(i, probe.value());
                        }
                        return std::make_pair(
                            i,
                            convert_error_to_probe(
                                target,
                                probe.error().user_message,
                                probe.error().code == ErrorCode::timeout
                            )
                        );
                    }
                    auto probe = run_probe(target, icmp_config, false, false);
                    if (probe) {
                        return std::make_pair(i, probe.value());
                    }
                    return std::make_pair(
                        i,
                        convert_error_to_probe(
                            target,
                            probe.error().user_message,
                            probe.error().code == ErrorCode::timeout
                        )
                    );
                }));
            }

            for (auto& f : futures) {
                auto [index, result] = f.get();
                const auto& host = arp_entries[index];
                IcmpPingHost ping_host{
                    .ip_address = host.ip_address,
                    .ping_ok = result.success,
                    .ping_latency_ms = result.elapsed_ms,
                    .from_arp_cache = true,
                    .adapter_id = host.adapter_id
                };
                icmp_hosts.push_back(std::move(ping_host));
                session.probe_results.push_back(
                    to_probe_result("icmp", result, host.ip_address, "icmp probe returned no details")
                );
                emit_progress(
                    callback,
                    ScanProgressKind::host_result,
                    "icmp",
                    stage_index,
                    stage_total,
                    icmp_hosts.size(),
                    arp_entries.size(),
                    host.ip_address,
                    result.success ? "ping successful" : "ping failed"
                );
            }
        }

        if (!options.mock_mode) {
            emit_progress(
                callback,
                ScanProgressKind::stage_started,
                "icmp",
                stage_index,
                stage_total,
                0,
                0,
                {},
                "running supplemental ICMP CIDR sweep for hosts missing from ARP cache"
            );
            const auto cidr_ping_hosts = discover_icmp_hosts(
                profile.scope.cidr_or_range,
                false,
                std::max<std::size_t>(1, options.max_qps),
                false
            );
            if (cidr_ping_hosts) {
                for (const auto& host : cidr_ping_hosts.value()) {
                    if (!host.ping_ok) {
                        continue;
                    }
                    const auto duplicate = std::any_of(
                        icmp_hosts.begin(),
                        icmp_hosts.end(),
                        [&host](const IcmpPingHost& existing) {
                            return existing.ip_address == host.ip_address;
                        }
                    );
                    if (duplicate) {
                        continue;
                    }
                    icmp_hosts.push_back(host);
                    session.probe_results.push_back(ProbeResult{
                        .probe_name = "icmp-sweep",
                        .target = host.ip_address,
                        .success = true,
                        .response_time_ms = host.ping_latency_ms,
                        .message = host.from_arp_cache ? "supplemental ARP-backed ping successful" : "supplemental CIDR ping successful",
                        .error_code = ""
                    });
                    emit_progress(
                        callback,
                        ScanProgressKind::host_result,
                        "icmp",
                        stage_index,
                        stage_total,
                        icmp_hosts.size(),
                        cidr_ping_hosts.value().size(),
                        host.ip_address,
                        "supplemental ping successful"
                    );
                }
            } else {
                emit_progress(
                    callback,
                    ScanProgressKind::host_result,
                    "icmp",
                    stage_index,
                    stage_total,
                    0,
                    0,
                    {},
                    "supplemental ICMP CIDR sweep skipped: " + cidr_ping_hosts.error().user_message
                );
            }
        }

        emit_progress(
            callback,
            ScanProgressKind::stage_complete,
            "icmp",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "ICMP stage complete"
        );
        ++stage_index;
    } else {
        for (const auto& host : arp_entries) {
            icmp_hosts.push_back(IcmpPingHost{
                .ip_address = host.ip_address,
                .ping_ok = false,
                .ping_latency_ms = 0,
                .from_arp_cache = true,
                .adapter_id = host.adapter_id
            });
        }
    }

    if (should_halt(cancellation, session, callback)) {
        return Result<ScanSession>::ok(std::move(session));
    }

    if (run_tcp) {
        ProbeBoundaryConfig tcp_config{
            .connect_timeout_ms = static_cast<long long>(std::min<std::size_t>(250, profile_timeout_ms / 4)),
            .total_timeout_ms = static_cast<long long>(std::min<std::size_t>(1000, profile_timeout_ms / 2)),
            .max_qps = static_cast<unsigned int>(options.max_qps)
        };

        emit_progress(
            callback,
            ScanProgressKind::stage_started,
            "tcp",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "running TCP liveness checks"
        );

        struct TcpHostPortBatch {
            std::size_t host_index;
            std::vector<TcpPortHint> ports;
        };
        for (std::size_t chunk = 0; chunk < icmp_hosts.size(); chunk += std::max<std::size_t>(1, options.max_concurrency)) {
            if (should_halt(cancellation, session, callback)) {
                return Result<ScanSession>::ok(std::move(session));
            }

            const std::size_t chunk_end = std::min(chunk + std::max<std::size_t>(1, options.max_concurrency), icmp_hosts.size());
            std::vector<std::future<TcpHostPortBatch>> futures;
            futures.reserve(chunk_end - chunk);

            for (std::size_t i = chunk; i < chunk_end; ++i) {
                const auto& host = icmp_hosts[i];
                const auto host_jitter = jitter_for_index(options.jitter_ms_min, options.jitter_ms_max, i + 7);
                futures.push_back(std::async(std::launch::async, [&, i, host_jitter, target = host.ip_address]() {
                    if (host_jitter > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(host_jitter));
                    }
                    TcpHostPortBatch batch;
                    batch.host_index = i;

                    for (int port : active_tcp_ports) {
                        if (options.mock_mode) {
                            batch.ports.push_back(build_mock_tcp_port_hint(target, port));
                            continue;
                        }
                        auto probe = run_tcp_connect_probe(target, port, tcp_config, false, false);
                        if (!probe) {
                            batch.ports.push_back(TcpPortHint{
                                .port = port,
                                .open = false,
                                .timed_out = probe.error().code == ErrorCode::timeout,
                                .error = probe.error().code != ErrorCode::timeout,
                                .latency_ms = 0
                            });
                            continue;
                        }
                        batch.ports.push_back(TcpPortHint{
                            .port = port,
                            .open = probe.value().success,
                            .timed_out = probe.value().timed_out,
                            .error = false,
                            .latency_ms = probe.value().elapsed_ms
                        });
                    }
                    return batch;
                }));
            }

            for (auto& f : futures) {
                auto batch = f.get();
                const auto& host = icmp_hosts[batch.host_index];
                for (const auto& port : batch.ports) {
                    session.probe_results.push_back(ProbeResult{
                        .probe_name = std::string("tcp/") + std::to_string(port.port),
                        .target = host.ip_address,
                        .success = port.open,
                        .response_time_ms = port.latency_ms,
                        .message = port.timed_out ? "timeout" : (port.error ? "error" : "tested"),
                        .error_code = port.timed_out ? "timeout" : (port.error ? "error" : "")
                    });
                }
                emit_progress(
                    callback,
                    ScanProgressKind::host_result,
                    "tcp",
                    stage_index,
                    stage_total,
                    batch.host_index + 1,
                    icmp_hosts.size(),
                    host.ip_address,
                    "tcp ports tested"
                );
            }
        }

        emit_progress(
            callback,
            ScanProgressKind::stage_complete,
            "tcp",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "TCP stage complete"
        );
        ++stage_index;
    }

    if (should_halt(cancellation, session, callback)) {
        return Result<ScanSession>::ok(std::move(session));
    }

    if (run_netbios) {
        const netsentinel::engine::NetBiosDiscoveryConfig netbios_config{
            .timeout_ms = 500,
            .cache_ttl_ms = 5 * 60 * 1000,
            .cache_enabled = true,
            .mock_mode = options.mock_mode
        };
        emit_progress(
            callback,
            ScanProgressKind::stage_started,
            "netbios",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "discovering NetBIOS identities from ARP hosts"
        );

        std::size_t netbios_discovered = 0;
        for (std::size_t i = 0; i < arp_entries.size(); ++i) {
            const auto& host = arp_entries[i];
            const auto result = resolve_netbios_name_for_ip(host.ip_address, netbios_config);
            std::string message = "netbios unsupported";
            std::string status = "not-found";
            if (result) {
                if (result.value().resolved) {
                    ++netbios_discovered;
                    status = "found";
                    message = "name=" + result.value().device_name;
                    if (!result.value().workgroup.empty()) {
                        message += "; workgroup=" + result.value().workgroup;
                    }
                    message += "; source=" + result.value().source;
                } else {
                    message = "no netbios data returned";
                }
            } else {
                message = "error=" + result.error().context + "; details=" + result.error().details;
                Logger::instance().warning(
                    "scan_contract",
                    "netbios discovery failed for " + host.ip_address + ": " + result.error().user_message
                );
            }
            if (result && !result.value().resolved) {
                status = "not-found";
            }
            session.probe_results.push_back(ProbeResult{
                .probe_name = "netbios",
                .target = host.ip_address,
                .success = result && result.value().resolved,
                .response_time_ms = 0,
                .message = message,
                .error_code = status
            });
            emit_progress(
                callback,
                ScanProgressKind::host_result,
                "netbios",
                stage_index,
                stage_total,
                i + 1,
                arp_entries.size(),
                host.ip_address,
                message
            );
        }
        emit_progress(
            callback,
            ScanProgressKind::stage_complete,
            "netbios",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "NetBIOS stage complete, discovered " + std::to_string(netbios_discovered) + " names"
        );
        ++stage_index;

        if (should_halt(cancellation, session, callback)) {
            return Result<ScanSession>::ok(std::move(session));
        }
    }

    if (run_mdns) {
        const netsentinel::engine::MdnsDiscoveryConfig mdns_scan_config{
            .query_timeout_ms = 550,
            .response_wait_ms = 400,
            .max_services = 128,
            .mock_mode = options.mock_mode
        };
        emit_progress(
            callback,
            ScanProgressKind::stage_started,
            "mdns",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "discovering Bonjour/mDNS services"
        );
        const auto mdns_services = discover_mdns_services(mdns_scan_config);
        std::size_t mdns_count = 0;
        if (mdns_services) {
            for (const auto& service : mdns_services.value()) {
                ++mdns_count;
                const std::string target = service.service_instance.empty() ? service.target : service.service_instance;
                session.probe_results.push_back(ProbeResult{
                    .probe_name = "mdns",
                    .target = target,
                    .success = true,
                    .response_time_ms = service.ttl_ms,
                    .message = service.service_name + " [" + service.device_type_hint + "] via " + service.source + " " + service.details,
                    .error_code = "ttl-" + std::to_string(service.ttl_ms)
                });
                emit_progress(
                    callback,
                    ScanProgressKind::host_result,
                    "mdns",
                    stage_index,
                    stage_total,
                    mdns_count,
                    mdns_services.value().size(),
                    target,
                    service.service_name + " [" + service.device_type_hint + "]"
                );
            }
            emit_progress(
                callback,
                ScanProgressKind::stage_complete,
                "mdns",
                stage_index,
                stage_total,
                0,
                0,
                {},
                "mDNS stage complete, discovered " + std::to_string(mdns_count) + " services"
            );
        } else {
            emit_progress(
                callback,
                ScanProgressKind::failed,
                "mdns",
                stage_index,
                stage_total,
                0,
                0,
                {},
                "mDNS stage failed: " + mdns_services.error().context
            );
        }
        ++stage_index;
    }
    if (run_ssdp) {
        const netsentinel::engine::SsdpDiscoveryConfig ssdp_scan_config{
            .query_timeout_ms = 550,
            .response_wait_ms = 450,
            .max_devices = 128,
            .parse_description = true,
            .mock_mode = options.mock_mode
        };
        emit_progress(
            callback,
            ScanProgressKind::stage_started,
            "ssdp",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "discovering SSDP/UPnP devices"
        );
        const auto ssdp_devices = discover_ssdp_devices(ssdp_scan_config);
        std::size_t ssdp_count = 0;
        if (ssdp_devices) {
            for (const auto& device : ssdp_devices.value()) {
                ++ssdp_count;
                const std::string target = device.friendly_name.empty() ? device.location : device.friendly_name;
                session.probe_results.push_back(ProbeResult{
                    .probe_name = "ssdp",
                    .target = target,
                    .success = true,
                    .response_time_ms = device.ttl_ms,
                    .message = "type=" + (device.device_type.empty() ? "unknown" : device.device_type) +
                        " manufacturer=" + (device.manufacturer.empty() ? "unknown" : device.manufacturer) +
                        " model=" + (device.model_name.empty() ? "unknown" : device.model_name),
                    .error_code = "ttl-" + std::to_string(device.ttl_ms)
                });
                emit_progress(
                    callback,
                    ScanProgressKind::host_result,
                    "ssdp",
                    stage_index,
                    stage_total,
                    ssdp_count,
                    ssdp_devices.value().size(),
                    target,
                    device.device_type.empty() ? device.usn : device.device_type
                );
            }
            emit_progress(
                callback,
                ScanProgressKind::stage_complete,
                "ssdp",
                stage_index,
                stage_total,
                0,
                0,
                {},
                "SSDP/UPnP stage complete, discovered " + std::to_string(ssdp_count) + " devices"
            );
            ++stage_index;
        } else {
            emit_progress(
                callback,
                ScanProgressKind::failed,
                "ssdp",
                stage_index,
                stage_total,
                0,
                0,
                {},
                "SSDP stage failed: " + ssdp_devices.error().context
            );
        }
    }
    if (run_snmp) {
        const netsentinel::engine::SnmpReadOnlyHintConfig snmp_config{
            .target = options.snmp_target,
            .community = options.snmp_community,
            .version = options.snmp_version.empty() ? "2c" : options.snmp_version,
            .response_timeout_ms = 700,
            .mock_mode = options.mock_mode
        };
        emit_progress(
            callback,
            ScanProgressKind::stage_started,
            "snmp",
            stage_index,
            stage_total,
            0,
            0,
            {},
            "querying SNMP read-only system fields for " + options.snmp_target
        );

        const auto snmp_hints = discover_snmp_read_only_hints(snmp_config);
        std::size_t snmp_count = 0;
        if (snmp_hints) {
            for (const auto& hint : snmp_hints.value()) {
                ++snmp_count;
                session.probe_results.push_back(ProbeResult{
                    .probe_name = "snmp",
                    .target = hint.target,
                    .success = true,
                    .response_time_ms = hint.response_time_ms,
                    .message = "sysDescr=" + (hint.sys_descr.empty() ? "unknown" : hint.sys_descr)
                        + " sysName=" + (hint.sys_name.empty() ? "unknown" : hint.sys_name)
                        + " sysObjectID=" + (hint.sys_object_id.empty() ? "unknown" : hint.sys_object_id),
                    .error_code = "snmp-" + (hint.source.empty() ? "ok" : hint.source)
                });
                emit_progress(
                    callback,
                    ScanProgressKind::host_result,
                    "snmp",
                    stage_index,
                    stage_total,
                    snmp_count,
                    snmp_hints.value().size(),
                    hint.target,
                    "sysDescr=" + (hint.sys_descr.empty() ? "unknown" : hint.sys_descr)
                );
            }
            emit_progress(
                callback,
                ScanProgressKind::stage_complete,
                "snmp",
                stage_index,
                stage_total,
                0,
                0,
                {},
                "SNMP stage complete, discovered " + std::to_string(snmp_count) + " hint set(s)"
            );
            ++stage_index;
        } else {
            emit_progress(
                callback,
                ScanProgressKind::failed,
                "snmp",
                stage_index,
                stage_total,
                0,
                0,
                {},
                "SNMP stage failed: " + snmp_hints.error().context
            );
        }
    }

    if (should_halt(cancellation, session, callback)) {
        return Result<ScanSession>::ok(std::move(session));
    }

    session.completed = true;
    session.ended_at_utc = format_timestamp();
    session.status_text = "completed";
    emit_progress(
        callback,
        ScanProgressKind::completed,
        "orchestration",
        stage_total,
        stage_total,
        0,
        0,
        {},
        "scan session complete"
    );

    Logger::instance().info("scan_contract", "scan session finished");
    return Result<ScanSession>::ok(std::move(session));
}

} // namespace netsentinel::engine

