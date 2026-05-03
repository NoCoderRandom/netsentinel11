#include "netsentinel/engine/netcore_boundary.h"
#include "netsentinel/engine/logger.h"

#include "netsentinel/netcore/netcore_boundary.h"

#include <utility>

namespace netsentinel::engine {

namespace {

ProbeExecutionResult map_result(const ns_probe_result& source) {
    return {
        .target = source.target ? source.target : "",
        .success = source.success != 0,
        .timed_out = source.timed_out != 0,
        .cancelled = false,
        .elapsed_ms = source.elapsed_ms,
        .details = source.details ? source.details : ""
    };
}

Result<ProbeExecutionResult> run_probe_impl(
    const std::string& target,
    const ProbeBoundaryConfig& config,
    bool request_cancel,
    bool mock_mode,
    int(*fn)(const char*, const ns_timeout_config*, const ns_cancel_token*, ns_probe_result*)
) {
    Logger::instance().info("netcore_boundary", "running probe");

    if (config.max_qps == 0) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid probe boundary config",
            "max_qps must be non-zero"
        );
    }
    if (config.connect_timeout_ms < 0 || config.total_timeout_ms < 0) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid probe timeout config",
            "timeouts must be zero or positive"
        );
    }
    if (target.empty()) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid probe target",
            "target address must not be empty"
        );
    }
    ns_timeout_config c_config{
        .connect_timeout_ms = config.connect_timeout_ms,
        .total_timeout_ms = config.total_timeout_ms
    };
    ns_rate_limiter limiter{};
    if (ns_rate_limiter_init(&limiter, config.max_qps) != 0) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid probe boundary config",
            "max_qps must be non-zero"
        );
    }

    ns_cancel_token token{};
    ns_cancel_token_init(&token);
    if (request_cancel) {
        ns_cancel_token_request(&token);
    }
    const int rate_ok = ns_rate_limiter_acquire(&limiter);
    if (rate_ok == 1) {
        ns_rate_limiter_destroy(&limiter);
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::timeout,
            "probe rate limit exceeded",
            "rate limiter rejected probe request"
        );
    }
    if (rate_ok != 0) {
        ns_rate_limiter_destroy(&limiter);
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::internal,
            "probe rate limiter internal error",
            "probe boundary could not acquire limiter slot"
        );
    }

    ns_probe_result out_result{};
    const int status = fn(target.c_str(), &c_config, &token, &out_result);
    ns_rate_limiter_destroy(&limiter);
    if (status == 1) {
        ns_free_probe_result(&out_result);
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::cancelled,
            "probe cancelled",
            "cancel token requested before or during probe"
        );
    }
    if (status != 0) {
        ns_free_probe_result(&out_result);
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::internal,
            "probe failed",
            mock_mode ? "mock boundary returned non-zero" : "probe boundary returned non-zero"
        );
    }

    ProbeExecutionResult result = map_result(out_result);
    ns_free_probe_result(&out_result);
    return Result<ProbeExecutionResult>::ok(std::move(result));
}

} // namespace

Result<ProbeExecutionResult> run_probe(const std::string& target, const ProbeBoundaryConfig& config, bool request_cancel, bool mock_mode) {
    return run_probe_impl(
        target,
        config,
        request_cancel,
        mock_mode,
        mock_mode ? ns_ping_probe_stub : ns_ping_probe_ipv4
    );
}

Result<ProbeExecutionResult> run_stub_probe(const std::string& target, const ProbeBoundaryConfig& config, bool request_cancel) {
    return run_probe(target, config, request_cancel, true);
}

Result<ProbeExecutionResult> run_tcp_connect_probe(
    const std::string& target,
    int port,
    const ProbeBoundaryConfig& config,
    bool request_cancel,
    bool mock_mode
) {
    (void)mock_mode;
    if (port < 1 || port > 65535) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid tcp port",
            "port must be in range 1..65535"
        );
    }
    if (config.max_qps == 0) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid probe boundary config",
            "max_qps must be non-zero"
        );
    }
    if (config.connect_timeout_ms < 0 || config.total_timeout_ms < 0) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid probe timeout config",
            "timeouts must be zero or positive"
        );
    }
    if (target.empty()) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid probe target",
            "target address must not be empty"
        );
    }

    ns_timeout_config c_config{
        .connect_timeout_ms = config.connect_timeout_ms,
        .total_timeout_ms = config.total_timeout_ms
    };
    ns_rate_limiter limiter{};
    if (ns_rate_limiter_init(&limiter, config.max_qps) != 0) {
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::invalid_input,
            "invalid probe boundary config",
            "max_qps must be non-zero"
        );
    }

    ns_cancel_token token{};
    ns_cancel_token_init(&token);
    if (request_cancel) {
        ns_cancel_token_request(&token);
    }
    const int rate_ok = ns_rate_limiter_acquire(&limiter);
    if (rate_ok == 1) {
        ns_rate_limiter_destroy(&limiter);
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::timeout,
            "tcp probe rate limit exceeded",
            "rate limiter rejected tcp probe request"
        );
    }
    if (rate_ok != 0) {
        ns_rate_limiter_destroy(&limiter);
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::internal,
            "tcp probe rate limiter internal error",
            "tcp probe boundary could not acquire limiter slot"
        );
    }

    ns_probe_result out_result{};
    const int status = ns_tcp_connect_probe(target.c_str(), port, &c_config, &token, &out_result);
    ns_rate_limiter_destroy(&limiter);
    if (status == 1) {
        ns_free_probe_result(&out_result);
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::cancelled,
            "tcp probe cancelled",
            "cancel token requested before or during probe"
        );
    }
    if (status != 0) {
        ns_free_probe_result(&out_result);
        return Result<ProbeExecutionResult>::fail(
            ErrorCode::internal,
            "tcp probe failed",
            mock_mode ? "mock tcp probe returned non-zero" : "tcp probe boundary returned non-zero"
        );
    }

    ProbeExecutionResult result = map_result(out_result);
    ns_free_probe_result(&out_result);
    return Result<ProbeExecutionResult>::ok(std::move(result));
}

} // namespace netsentinel::engine
