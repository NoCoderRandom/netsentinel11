#pragma once

#include <string>
#include <vector>

namespace netsentinel::api {

struct AgentCollectorConfig {
    bool enabled = false;
    bool mock_mode = true;
    std::string collector_id = "netsentinel-desktop";
    std::string agent_id = "mock-agent";
    std::string agent_kind = "raspberry-pi";
    std::string transport = "mutual-tls";
    std::string server_certificate_fingerprint;
    std::string client_certificate_fingerprint;
    std::string pairing_token;
    std::string pairing_token_signature;
    std::vector<std::string> permissions{"metrics:read", "inventory:read"};
    bool allow_background_persistence = false;
    bool explicit_install_required = true;
    bool explicit_removal_supported = true;
};

struct AgentCollectorValidation {
    bool ok = false;
    bool enabled = false;
    bool mock_only = true;
    std::string message;
    std::vector<std::string> errors{};
    std::vector<std::string> security_controls{};
};

struct AgentCollectorTelemetry {
    std::string key;
    std::string value;
    std::string unit;
    std::string sensitivity;
};

struct AgentCollectorSession {
    bool accepted = false;
    std::string collector_id;
    std::string agent_id;
    std::string agent_kind;
    std::string message;
    AgentCollectorValidation validation{};
    std::vector<std::string> transcript{};
    std::vector<AgentCollectorTelemetry> telemetry{};
};

AgentCollectorValidation validate_agent_collector_config(const AgentCollectorConfig& config);
AgentCollectorSession run_mock_agent_collector_session(const AgentCollectorConfig& config);
std::string agent_collector_session_json(const AgentCollectorSession& session);
std::string agent_collector_protocol_markdown(const AgentCollectorSession& session);

} // namespace netsentinel::api
