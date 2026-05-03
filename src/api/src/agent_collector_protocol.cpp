#include "netsentinel/api/agent_collector_protocol.h"

#include <algorithm>
#include <sstream>

namespace netsentinel::api {

namespace {

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        if (ch == '\\') {
            out += "\\\\";
        } else if (ch == '"') {
            out += "\\\"";
        } else if (ch == '\n') {
            out += "\\n";
        } else if (ch == '\r') {
            out += "\\r";
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::string json_string(const std::string& value) {
    return "\"" + json_escape(value) + "\"";
}

std::vector<std::string> security_controls() {
    return {
        "disabled-by-default",
        "mock-only-in-this-stage",
        "mutual-tls-required",
        "signed-pairing-token-required",
        "least-privilege-permissions",
        "no-background-persistence",
        "explicit-install-and-removal-required",
        "no-agent-network-listener-started-by-mock"
    };
}

bool contains_value(const std::vector<std::string>& values, const std::string& expected) {
    return std::find(values.begin(), values.end(), expected) != values.end();
}

std::string join_markdown_list(const std::vector<std::string>& values) {
    if (values.empty()) {
        return "- None\n";
    }
    std::string out;
    for (const auto& value : values) {
        out += "- " + value + "\n";
    }
    return out;
}

std::string json_string_array(const std::vector<std::string>& values) {
    std::string out = "[";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        out += json_string(values[i]);
    }
    out += "]";
    return out;
}

} // namespace

AgentCollectorValidation validate_agent_collector_config(const AgentCollectorConfig& config) {
    AgentCollectorValidation validation{};
    validation.enabled = config.enabled;
    validation.mock_only = config.mock_mode;
    validation.security_controls = security_controls();

    if (!config.enabled) {
        validation.ok = true;
        validation.message = "Optional agent collector protocol is disabled by default.";
        return validation;
    }

    if (!config.mock_mode) {
        validation.errors.push_back("real agent transport is not implemented in this stage; use mock mode");
    }
    if (config.transport != "mutual-tls") {
        validation.errors.push_back("transport must be mutual-tls");
    }
    if (config.server_certificate_fingerprint.empty()) {
        validation.errors.push_back("server certificate fingerprint is required for mutual authentication");
    }
    if (config.client_certificate_fingerprint.empty()) {
        validation.errors.push_back("client certificate fingerprint is required for mutual authentication");
    }
    if (config.pairing_token.empty() || config.pairing_token_signature.empty()) {
        validation.errors.push_back("signed pairing token and signature are required");
    }
    if (config.permissions.empty()) {
        validation.errors.push_back("at least one least-privilege permission is required");
    }
    if (contains_value(config.permissions, "admin")) {
        validation.errors.push_back("admin permission is not allowed for optional agents in this stage");
    }
    if (config.allow_background_persistence) {
        validation.errors.push_back("background persistence is not allowed; install/start must be explicit");
    }
    if (!config.explicit_install_required || !config.explicit_removal_supported) {
        validation.errors.push_back("agent lifecycle must document explicit install and removal");
    }

    validation.ok = validation.errors.empty();
    validation.message = validation.ok
        ? "Mock agent collector protocol is valid for local-only dry-run verification."
        : "Mock agent collector protocol validation failed.";
    return validation;
}

AgentCollectorSession run_mock_agent_collector_session(const AgentCollectorConfig& config) {
    AgentCollectorSession session{};
    session.collector_id = config.collector_id;
    session.agent_id = config.agent_id;
    session.agent_kind = config.agent_kind;
    session.validation = validate_agent_collector_config(config);

    if (!session.validation.ok) {
        session.accepted = false;
        session.message = "Mock agent collector rejected unsafe or incomplete configuration.";
        session.transcript = {
            "Loaded optional agent collector profile.",
            "Validation stopped before any socket, service, or persistence action.",
            "No network traffic was generated."
        };
        return session;
    }

    session.accepted = true;
    session.message = "Mock agent collector accepted using required mutual-TLS metadata and signed-pairing-token metadata.";
    session.transcript = {
        "Loaded optional agent collector profile.",
        "Verified mock requirement: no real network listener is started.",
        "Checked mutual-TLS server certificate fingerprint field.",
        "Checked mutual-TLS client certificate fingerprint field.",
        "Checked signed pairing token and signature fields.",
        "Checked least-privilege permissions.",
        "Checked explicit install/removal lifecycle requirements.",
        "Produced deterministic mock telemetry for UI and storage integration tests."
    };
    session.telemetry = {
        {"agent_id", config.agent_id, "", "identity"},
        {"agent_kind", config.agent_kind, "", "identity"},
        {"health", "ok", "", "mock"},
        {"cpu_load", "12", "percent", "mock"},
        {"memory_used", "384", "MB", "mock"},
        {"observed_interfaces", "1", "count", "mock"},
        {"allowed_permissions", std::to_string(config.permissions.size()), "count", "security"}
    };
    return session;
}

std::string agent_collector_session_json(const AgentCollectorSession& session) {
    std::string out = "{";
    out += "\"ok\":" + std::string(session.accepted ? "true" : "false") + ",";
    out += "\"collector_id\":" + json_string(session.collector_id) + ",";
    out += "\"agent_id\":" + json_string(session.agent_id) + ",";
    out += "\"agent_kind\":" + json_string(session.agent_kind) + ",";
    out += "\"message\":" + json_string(session.message) + ",";
    out += "\"security_controls\":" + json_string_array(session.validation.security_controls) + ",";
    out += "\"errors\":" + json_string_array(session.validation.errors) + ",";
    out += "\"telemetry\":[";
    for (std::size_t i = 0; i < session.telemetry.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        const auto& item = session.telemetry[i];
        out += "{";
        out += "\"key\":" + json_string(item.key) + ",";
        out += "\"value\":" + json_string(item.value) + ",";
        out += "\"unit\":" + json_string(item.unit) + ",";
        out += "\"sensitivity\":" + json_string(item.sensitivity);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string agent_collector_protocol_markdown(const AgentCollectorSession& session) {
    std::ostringstream out;
    out << "# Optional Agent Collector Protocol\n\n";
    out << "## Status\n\n";
    out << "- Accepted: " << (session.accepted ? "yes" : "no") << "\n";
    out << "- Collector ID: " << session.collector_id << "\n";
    out << "- Agent ID: " << session.agent_id << "\n";
    out << "- Agent kind: " << session.agent_kind << "\n";
    out << "- Message: " << session.message << "\n\n";
    out << "## Security controls\n\n";
    out << join_markdown_list(session.validation.security_controls) << "\n";
    out << "## Validation errors\n\n";
    out << join_markdown_list(session.validation.errors) << "\n";
    out << "## Mock transcript\n\n";
    out << join_markdown_list(session.transcript) << "\n";
    out << "## Mock telemetry\n\n";
    if (session.telemetry.empty()) {
        out << "- None\n";
    } else {
        for (const auto& item : session.telemetry) {
            out << "- " << item.key << ": " << item.value;
            if (!item.unit.empty()) {
                out << " " << item.unit;
            }
            out << " (" << item.sensitivity << ")\n";
        }
    }
    out << "\n## Limitations\n\n";
    out << "- This stage is protocol/specification and mock collector only.\n";
    out << "- No sockets are opened and no agent service is installed.\n";
    out << "- Real transport must use OS-backed TLS with mutual authentication.\n";
    out << "- Pairing tokens must be cryptographically signed before a production agent is accepted.\n";
    out << "- Agent installation, start, stop, and removal must always be explicit user actions.\n";
    return out.str();
}

} // namespace netsentinel::api
