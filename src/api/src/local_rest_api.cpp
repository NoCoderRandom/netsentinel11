#include "netsentinel/api/local_rest_api.h"

#include <algorithm>
#include <cctype>
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

std::vector<std::string> default_security_controls() {
    return {
        "disabled-by-default",
        "binds-to-127.0.0.1-by-default",
        "token-auth-required-when-enabled",
        "permission-scoped-endpoints",
        "csrf-token-required-for-state-changing-requests",
        "local-rate-limit-guard",
        "trigger-scan-is-dry-run-by-default",
        "no-remote-bind-without-future-explicit-hardening",
        "future-companion-pairing-must-remain-explicit-and-local"
    };
}

bool is_loopback_bind(const std::string& host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1";
}

std::string method_upper(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::toupper(ch));
        }
    );
    return value;
}

LocalRestApiResponse make_json_response(int status_code, const std::string& body) {
    return {
        .status_code = status_code,
        .content_type = "application/json",
        .body = body,
        .security_controls = default_security_controls()
    };
}

std::string json_error(const std::string& message) {
    return std::string{"{\"ok\":false,\"error\":"} + json_string(message) + "}";
}

bool has_permission(const LocalRestApiConfig& config, const std::string& permission) {
    return std::find(config.permissions.begin(), config.permissions.end(), permission) != config.permissions.end() ||
        std::find(config.permissions.begin(), config.permissions.end(), "admin") != config.permissions.end();
}

bool is_state_changing_method(const std::string& method) {
    return method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE";
}

bool request_has_valid_csrf(const LocalRestApiConfig& config, const LocalRestApiRequest& request, const std::string& method) {
    if (!config.require_csrf_for_state_change || !is_state_changing_method(method)) {
        return true;
    }
    return !config.csrf_token.empty() && request.csrf_token == config.csrf_token;
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

std::string networks_json(const LocalRestApiConfig& config) {
    const auto workspaces = netsentinel::storage::list_network_workspaces(config.storage);
    if (!workspaces) {
        return "{\"ok\":false,\"networks\":[],\"error\":\"workspace-list-failed\"}";
    }
    std::string out = "{\"ok\":true,\"networks\":[";
    for (std::size_t i = 0; i < workspaces.value().size(); ++i) {
        const auto& workspace = workspaces.value()[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"id\":" + json_string(workspace.workspace_id) + ",";
        out += "\"gateway_mac\":" + json_string(workspace.key.gateway_mac) + ",";
        out += "\"subnet\":" + json_string(workspace.key.subnet) + ",";
        out += "\"ssid\":" + json_string(workspace.key.ssid) + ",";
        out += "\"label\":" + json_string(workspace.key.user_label) + ",";
        out += "\"active\":" + std::string(workspace.active ? "true" : "false");
        out += "}";
    }
    out += "]}";
    return out;
}

std::string devices_json(const LocalRestApiConfig& config) {
    const auto devices = netsentinel::storage::list_inventory_records(config.storage, false);
    if (!devices) {
        return "{\"ok\":false,\"devices\":[],\"error\":\"device-list-failed\"}";
    }
    std::string out = "{\"ok\":true,\"devices\":[";
    for (std::size_t i = 0; i < devices.value().size(); ++i) {
        const auto& device = devices.value()[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"id\":" + json_string(device.device_id) + ",";
        out += "\"hostname\":" + json_string(device.hostname) + ",";
        out += "\"vendor\":" + json_string(device.vendor_hint) + ",";
        out += "\"type\":" + json_string(device.device_type) + ",";
        out += "\"importance\":" + std::to_string(device.importance);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string events_json(const LocalRestApiConfig& config) {
    const auto events = netsentinel::storage::list_timeline_records(config.storage);
    if (!events) {
        return "{\"ok\":false,\"events\":[],\"error\":\"event-list-failed\"}";
    }
    std::string out = "{\"ok\":true,\"events\":[";
    for (std::size_t i = 0; i < events.value().size(); ++i) {
        const auto& event = events.value()[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"device_id\":" + json_string(event.device_id) + ",";
        out += "\"network_id\":" + json_string(event.network_id) + ",";
        out += "\"type\":" + json_string(event.event_type) + ",";
        out += "\"severity\":" + std::to_string(event.severity);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string findings_json(const LocalRestApiConfig& config) {
    netsentinel::storage::DeviceSearchQuery query{};
    query.preset = "security-findings";
    const auto findings = netsentinel::storage::search_inventory_devices(query, config.storage);
    if (!findings) {
        return "{\"ok\":false,\"findings\":[],\"error\":\"finding-search-failed\"}";
    }
    std::string out = "{\"ok\":true,\"findings\":[";
    for (std::size_t i = 0; i < findings.value().size(); ++i) {
        const auto& finding = findings.value()[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"device_id\":" + json_string(finding.device.device_id) + ",";
        out += "\"network_id\":" + json_string(finding.network_id) + ",";
        out += "\"reasons\":" + json_string_array(finding.matched_reasons);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string scans_json(const LocalRestApiConfig& config) {
    const auto scans = netsentinel::storage::list_workspace_scan_history("", config.storage);
    if (!scans) {
        return "{\"ok\":false,\"scans\":[],\"error\":\"scan-history-failed\"}";
    }
    std::string out = "{\"ok\":true,\"scans\":[";
    for (std::size_t i = 0; i < scans.value().size(); ++i) {
        const auto& scan = scans.value()[i];
        if (i > 0) {
            out += ",";
        }
        out += "{";
        out += "\"workspace_id\":" + json_string(scan.workspace_id) + ",";
        out += "\"scan_id\":" + std::to_string(scan.scan_id) + ",";
        out += "\"status\":" + json_string(scan.status) + ",";
        out += "\"summary\":" + json_string(scan.summary);
        out += "}";
    }
    out += "]}";
    return out;
}

std::string speed_tests_json() {
    return "{\"ok\":true,\"speed_tests\":[],\"message\":\"speed-test history endpoint is available; persistent speed-test storage is planned for reporting stage\"}";
}

std::string pairing_guide_json() {
    return std::string{"{\"ok\":true,"}
        + "\"localhost_only\":true,"
        + "\"internet_exposure_allowed\":false,"
        + "\"required_controls\":["
        + "\"keep bind host on 127.0.0.1, localhost, or ::1\","
        + "\"use a short-lived bearer token\","
        + "\"require CSRF token for state-changing calls\","
        + "\"grant only needed permissions such as read or scan:trigger\","
        + "\"keep scan trigger dry-run until a local service explicitly owns orchestration\","
        + "\"do not open firewall ports or bind to 0.0.0.0 for companion pairing\""
        + "],"
        + "\"future_pairing_flow\":\"show one-time local code in the desktop app, exchange it over localhost, then store a scoped token locally\""
        + "}";
}

std::string trigger_scan_json(const LocalRestApiConfig& config) {
    if (config.dry_run) {
        return "{\"ok\":true,\"accepted\":true,\"dry_run\":true,\"message\":\"scan trigger accepted as dry-run; no network probe started\"}";
    }
    return "{\"ok\":false,\"accepted\":false,\"dry_run\":false,\"error\":\"non-dry-run scan trigger requires future service orchestration\"}";
}

} // namespace

LocalRestApiStatus validate_local_rest_api_config(const LocalRestApiConfig& config) {
    LocalRestApiStatus status{};
    status.enabled = config.enabled;
    status.localhost_only = is_loopback_bind(config.bind_host);
    status.token_required = true;
    status.csrf_required = config.require_csrf_for_state_change;
    status.rate_limit_enabled = config.rate_limit_per_minute > 0;
    status.permission_model_enabled = true;
    status.rate_limit_per_minute = config.rate_limit_per_minute;
    status.permissions = config.permissions;
    status.security_controls = default_security_controls();

    if (!config.enabled) {
        status.valid = true;
        status.message = "Local REST API is disabled by default.";
        return status;
    }
    if (!status.localhost_only) {
        status.valid = false;
        status.message = "Local REST API may only bind to 127.0.0.1, localhost, or ::1 in this stage.";
        return status;
    }
    if (config.auth_token.empty()) {
        status.valid = false;
        status.message = "Local REST API token auth is required when enabled.";
        return status;
    }
    if (config.permissions.empty()) {
        status.valid = false;
        status.message = "Local REST API requires at least one explicit permission scope.";
        return status;
    }
    status.valid = true;
    status.message = "Local REST API configuration is valid for localhost-only use.";
    return status;
}

LocalRestApiResponse handle_local_rest_api_request(
    const LocalRestApiConfig& config,
    const LocalRestApiRequest& request
) {
    const auto status = validate_local_rest_api_config(config);
    if (!status.enabled) {
        return make_json_response(503, json_error("local REST API is disabled"));
    }
    if (!status.valid) {
        return make_json_response(403, json_error(status.message));
    }
    if (request.bearer_token != config.auth_token) {
        return make_json_response(401, json_error("invalid or missing bearer token"));
    }
    if (config.rate_limit_per_minute > 0 && request.simulated_requests_in_window > config.rate_limit_per_minute) {
        return make_json_response(429, json_error("local REST API rate limit exceeded"));
    }

    const auto method = method_upper(request.method);
    if (method == "GET" && request.path == "/v1/networks") {
        if (!has_permission(config, "read")) {
            return make_json_response(403, json_error("missing read permission"));
        }
        return make_json_response(200, networks_json(config));
    }
    if (method == "GET" && request.path == "/v1/devices") {
        if (!has_permission(config, "read")) {
            return make_json_response(403, json_error("missing read permission"));
        }
        return make_json_response(200, devices_json(config));
    }
    if (method == "GET" && request.path == "/v1/scans") {
        if (!has_permission(config, "read")) {
            return make_json_response(403, json_error("missing read permission"));
        }
        return make_json_response(200, scans_json(config));
    }
    if (method == "GET" && request.path == "/v1/events") {
        if (!has_permission(config, "read")) {
            return make_json_response(403, json_error("missing read permission"));
        }
        return make_json_response(200, events_json(config));
    }
    if (method == "GET" && request.path == "/v1/findings") {
        if (!has_permission(config, "read")) {
            return make_json_response(403, json_error("missing read permission"));
        }
        return make_json_response(200, findings_json(config));
    }
    if (method == "GET" && request.path == "/v1/speed-tests") {
        if (!has_permission(config, "read")) {
            return make_json_response(403, json_error("missing read permission"));
        }
        return make_json_response(200, speed_tests_json());
    }
    if (method == "GET" && request.path == "/v1/pairing/guide") {
        if (!has_permission(config, "read")) {
            return make_json_response(403, json_error("missing read permission"));
        }
        return make_json_response(200, pairing_guide_json());
    }
    if (method == "POST" && request.path == "/v1/scans/trigger") {
        if (!has_permission(config, "scan:trigger")) {
            return make_json_response(403, json_error("missing scan:trigger permission"));
        }
        if (!request_has_valid_csrf(config, request, method)) {
            return make_json_response(403, json_error("missing or invalid CSRF token"));
        }
        return make_json_response(config.dry_run ? 202 : 409, trigger_scan_json(config));
    }

    return make_json_response(404, json_error("unknown local REST API endpoint"));
}

} // namespace netsentinel::api
