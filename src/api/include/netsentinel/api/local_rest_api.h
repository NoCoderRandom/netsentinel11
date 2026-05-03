#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "netsentinel/storage/storage.h"

namespace netsentinel::api {

struct LocalRestApiConfig {
    bool enabled = false;
    std::string bind_host = "127.0.0.1";
    std::uint16_t port = 8765;
    std::string auth_token;
    std::string csrf_token;
    std::vector<std::string> permissions{"read"};
    std::uint32_t rate_limit_per_minute = 60;
    bool require_csrf_for_state_change = true;
    bool dry_run = true;
    netsentinel::storage::StorageConfig storage{};
};

struct LocalRestApiRequest {
    std::string method = "GET";
    std::string path = "/";
    std::string bearer_token;
    std::string csrf_token;
    std::string client_id = "local-cli";
    std::uint32_t simulated_requests_in_window = 1;
    std::string body;
};

struct LocalRestApiResponse {
    int status_code = 500;
    std::string content_type = "application/json";
    std::string body = "{}";
    std::vector<std::string> security_controls{};
};

struct LocalRestApiStatus {
    bool valid = false;
    bool enabled = false;
    bool localhost_only = true;
    bool token_required = true;
    bool csrf_required = true;
    bool rate_limit_enabled = true;
    bool permission_model_enabled = true;
    std::uint32_t rate_limit_per_minute = 60;
    std::string message;
    std::vector<std::string> permissions{};
    std::vector<std::string> security_controls{};
};

LocalRestApiStatus validate_local_rest_api_config(const LocalRestApiConfig& config);
LocalRestApiResponse handle_local_rest_api_request(
    const LocalRestApiConfig& config,
    const LocalRestApiRequest& request
);

} // namespace netsentinel::api
