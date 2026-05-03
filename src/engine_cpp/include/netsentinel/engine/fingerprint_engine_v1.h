#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct FingerprintRule {
    std::string rule_id;
    std::string device_type;
    std::string vendor;
    std::string model;
    int base_confidence = 20;
    int max_confidence = 95;
    int weight_oui_vendor = 24;
    int weight_hostname = 18;
    int weight_netbios = 18;
    int weight_mdns = 16;
    int weight_ssdp = 16;
    int weight_open_port = 12;
    int weight_user_label = 22;

    std::vector<std::string> match_oui_vendor_tokens;
    std::vector<std::string> match_hostname_tokens;
    std::vector<std::string> match_netbios_tokens;
    std::vector<std::string> match_mdns_tokens;
    std::vector<std::string> match_ssdp_tokens;
    std::vector<int> match_open_ports;
    std::vector<std::string> match_user_labels;
};

struct FingerprintSignalSet {
    std::optional<std::string> oui_vendor_hint;
    std::optional<std::string> hostname;
    std::optional<std::string> netbios_name;
    std::vector<std::string> mdns_hints;
    std::vector<std::string> ssdp_hints;
    std::vector<int> open_tcp_ports;
    std::vector<std::string> user_labels;
};

struct FingerprintGuess {
    std::string rule_id;
    std::string device_type;
    std::string vendor;
    std::string model;
    int confidence = 0;
    std::vector<std::string> evidence;
};

struct FingerprintEngineOptions {
    int min_confidence = 20;
};

Result<std::vector<FingerprintRule>> load_fingerprint_rules(const std::string& rules_path = {});
Result<std::vector<FingerprintGuess>> infer_fingerprints(
    const FingerprintSignalSet& signals,
    const std::vector<FingerprintRule>& rules,
    const FingerprintEngineOptions& options = {}
);

} // namespace netsentinel::engine
