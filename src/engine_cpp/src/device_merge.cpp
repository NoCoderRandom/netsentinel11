#include "netsentinel/engine/device_merge.h"
#include "netsentinel/engine/logger.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

std::string normalize_mac(std::string value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char ch : value) {
        if (std::isalnum(ch)) {
            out += static_cast<char>(std::toupper(ch));
        }
    }
    return out;
}

std::string normalize_hostname(std::string value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char ch : value) {
        if (!std::isspace(ch)) {
            out += static_cast<char>(std::tolower(ch));
        }
    }
    return out;
}

std::string sanitize_id_token(std::string value) {
    std::string out;
    for (const unsigned char ch : value) {
        if (std::isalnum(ch) || ch == '-') {
            out += static_cast<char>(std::tolower(ch));
        }
    }
    if (out.empty()) {
        return "unknown";
    }
    return out;
}

bool has_ip(const netsentinel::engine::DeviceIdentity& device, const std::string& ip) {
    return std::find(device.ipv4_addresses.begin(), device.ipv4_addresses.end(), ip) != device.ipv4_addresses.end();
}

void append_ip_once(netsentinel::engine::DeviceIdentity& device, const std::string& ip) {
    if (!ip.empty() && !has_ip(device, ip)) {
        device.ipv4_addresses.push_back(ip);
    }
}

void add_warning_once(
    std::vector<std::string>& warnings,
    std::unordered_set<std::string>& dedupe,
    const std::string& key,
    const std::string& message
) {
    if (dedupe.find(key) == dedupe.end()) {
        dedupe.insert(key);
        warnings.push_back(message);
    }
}

int clamp_confidence(int value, int min_value, int max_value) {
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

std::string make_identity_id(const netsentinel::engine::DeviceObservation& observation, std::size_t index, bool duplicate_mac) {
    if (observation.mac_address && duplicate_mac) {
        std::ostringstream oss;
        oss << "device-mac-" << normalize_mac(*observation.mac_address);
        oss << "-ip-" << sanitize_id_token(observation.ip_address);
        oss << "-" << index;
        return oss.str();
    }
    if (observation.mac_address && !normalize_mac(*observation.mac_address).empty()) {
        return "device-mac-" + normalize_mac(*observation.mac_address);
    }
    if (observation.hostname && !normalize_hostname(*observation.hostname).empty()) {
        return "device-host-" + sanitize_id_token(*observation.hostname);
    }
    if (observation.netbios_name && !normalize_hostname(*observation.netbios_name).empty()) {
        return "device-netbios-" + sanitize_id_token(*observation.netbios_name);
    }
    if (!observation.ip_address.empty()) {
        return "device-ip-" + sanitize_id_token(observation.ip_address);
    }
    return "device-observation-" + std::to_string(index);
}

std::string resolve_vendor_hint(
    const netsentinel::engine::DeviceObservation& observation,
    const std::vector<netsentinel::engine::OUIRecord>& oui_catalog
) {
    if (!observation.mac_address) {
        return {};
    }
    const auto vendor = netsentinel::engine::lookup_vendor_by_mac(*observation.mac_address, oui_catalog);
    if (!netsentinel::engine::is_known_vendor(vendor)) {
        return {};
    }
    return vendor;
}

void apply_vendor_hint_if_present(
    netsentinel::engine::DeviceIdentity& identity,
    const std::vector<netsentinel::engine::OUIRecord>& oui_catalog
) {
    const auto& mac = identity.mac_address;
    if (!mac) {
        return;
    }
    const auto vendor = netsentinel::engine::lookup_vendor_by_mac(*mac, oui_catalog);
    if (!netsentinel::engine::is_known_vendor(vendor)) {
        return;
    }
    if (!identity.vendor_hint || netsentinel::engine::normalize_oui_vendor_name(*identity.vendor_hint) != vendor) {
        identity.vendor_hint = vendor;
    }
}

std::string resolve_hostname_source(
    const netsentinel::engine::DeviceObservation& observation,
    const std::string& fallback
) {
    if (!observation.hostname_source.empty()) {
        return observation.hostname_source;
    }
    return fallback;
}

int resolve_hostname_confidence(const netsentinel::engine::DeviceObservation& observation, int fallback, int min_confidence, int max_confidence) {
    const int source_confidence = observation.hostname_confidence > 0 ? observation.hostname_confidence : fallback;
    return clamp_confidence(source_confidence, min_confidence, max_confidence);
}

std::string resolve_netbios_source(
    const netsentinel::engine::DeviceObservation& observation,
    const std::string& fallback
) {
    if (!observation.netbios_source.empty()) {
        return observation.netbios_source;
    }
    return fallback;
}

int resolve_netbios_confidence(const netsentinel::engine::DeviceObservation& observation, int fallback, int min_confidence, int max_confidence) {
    const int source_confidence = observation.netbios_confidence > 0 ? observation.netbios_confidence : fallback;
    return clamp_confidence(source_confidence, min_confidence, max_confidence);
}

void apply_hostname_if_present(
    netsentinel::engine::DeviceIdentity& identity,
    const netsentinel::engine::DeviceObservation& observation,
    const netsentinel::engine::DeviceMergePolicy& policy
) {
    if (!observation.hostname) {
        return;
    }
    const auto source = resolve_hostname_source(observation, "hostname-observation");
    const int confidence = resolve_hostname_confidence(
        observation,
        policy.base_confidence_match_hostname,
        policy.min_confidence,
        policy.max_confidence
    );
    if (identity.hostname.empty()) {
        identity.hostname = *observation.hostname;
        identity.hostname_source = source;
        identity.hostname_confidence = confidence;
        return;
    }
    const auto normalized_existing = normalize_hostname(identity.hostname);
    const auto normalized_new = normalize_hostname(*observation.hostname);
    if (normalized_existing == normalized_new && identity.hostname_source.empty()) {
        identity.hostname_source = source;
        identity.hostname_confidence = confidence;
    }
    if (normalized_existing == normalized_new && confidence > identity.hostname_confidence) {
        identity.hostname_source = source;
        identity.hostname_confidence = confidence;
    }
}

void apply_netbios_if_present(
    netsentinel::engine::DeviceIdentity& identity,
    const netsentinel::engine::DeviceObservation& observation,
    const netsentinel::engine::DeviceMergePolicy& policy
) {
    if (!observation.netbios_name) {
        return;
    }
    const auto source = resolve_netbios_source(observation, "netbios-observation");
    const int confidence = resolve_netbios_confidence(
        observation,
        policy.base_confidence_match_netbios,
        policy.min_confidence,
        policy.max_confidence
    );
    identity.netbios_name = observation.netbios_name;
    identity.netbios_workgroup = observation.netbios_workgroup;
    identity.netbios_source = source;
    identity.netbios_confidence = confidence;
    if (identity.hostname.empty()) {
        identity.hostname = *observation.netbios_name;
        identity.hostname_source = source;
        identity.hostname_confidence = confidence;
    }
}

void update_map(
    std::unordered_map<std::string, std::size_t>& map,
    const std::string& key,
    std::size_t index
) {
    if (!key.empty()) {
        map[key] = index;
    }
}

std::string pick_mac_key(const netsentinel::engine::DeviceIdentity& identity) {
    if (!identity.mac_address || identity.mac_address->empty()) {
        return {};
    }
    return normalize_mac(*identity.mac_address);
}

} // namespace

namespace netsentinel::engine {

enum class MatchReason {
    none,
    mac,
    hostname,
    ip
};

Result<DeviceMergeDiff> merge_device_observations(
    const std::vector<DeviceIdentity>& prior_devices,
    const std::vector<DeviceObservation>& observations,
    const DeviceMergePolicy& policy,
    const std::vector<netsentinel::engine::OUIRecord>& oui_catalog
) {
    if (policy.min_confidence < 0 || policy.max_confidence < policy.min_confidence) {
        Logger::instance().error("device_merge", "merge request rejected: invalid confidence window");
        return Result<DeviceMergeDiff>::fail(
            ErrorCode::invalid_input,
            "invalid device merge policy",
            "min_confidence must be non-negative and <= max_confidence"
        );
    }

    DeviceMergeDiff out;
    out.current_devices = prior_devices;

    std::unordered_map<std::string, std::size_t> by_mac;
    std::unordered_map<std::string, std::size_t> by_hostname;
    std::unordered_map<std::string, std::size_t> by_ip;
    std::unordered_set<std::string> warning_keys;

    for (std::size_t i = 0; i < out.current_devices.size(); ++i) {
        const auto& device = out.current_devices[i];
        const auto mac_key = pick_mac_key(device);
        if (!mac_key.empty()) {
            if (by_mac.find(mac_key) != by_mac.end()) {
                add_warning_once(
                    out.warnings,
                    warning_keys,
                    "history-dup-mac-" + mac_key,
                    "Observation history has duplicate MAC " + mac_key + "; using latest match preference."
                );
            }
            by_mac[mac_key] = i;
        }
        const auto host_key = normalize_hostname(device.hostname);
        if (!host_key.empty()) {
            if (by_hostname.find(host_key) != by_hostname.end()) {
                add_warning_once(
                    out.warnings,
                    warning_keys,
                    "history-dup-host-" + host_key,
                    "Observation history has duplicate hostname " + host_key + "; using latest match preference."
                );
            }
            by_hostname[host_key] = i;
        }
        const auto netbios_key = normalize_hostname(device.netbios_name.value_or(""));
        if (!netbios_key.empty()) {
            if (by_hostname.find(netbios_key) != by_hostname.end()) {
                add_warning_once(
                    out.warnings,
                    warning_keys,
                    "history-dup-netbios-" + netbios_key,
                    "Observation history has duplicate netbios name " + netbios_key + "; using latest match preference."
                );
            }
            by_hostname[netbios_key] = i;
        }
        for (const auto& ip : device.ipv4_addresses) {
            if (!ip.empty()) {
                by_ip[ip] = i;
            }
        }
    }

    std::unordered_map<std::string, std::size_t> next_mac_counts;
    for (const auto& observation : observations) {
        if (!observation.mac_address) {
            continue;
        }
        const auto mac_key = normalize_mac(*observation.mac_address);
        if (!mac_key.empty()) {
            ++next_mac_counts[mac_key];
        }
    }

    for (std::size_t i = 0; i < observations.size(); ++i) {
        const auto& observation = observations[i];
        const auto normalized_mac = observation.mac_address ? normalize_mac(*observation.mac_address) : std::string();
        const auto normalized_hostname = observation.hostname ? normalize_hostname(*observation.hostname) : std::string();
        const auto normalized_netbios = normalize_hostname(observation.netbios_name.value_or(""));
        const auto duplicate_mac = !normalized_mac.empty() && next_mac_counts[normalized_mac] > 1;

        if (observation.ip_address.empty() && normalized_mac.empty() && normalized_hostname.empty() && normalized_netbios.empty()) {
            Logger::instance().warning(
                "device_merge",
                "observation had no IP, MAC, hostname, or netbios name and was skipped"
            );
            add_warning_once(
                out.warnings,
                warning_keys,
                "unresolved-" + std::to_string(i),
                "Skipped identifier-less observation because no IP, MAC, hostname, or netbios name was present."
            );
            continue;
        }

        std::size_t existing_index = 0;
        MatchReason reason = MatchReason::none;
        if (!normalized_mac.empty() && !duplicate_mac) {
            const auto it = by_mac.find(normalized_mac);
            if (it != by_mac.end()) {
                existing_index = it->second;
                reason = MatchReason::mac;
            }
        }
        if (reason == MatchReason::none && !normalized_hostname.empty()) {
            const auto it = by_hostname.find(normalized_hostname);
            if (it != by_hostname.end()) {
                existing_index = it->second;
                reason = MatchReason::hostname;
            }
        }
        if (reason == MatchReason::none && !normalized_netbios.empty()) {
            const auto it = by_hostname.find(normalized_netbios);
            if (it != by_hostname.end()) {
                existing_index = it->second;
                reason = MatchReason::hostname;
            }
        }
        if (reason == MatchReason::none && !observation.ip_address.empty()) {
            const auto it = by_ip.find(observation.ip_address);
            if (it != by_ip.end()) {
                existing_index = it->second;
                reason = MatchReason::ip;
            }
        }

        if (reason == MatchReason::none) {
            DeviceIdentity identity{};
            identity.device_id = make_identity_id(observation, i, duplicate_mac);
            if (observation.hostname) {
                identity.hostname = *observation.hostname;
                identity.hostname_source = resolve_hostname_source(observation, "hostname-observation");
                identity.hostname_confidence = resolve_hostname_confidence(
                    observation,
                    policy.base_confidence_match_hostname,
                    policy.min_confidence,
                    policy.max_confidence
                );
            }
            identity.mac_address = observation.mac_address;
            identity.netbios_name = observation.netbios_name;
            identity.netbios_workgroup = observation.netbios_workgroup;
            identity.netbios_source = observation.netbios_source;
            identity.netbios_confidence = observation.netbios_confidence;
            identity.confidence = clamp_confidence(policy.base_confidence_new_device, policy.min_confidence, policy.max_confidence);
            append_ip_once(identity, observation.ip_address);
            const auto vendor = resolve_vendor_hint(observation, oui_catalog);
            if (!vendor.empty()) {
                identity.vendor_hint = vendor;
            }

            if (duplicate_mac) {
                identity.confidence = clamp_confidence(
                    identity.confidence - policy.duplicate_mac_penalty,
                    policy.min_confidence,
                    policy.max_confidence
                );
                add_warning_once(
                    out.warnings,
                    warning_keys,
                    "duplicate-mac-" + normalized_mac,
                    "Duplicate MAC " + normalized_mac + " seen across active observations; identities were not merged."
                );
            }
            if (observation.randomized_mac) {
                identity.confidence = clamp_confidence(
                    identity.confidence - policy.random_mac_penalty,
                    policy.min_confidence,
                    policy.max_confidence
                );
                add_warning_once(
                    out.warnings,
                    warning_keys,
                    "random-mac-new-" + identity.device_id,
                    "Randomized MAC observed for " + identity.device_id + "; identity confidence reduced."
                );
            }
            if (observation.virtual_adapter) {
                identity.confidence = clamp_confidence(
                    identity.confidence - policy.virtual_adapter_penalty,
                    policy.min_confidence,
                    policy.max_confidence
                );
                add_warning_once(
                    out.warnings,
                    warning_keys,
                    "virtual-new-" + identity.device_id,
                    "Virtual adapter signal seen for " + identity.device_id + "; confidence reduced."
                );
            }
            if (!identity.hostname.empty()) {
                identity.confidence = clamp_confidence(
                    identity.confidence + policy.multi_signal_bonus,
                    policy.min_confidence,
                    policy.max_confidence
                );
            } else {
                apply_hostname_if_present(identity, observation, policy);
            }
            apply_netbios_if_present(identity, observation, policy);

            const std::size_t added_index = out.current_devices.size();
            out.current_devices.push_back(identity);
            out.added_devices.push_back(identity);

            update_map(by_mac, pick_mac_key(identity), added_index);
            update_map(by_hostname, normalize_hostname(identity.hostname), added_index);
            update_map(by_hostname, normalize_hostname(identity.netbios_name.value_or("")), added_index);
            for (const auto& ip : identity.ipv4_addresses) {
                update_map(by_ip, ip, added_index);
            }
            Logger::instance().info("device_merge", "added new identity " + identity.device_id);
            continue;
        }

        auto merged = out.current_devices[existing_index];
        const auto previous_confidence = merged.confidence;

        if (observation.hostname && merged.hostname != *observation.hostname) {
            if (merged.hostname.empty()) {
                merged.hostname = *observation.hostname;
                merged.confidence = clamp_confidence(
                    merged.confidence + policy.multi_signal_bonus,
                    policy.min_confidence,
                    policy.max_confidence
                );
            } else {
                if (normalized_hostname != normalize_hostname(merged.hostname)) {
                    add_warning_once(
                        out.warnings,
                        warning_keys,
                        "hostname-conflict-" + merged.device_id,
                        "Hostname changed for " + merged.device_id + "; keeping existing label for stability."
                    );
                }
            }
        }

        if (!observation.ip_address.empty() && !has_ip(merged, observation.ip_address)) {
            if (!merged.ipv4_addresses.empty()) {
                add_warning_once(
                    out.warnings,
                    warning_keys,
                    "ip-change-" + merged.device_id,
                    "IP change observed for identity " + merged.device_id + "."
                );
                merged.confidence = clamp_confidence(
                    merged.confidence - policy.ip_change_penalty,
                    policy.min_confidence,
                    policy.max_confidence
                );
            }
            append_ip_once(merged, observation.ip_address);
        }

        if (!observation.hostname && merged.hostname.empty()) {
            add_warning_once(
                out.warnings,
                warning_keys,
                "hostname-missing-" + merged.device_id,
                "No hostname was available for identity " + merged.device_id + " from this observation."
            );
        }
        if (!observation.netbios_name && merged.netbios_name.has_value() == false) {
            add_warning_once(
                out.warnings,
                warning_keys,
                "netbios-missing-" + merged.device_id,
                "No netbios name was available for identity " + merged.device_id + " from this observation."
            );
        }

        apply_hostname_if_present(merged, observation, policy);
        apply_netbios_if_present(merged, observation, policy);

        if (observation.mac_address) {
            const auto obs_mac = normalize_mac(*observation.mac_address);
            const auto current_mac = pick_mac_key(merged);
            if (current_mac.empty()) {
                merged.mac_address = observation.mac_address;
                merged.confidence = clamp_confidence(
                    merged.confidence + policy.history_alignment_bonus,
                    policy.min_confidence,
                    policy.max_confidence
                );
            } else if (current_mac != obs_mac) {
                add_warning_once(
                    out.warnings,
                    warning_keys,
                    "mac-conflict-" + merged.device_id,
                    "Conflicting MAC for identity " + merged.device_id + "; previous MAC retained."
                );
                merged.confidence = clamp_confidence(
                    merged.confidence - policy.duplicate_mac_penalty,
                    policy.min_confidence,
                    policy.max_confidence
                );
            }
            apply_vendor_hint_if_present(merged, oui_catalog);
        }

        int confidence_hint = 0;
        if (reason == MatchReason::mac) {
            confidence_hint = policy.base_confidence_match_mac / 2;
        } else if (reason == MatchReason::hostname) {
            confidence_hint = policy.base_confidence_match_hostname / 2;
        } else {
            confidence_hint = policy.base_confidence_match_ip / 2;
        }

        merged.confidence = clamp_confidence(
            merged.confidence + confidence_hint,
            policy.min_confidence,
            policy.max_confidence
        );

        if (observation.randomized_mac) {
            merged.confidence = clamp_confidence(
                merged.confidence - policy.random_mac_penalty,
                policy.min_confidence,
                policy.max_confidence
            );
            add_warning_once(
                out.warnings,
                warning_keys,
                "random-mac-" + merged.device_id,
                "Randomized MAC observed for known identity " + merged.device_id + "; confidence reduced."
            );
            Logger::instance().warning("device_merge", "randomized MAC signal for known identity");
        }
        if (observation.virtual_adapter) {
            merged.confidence = clamp_confidence(
                merged.confidence - policy.virtual_adapter_penalty,
                policy.min_confidence,
                policy.max_confidence
            );
            add_warning_once(
                out.warnings,
                warning_keys,
                "virtual-known-" + merged.device_id,
                "Virtual adapter signal for " + merged.device_id + "; confidence reduced."
            );
            Logger::instance().warning("device_merge", "virtual adapter signal for known identity");
        }

        if (merged.confidence < previous_confidence) {
            merged.confidence = previous_confidence;
        }
        if (merged.confidence == previous_confidence) {
            merged.confidence = clamp_confidence(
                merged.confidence + policy.history_alignment_bonus,
                policy.min_confidence,
                policy.max_confidence
            );
        }

        out.current_devices[existing_index] = merged;
        out.updated_devices.push_back(merged);

        if (merged.ipv4_addresses.size() > 0 && !merged.ipv4_addresses.back().empty()) {
            update_map(by_ip, merged.ipv4_addresses.back(), existing_index);
        }
        update_map(by_hostname, normalize_hostname(merged.hostname), existing_index);
        update_map(by_hostname, normalize_hostname(merged.netbios_name.value_or("")), existing_index);
    }

    if (out.current_devices.empty()) {
        Logger::instance().warning("device_merge", "no identifiers could be resolved into identities");
        return Result<DeviceMergeDiff>::fail(
            ErrorCode::invalid_input,
            "no resolvable identifiers",
            "all observations lacked IP, MAC, hostname, and netbios name"
        );
    }

    if (out.warnings.empty()) {
        Logger::instance().info("device_merge", "merge completed with no warnings");
    } else {
        Logger::instance().info("device_merge", "merge completed with " + std::to_string(out.warnings.size()) + " warning(s)");
    }
    return Result<DeviceMergeDiff>::ok(std::move(out));
}

} // namespace netsentinel::engine
