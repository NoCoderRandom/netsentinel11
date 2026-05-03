#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "netsentinel/engine/domain_model.h"
#include "netsentinel/engine/error_model.h"
#include "netsentinel/engine/oui_vendor.h"

namespace netsentinel::engine {

struct DeviceObservation {
    std::string ip_address;
    std::optional<std::string> mac_address;
    std::optional<std::string> hostname;
    std::string hostname_source;
    int hostname_confidence = 0;
    std::optional<std::string> netbios_name;
    std::string netbios_workgroup;
    std::string netbios_source;
    int netbios_confidence = 0;
    bool virtual_adapter = false;
    bool randomized_mac = false;
};

struct DeviceMergePolicy {
    int base_confidence_match_mac = 85;
    int base_confidence_match_hostname = 70;
    int base_confidence_match_netbios = 58;
    int base_confidence_match_ip = 58;
    int base_confidence_new_device = 64;

    int history_alignment_bonus = 8;
    int multi_signal_bonus = 5;

    int duplicate_mac_penalty = 25;
    int random_mac_penalty = 35;
    int virtual_adapter_penalty = 12;
    int ip_change_penalty = 10;

    int min_confidence = 0;
    int max_confidence = 100;
};

struct DeviceMergeDiff {
    std::vector<DeviceIdentity> current_devices;
    std::vector<DeviceIdentity> added_devices;
    std::vector<DeviceIdentity> updated_devices;
    std::vector<std::string> warnings;
};

Result<DeviceMergeDiff> merge_device_observations(
    const std::vector<DeviceIdentity>& prior_devices,
    const std::vector<DeviceObservation>& observations,
    const DeviceMergePolicy& policy = {},
    const std::vector<OUIRecord>& oui_catalog = {}
);

} // namespace netsentinel::engine
