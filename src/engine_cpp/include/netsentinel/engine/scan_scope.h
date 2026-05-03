#pragma once

#include <cstddef>
#include <string>

#include "netsentinel/engine/adapter_inventory.h"
#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct ScanScopeProposal {
    std::string scope_text;
    std::string gateway;
    std::string network_cidr;
    std::string first_host;
    std::string last_host;
    std::size_t estimated_host_count = 0;
    bool local_only = true;
    std::string warning;
};

Result<ScanScopeProposal> propose_scan_scope_from_adapter(const AdapterInventoryEntry& adapter, std::size_t max_host_count = 2048);
Result<ScanScopeProposal> propose_scan_scope_from_custom_cidr(const std::string& cidr_or_range, bool allow_non_local, bool confirmed, std::size_t max_host_count = 2048);

} // namespace netsentinel::engine
