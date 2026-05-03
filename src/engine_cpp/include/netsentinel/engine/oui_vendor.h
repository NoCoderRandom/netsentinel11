#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

struct OUIRecord {
    std::string oui_prefix;
    std::string vendor_name;
    std::string normalized_vendor_name;
};

struct OUILookupPolicy {
    bool allow_unknown_vendor = true;
    std::string unknown_vendor_label = "Unknown Vendor";
    bool normalize_vendor_output = true;
};

struct OUICacheConfig {
    std::string cache_path = "netsentinel_oui_cache.txt";
    std::size_t max_cache_entries = 100000;
    bool skip_cache = false;
};

struct OUIImportOptions {
    std::string source_csv_path;
    OUICacheConfig cache;
    bool force_refresh = false;
};

std::string normalize_oui_vendor_name(const std::string& value);
std::string normalize_mac_oui_prefix(const std::string& mac);
bool is_known_vendor(const std::string& vendor_name);

Result<std::vector<OUIRecord>> import_oui_database(const std::string& source_csv_path);
Result<std::size_t> write_oui_cache(const std::vector<OUIRecord>& records, const OUICacheConfig& config);
Result<std::vector<OUIRecord>> load_oui_cache(const OUICacheConfig& config);
Result<std::vector<OUIRecord>> load_oui_catalog(const OUIImportOptions& options = {});
std::string lookup_vendor_by_mac(
    const std::string& mac,
    const std::vector<OUIRecord>& records,
    const OUILookupPolicy& policy = {}
);

} // namespace netsentinel::engine
