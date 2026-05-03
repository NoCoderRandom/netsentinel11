#include "netsentinel/engine/oui_vendor.h"
#include "netsentinel/engine/logger.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

std::string trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.erase(value.begin());
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
    return value;
}

std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '"') {
            if (quoted && i + 1 < line.size() && line[i + 1] == '"') {
                field += '"';
                ++i;
            } else {
                quoted = !quoted;
            }
            continue;
        }
        if (ch == ',' && !quoted) {
            fields.push_back(trim(field));
            field.clear();
            continue;
        }
        field += ch;
    }
    fields.push_back(trim(field));

    return fields;
}

std::string cache_field(std::string value) {
    value = trim(std::move(value));
    for (auto& ch : value) {
        if (ch == '\t' || ch == '\n' || ch == '\r') {
            ch = ' ';
        }
    }
    return value;
}

std::vector<std::string> parse_cache_line(const std::string& line) {
    std::vector<std::string> fields;
    std::istringstream stream{line};
    std::string token;
    while (std::getline(stream, token, '\t')) {
        fields.push_back(trim(std::move(token)));
    }
    return fields;
}

} // namespace

namespace netsentinel::engine {

std::string normalize_oui_vendor_name(const std::string& value) {
    std::string normalized;
    normalized.reserve(value.size());
    bool last_was_space = false;
    for (const unsigned char ch : value) {
        if (std::isalnum(ch)) {
            normalized += static_cast<char>(std::tolower(ch));
            last_was_space = false;
            continue;
        }
        if (std::isspace(ch)) {
            if (!normalized.empty() && !last_was_space) {
                normalized += ' ';
            }
            last_was_space = true;
            continue;
        }
        if (ch == '-' || ch == '_' || ch == ',' || ch == '.' || ch == '&' || ch == '(' || ch == ')' || ch == '@') {
            if (!normalized.empty() && !last_was_space) {
                normalized += ' ';
            }
            last_was_space = true;
            continue;
        }
    }

    if (!normalized.empty() && normalized.back() == ' ') {
        normalized.pop_back();
    }
    return normalized;
}

std::string normalize_mac_oui_prefix(const std::string& mac) {
    std::string prefix;
    prefix.reserve(6);
    for (const unsigned char ch : mac) {
        if (std::isxdigit(ch)) {
            prefix += static_cast<char>(std::toupper(ch));
            if (prefix.size() == 6) {
                break;
            }
        }
    }
    return prefix.size() == 6 ? prefix : std::string{};
}

bool is_known_vendor(const std::string& vendor_name) {
    const auto normalized = normalize_oui_vendor_name(vendor_name);
    if (normalized.empty()) {
        return false;
    }
    const char* unknown_tokens[] = {
        "unknown",
        "unknown vendor",
        "n/a",
        "not available",
        "not applicable",
        "private",
        "reserved",
        "multicast",
        "locally administered"
    };
    for (const auto* token : unknown_tokens) {
        if (normalized == token) {
            return false;
        }
    }
    return true;
}

Result<std::vector<OUIRecord>> import_oui_database(const std::string& source_csv_path) {
    if (source_csv_path.empty()) {
        return Result<std::vector<OUIRecord>>::fail(
            ErrorCode::invalid_input,
            "oui import",
            "source_csv_path must not be empty"
        );
    }

    std::ifstream source_file{source_csv_path};
    if (!source_file.is_open()) {
        return Result<std::vector<OUIRecord>>::fail(
            ErrorCode::invalid_input,
            "oui import",
            "failed to open source file: " + source_csv_path
        );
    }

    std::unordered_map<std::string, OUIRecord> records;
    std::string line;
    std::size_t line_no = 0;
    while (std::getline(source_file, line)) {
        ++line_no;
        if (line.empty() || line[0] == '#') {
            continue;
        }
        auto fields = split_csv_line(line);
        if (fields.size() < 2) {
            continue;
        }
        std::string assignment_field = fields[0];
        std::string vendor_field = fields[1];
        if (fields.size() >= 3 && normalize_mac_oui_prefix(assignment_field).empty()) {
            assignment_field = fields[1];
            vendor_field = fields[2];
        }

        auto prefix = normalize_mac_oui_prefix(assignment_field);
        if (prefix.empty()) {
            continue;
        }
        auto vendor = cache_field(vendor_field);
        if (vendor.empty()) {
            continue;
        }
        OUIRecord record;
        record.oui_prefix = prefix;
        record.vendor_name = vendor;
        record.normalized_vendor_name = normalize_oui_vendor_name(vendor);
        records[prefix] = record;
    }

    std::vector<OUIRecord> out;
    out.reserve(records.size());
    for (auto& entry : records) {
        out.push_back(std::move(entry.second));
    }
    std::sort(out.begin(), out.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.oui_prefix < rhs.oui_prefix;
    });

    if (out.empty()) {
        Logger::instance().warning("oui_vendor", "import_oui_database loaded 0 entries from " + source_csv_path + " at line " + std::to_string(line_no));
    }
    return Result<std::vector<OUIRecord>>::ok(std::move(out));
}

Result<std::size_t> write_oui_cache(const std::vector<OUIRecord>& records, const OUICacheConfig& config) {
    if (config.cache_path.empty()) {
        return Result<std::size_t>::fail(
            ErrorCode::invalid_input,
            "oui cache",
            "cache_path must not be empty"
        );
    }
    if (config.max_cache_entries == 0) {
        return Result<std::size_t>::fail(
            ErrorCode::invalid_input,
            "oui cache",
            "max_cache_entries must be greater than zero"
        );
    }

    std::vector<OUIRecord> sorted(records.begin(), records.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.oui_prefix < rhs.oui_prefix;
    });
    if (sorted.size() > config.max_cache_entries) {
        sorted.resize(config.max_cache_entries);
    }

    const std::filesystem::path cache_path{config.cache_path};
    const auto parent = cache_path.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::error_code ec;
        const auto created = std::filesystem::create_directories(parent, ec);
        if (!created || ec) {
            return Result<std::size_t>::fail(
                ErrorCode::permission_denied,
                "oui cache",
                "failed to create cache directory: " + parent.string() + (ec ? " (" + ec.message() + ")" : "")
            );
        }
    }

    std::ofstream cache_file{config.cache_path};
    if (!cache_file.is_open()) {
        return Result<std::size_t>::fail(
            ErrorCode::permission_denied,
            "oui cache",
            "failed to open cache file for write: " + config.cache_path
        );
    }

    cache_file << "# netsentinel OUI cache\n";
    for (const auto& record : sorted) {
        cache_file << cache_field(record.oui_prefix) << '\t'
                   << cache_field(record.vendor_name) << '\t'
                   << cache_field(record.normalized_vendor_name) << '\n';
    }
    return Result<std::size_t>::ok(sorted.size());
}

Result<std::vector<OUIRecord>> load_oui_cache(const OUICacheConfig& config) {
    if (config.cache_path.empty()) {
        return Result<std::vector<OUIRecord>>::fail(
            ErrorCode::invalid_input,
            "oui cache",
            "cache_path must not be empty"
        );
    }

    std::ifstream cache_file{config.cache_path};
    if (!cache_file.is_open()) {
        return Result<std::vector<OUIRecord>>::fail(
            ErrorCode::invalid_input,
            "oui cache",
            "cache file is unavailable: " + config.cache_path
        );
    }

    std::vector<OUIRecord> out;
    std::unordered_map<std::string, OUIRecord> dedupe;
    std::string line;
    while (std::getline(cache_file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const auto fields = parse_cache_line(line);
        if (fields.size() < 2) {
            continue;
        }
        const auto prefix = normalize_mac_oui_prefix(fields[0]);
        if (prefix.empty()) {
            continue;
        }
        OUIRecord record;
        record.oui_prefix = prefix;
        record.vendor_name = fields[1];
        if (fields.size() >= 3 && !fields[2].empty()) {
            record.normalized_vendor_name = fields[2];
        } else {
            record.normalized_vendor_name = normalize_oui_vendor_name(record.vendor_name);
        }
        dedupe[prefix] = std::move(record);
    }
    out.reserve(dedupe.size());
    for (auto& entry : dedupe) {
        out.push_back(std::move(entry.second));
    }
    std::sort(out.begin(), out.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.oui_prefix < rhs.oui_prefix;
    });
    return Result<std::vector<OUIRecord>>::ok(std::move(out));
}

Result<std::vector<OUIRecord>> load_oui_catalog(const OUIImportOptions& options) {
    if (!options.cache.skip_cache) {
        const auto cached = load_oui_cache(options.cache);
        if (cached && !cached.value().empty()) {
            Logger::instance().info("oui_vendor", "loaded OUI catalog from cache");
            return cached;
        }
        if (!cached && !cached.error().details.empty()) {
            Logger::instance().warning("oui_vendor", "cache load failed: " + cached.error().details);
        }
        if (cached && cached.value().empty() && !options.source_csv_path.empty()) {
            Logger::instance().warning(
                "oui_vendor",
                "cache did not contain usable OUI rows; trying source import"
            );
        }
    }

    if (options.source_csv_path.empty()) {
        return Result<std::vector<OUIRecord>>::fail(
            ErrorCode::invalid_input,
            "oui catalog",
            "no source_csv_path was provided and cache could not be loaded"
        );
    }

    const auto imported = import_oui_database(options.source_csv_path);
    if (!imported) {
        Logger::instance().warning("oui_vendor", "source import failed: " + imported.error().details);
        return imported;
    }

    if (options.cache.skip_cache) {
        return imported;
    }
    const auto saved = write_oui_cache(imported.value(), options.cache);
    if (!saved) {
        Logger::instance().warning("oui_vendor", "failed to refresh cache: " + saved.error().details);
    }
    return imported;
}

std::string lookup_vendor_by_mac(
    const std::string& mac,
    const std::vector<OUIRecord>& records,
    const OUILookupPolicy& policy
) {
    const auto prefix = normalize_mac_oui_prefix(mac);
    if (!records.empty()) {
        const auto it = std::lower_bound(
            records.begin(),
            records.end(),
            prefix,
            [](const OUIRecord& candidate, const std::string& value) {
                return candidate.oui_prefix < value;
            }
        );
        if (it != records.end() && it->oui_prefix == prefix) {
            const std::string& vendor = policy.normalize_vendor_output ? it->normalized_vendor_name : it->vendor_name;
            if (is_known_vendor(vendor)) {
                return vendor;
            }
        }
    }

    if (!policy.allow_unknown_vendor) {
        return {};
    }
    if (policy.unknown_vendor_label.empty()) {
        return "Unknown Vendor";
    }
    return policy.normalize_vendor_output
        ? normalize_oui_vendor_name(policy.unknown_vendor_label)
        : policy.unknown_vendor_label;
}

} // namespace netsentinel::engine
