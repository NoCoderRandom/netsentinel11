#include "netsentinel/engine/fingerprint_engine_v1.h"
#include "netsentinel/engine/logger.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using netsentinel::engine::FingerprintRule;

int clamp_confidence(int value, int min, int max) {
    if (value < min) {
        return min;
    }
    if (value > max) {
        return max;
    }
    return value;
}

std::string default_rules_path() {
    const auto source_dir = std::filesystem::path{__FILE__}.parent_path();
    return (source_dir / "fingerprint_rules_v1.json").string();
}

void skip_ws(std::string_view text, std::size_t& pos) {
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
        ++pos;
    }
}

std::size_t find_matching(std::string_view text, std::size_t open_pos, char open_c, char close_c) {
    if (open_c == close_c) {
        bool escaped = false;
        for (std::size_t i = open_pos + 1; i < text.size(); ++i) {
            const char ch = text[i];
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == close_c) {
                return i;
            }
        }
        return std::string_view::npos;
    }

    std::size_t depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (std::size_t i = open_pos; i < text.size(); ++i) {
        const char ch = text[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (in_string) {
            if (ch == '\\') {
                escaped = true;
            } else if (ch == '\"') {
                in_string = false;
            }
            continue;
        }
        if (ch == '\"') {
            in_string = true;
            continue;
        }
        if (ch == open_c) {
            ++depth;
            continue;
        }
        if (ch == close_c) {
            --depth;
            if (depth == 0) {
                return i;
            }
        }
    }
    return std::string_view::npos;
}

std::string extract_raw_value(std::string_view text, std::string_view key) {
    const auto pattern = std::string("\"") + std::string(key) + "\"";
    const auto key_pos = text.find(pattern);
    if (key_pos == std::string_view::npos) {
        throw std::runtime_error("missing key");
    }
    std::size_t pos = key_pos + pattern.size();
    skip_ws(text, pos);
    if (pos >= text.size() || text[pos] != ':') {
        throw std::runtime_error("malformed key/value");
    }
    ++pos;
    skip_ws(text, pos);
    if (pos >= text.size()) {
        throw std::runtime_error("malformed value");
    }

    if (text[pos] == '\"') {
        const auto end = find_matching(text, pos, '\"', '\"');
        if (end == std::string_view::npos) {
            throw std::runtime_error("unterminated string");
        }
        return std::string(text.substr(pos, end - pos + 1));
    }
    if (text[pos] == '{' || text[pos] == '[') {
        const char open_c = text[pos];
        const char close_c = open_c == '{' ? '}' : ']';
        const auto end = find_matching(text, pos, open_c, close_c);
        if (end == std::string_view::npos) {
            throw std::runtime_error("unterminated collection");
        }
        return std::string(text.substr(pos, end - pos + 1));
    }
    auto start = pos;
    while (pos < text.size() && text[pos] != ',' && text[pos] != '}') {
        ++pos;
    }
    return std::string(text.substr(start, pos - start));
}

std::string parse_json_string(std::string_view raw) {
    if (raw.empty() || raw.front() != '\"' || raw.back() != '\"') {
        throw std::invalid_argument("expected string");
    }
    std::string value = std::string(raw.substr(1, raw.size() - 2));
    std::string out;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) {
            ++i;
            switch (value[i]) {
                case '\"':
                    out += '\"';
                    break;
                case '\\':
                    out += '\\';
                    break;
                case 'n':
                    out += '\n';
                    break;
                case 'r':
                    out += '\r';
                    break;
                case 't':
                    out += '\t';
                    break;
                default:
                    out += value[i];
                    break;
            }
            continue;
        }
        out += value[i];
    }
    return out;
}

std::string parse_optional_string(std::string_view text, std::string_view key) {
    try {
        return parse_json_string(extract_raw_value(text, key));
    } catch (const std::exception&) {
        return {};
    }
}

int parse_optional_int(std::string_view text, std::string_view key, int fallback) {
    try {
        const auto raw = extract_raw_value(text, key);
        return std::stoi(std::string(raw));
    } catch (const std::exception&) {
        return fallback;
    }
}

std::vector<std::string> parse_string_array(std::string_view raw) {
    if (raw.size() < 2 || raw.front() != '[' || raw.back() != ']') {
        throw std::invalid_argument("expected array");
    }
    std::vector<std::string> out;
    std::size_t pos = 1;
    while (pos < raw.size() - 1) {
        while (pos < raw.size() - 1 && std::isspace(static_cast<unsigned char>(raw[pos]))) {
            ++pos;
        }
        if (pos >= raw.size() - 1) {
            break;
        }
        if (raw[pos] == ',') {
            ++pos;
            continue;
        }
        if (raw[pos] != '\"') {
            throw std::invalid_argument("array element not string");
        }
        const auto end = find_matching(raw, pos, '\"', '\"');
        if (end == std::string_view::npos) {
            throw std::invalid_argument("unterminated string in array");
        }
        out.push_back(parse_json_string(raw.substr(pos, end - pos + 1)));
        pos = end + 1;
    }
    return out;
}

std::vector<std::string> parse_top_level_string_array(std::string_view text, std::string_view key) {
    try {
        const auto raw = extract_raw_value(text, key);
        return parse_string_array(raw);
    } catch (const std::exception&) {
        return {};
    }
}

std::vector<int> parse_int_array(std::string_view raw) {
    if (raw.size() < 2 || raw.front() != '[' || raw.back() != ']') {
        throw std::invalid_argument("expected array");
    }
    std::vector<int> out;
    std::size_t pos = 1;
    while (pos < raw.size() - 1) {
        while (pos < raw.size() - 1 && std::isspace(static_cast<unsigned char>(raw[pos]))) {
            ++pos;
        }
        if (raw[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos >= raw.size() - 1) {
            break;
        }
        auto start = pos;
        while (pos < raw.size() - 1 && raw[pos] != ',' && raw[pos] != ']') {
            ++pos;
        }
        std::string value = std::string(raw.substr(start, pos - start));
        const auto left = value.find_first_not_of(" \t\r\n");
        if (left == std::string::npos) {
            continue;
        }
        const auto right = value.find_last_not_of(" \t\r\n");
        if (right == std::string::npos) {
            continue;
        }
        value = value.substr(left, right - left + 1);
        if (!value.empty()) {
            out.push_back(std::stoi(value));
        }
    }
    return out;
}

std::vector<int> parse_top_level_int_array(std::string_view text, std::string_view key) {
    try {
        const auto raw = extract_raw_value(text, key);
        return parse_int_array(raw);
    } catch (const std::exception&) {
        return {};
    }
}

std::vector<std::string> split_top_level_objects(std::string_view array_raw) {
    if (array_raw.size() < 2 || array_raw.front() != '[' || array_raw.back() != ']') {
        throw std::invalid_argument("expected json array");
    }
    std::vector<std::string> out;
    std::size_t pos = 1;
    while (pos < array_raw.size() - 1) {
        while (pos < array_raw.size() - 1 && std::isspace(static_cast<unsigned char>(array_raw[pos]))) {
            ++pos;
        }
        if (pos >= array_raw.size() - 1) {
            break;
        }
        if (array_raw[pos] == ',') {
            ++pos;
            continue;
        }
        if (array_raw[pos] != '{') {
            throw std::invalid_argument("expected json object in array");
        }
        const auto end = find_matching(array_raw, pos, '{', '}');
        if (end == std::string_view::npos) {
            throw std::invalid_argument("unterminated rule object");
        }
        out.push_back(std::string(array_raw.substr(pos, end - pos + 1)));
        pos = end + 1;
    }
    return out;
}

std::vector<FingerprintRule> parse_rule_set(std::string_view json) {
    std::vector<std::string> rule_objects;
    try {
        std::string rules_blob = extract_raw_value(json, "rules");
        rule_objects = split_top_level_objects(rules_blob);
    } catch (...) {
        rule_objects = split_top_level_objects(json);
    }

    std::vector<FingerprintRule> rules;
    rules.reserve(rule_objects.size());
    for (std::size_t i = 0; i < rule_objects.size(); ++i) {
        const auto& rule_raw = rule_objects[i];
        FingerprintRule rule;
        rule.rule_id = parse_optional_string(rule_raw, "id");
        if (rule.rule_id.empty()) {
            rule.rule_id = "rule-" + std::to_string(i + 1);
        }
        rule.device_type = parse_optional_string(rule_raw, "device_type");
        rule.vendor = parse_optional_string(rule_raw, "vendor");
        rule.model = parse_optional_string(rule_raw, "model");
        rule.base_confidence = parse_optional_int(rule_raw, "base_confidence", rule.base_confidence);
        rule.max_confidence = parse_optional_int(rule_raw, "max_confidence", rule.max_confidence);
        rule.weight_oui_vendor = parse_optional_int(rule_raw, "weight_oui_vendor", rule.weight_oui_vendor);
        rule.weight_hostname = parse_optional_int(rule_raw, "weight_hostname", rule.weight_hostname);
        rule.weight_netbios = parse_optional_int(rule_raw, "weight_netbios", rule.weight_netbios);
        rule.weight_mdns = parse_optional_int(rule_raw, "weight_mdns", rule.weight_mdns);
        rule.weight_ssdp = parse_optional_int(rule_raw, "weight_ssdp", rule.weight_ssdp);
        rule.weight_open_port = parse_optional_int(rule_raw, "weight_open_port", rule.weight_open_port);
        rule.weight_user_label = parse_optional_int(rule_raw, "weight_user_label", rule.weight_user_label);

        rule.match_oui_vendor_tokens = parse_top_level_string_array(rule_raw, "match_oui_vendor_tokens");
        rule.match_hostname_tokens = parse_top_level_string_array(rule_raw, "match_hostname_tokens");
        rule.match_netbios_tokens = parse_top_level_string_array(rule_raw, "match_netbios_tokens");
        rule.match_mdns_tokens = parse_top_level_string_array(rule_raw, "match_mdns_tokens");
        rule.match_ssdp_tokens = parse_top_level_string_array(rule_raw, "match_ssdp_tokens");
        rule.match_open_ports = parse_top_level_int_array(rule_raw, "match_open_ports");
        rule.match_user_labels = parse_top_level_string_array(rule_raw, "match_user_labels");
        rules.push_back(std::move(rule));
    }
    return rules;
}

std::string to_lower(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

void maybe_append_reason(std::vector<std::string>& reasons, std::string&& reason) {
    if (!reason.empty()) {
        reasons.push_back(std::move(reason));
    }
}

bool matches_any_token(std::string_view source, const std::vector<std::string>& tokens, std::string& matched) {
    const std::string normalized_source = to_lower(std::string(source));
    for (const auto& token : tokens) {
        const auto normalized_token = to_lower(token);
        if (normalized_token.empty()) {
            continue;
        }
        if (normalized_source.find(normalized_token) != std::string::npos) {
            matched = token;
            return true;
        }
    }
    return false;
}

bool contains_any_port(const std::vector<int>& observed, const std::vector<int>& rule_ports, int& matched_count) {
    for (const auto port : observed) {
        if (std::find(rule_ports.begin(), rule_ports.end(), port) != rule_ports.end()) {
            ++matched_count;
        }
    }
    return matched_count > 0;
}

} // namespace

namespace netsentinel::engine {

Result<std::vector<FingerprintRule>> load_fingerprint_rules(const std::string& rules_path) {
    std::string path = rules_path;
    if (path.empty()) {
        path = default_rules_path();
    }
    if (path.empty()) {
        return Result<std::vector<FingerprintRule>>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "fingerprint rules",
            "rules path must not be empty"
        );
    }

    std::ifstream rules_file{path};
    if (!rules_file.is_open()) {
        return Result<std::vector<FingerprintRule>>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "fingerprint rules",
            "unable to open rule file: " + path
        );
    }

    std::ostringstream raw;
    raw << rules_file.rdbuf();
    const auto content = raw.str();
    if (content.empty()) {
        return Result<std::vector<FingerprintRule>>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "fingerprint rules",
            "rule file is empty: " + path
        );
    }

    try {
        auto rules = parse_rule_set(content);
        if (rules.empty()) {
            return Result<std::vector<FingerprintRule>>::fail(
                netsentinel::engine::ErrorCode::invalid_input,
                "fingerprint rules",
                "no valid rules in: " + path
            );
        }
        Logger::instance().info("fingerprint_engine_v1", "loaded " + std::to_string(rules.size()) + " fingerprint rules");
        return Result<std::vector<FingerprintRule>>::ok(std::move(rules));
    } catch (const std::exception& ex) {
        return Result<std::vector<FingerprintRule>>::fail(
            netsentinel::engine::ErrorCode::invalid_input,
            "fingerprint rules",
            std::string("failed to parse rule file ") + path + ": " + ex.what()
        );
    }
}

Result<std::vector<FingerprintGuess>> infer_fingerprints(
    const FingerprintSignalSet& signals,
    const std::vector<FingerprintRule>& rules,
    const FingerprintEngineOptions& options
) {
    if (options.min_confidence < 0 || options.min_confidence > 100) {
        return Result<std::vector<FingerprintGuess>>::fail(
            ErrorCode::invalid_input,
            "fingerprint options",
            "min_confidence must be between 0 and 100"
        );
    }
    if (rules.empty()) {
        return Result<std::vector<FingerprintGuess>>::fail(
            ErrorCode::invalid_input,
            "fingerprint rules",
            "no rules supplied"
        );
    }

    std::vector<FingerprintGuess> out;
    out.reserve(rules.size());

    const auto mdns_signals = signals.mdns_hints;
    const auto ssdp_signals = signals.ssdp_hints;
    const auto user_signals = signals.user_labels;
    const auto ports = signals.open_tcp_ports;

    for (const auto& rule : rules) {
        int confidence = rule.base_confidence;
        std::vector<std::string> evidence;
        bool matched = false;
        std::string matched_token;

        if (!rule.match_oui_vendor_tokens.empty() && signals.oui_vendor_hint && matches_any_token(*signals.oui_vendor_hint, rule.match_oui_vendor_tokens, matched_token)) {
            confidence += rule.weight_oui_vendor;
            maybe_append_reason(evidence, "oui vendor token matched: " + matched_token);
            matched = true;
        }

        if (!rule.match_hostname_tokens.empty() && signals.hostname && matches_any_token(*signals.hostname, rule.match_hostname_tokens, matched_token)) {
            confidence += rule.weight_hostname;
            maybe_append_reason(evidence, "hostname matched token: " + matched_token);
            matched = true;
        }

        if (!rule.match_netbios_tokens.empty() && signals.netbios_name && matches_any_token(*signals.netbios_name, rule.match_netbios_tokens, matched_token)) {
            confidence += rule.weight_netbios;
            maybe_append_reason(evidence, "netbios matched token: " + matched_token);
            matched = true;
        }

        if (!rule.match_mdns_tokens.empty()) {
            for (const auto& hint : mdns_signals) {
                if (!matches_any_token(hint, rule.match_mdns_tokens, matched_token)) {
                    continue;
                }
                confidence += rule.weight_mdns;
                maybe_append_reason(evidence, "mDNS matched token: " + matched_token);
                matched = true;
                break;
            }
        }

        if (!rule.match_ssdp_tokens.empty()) {
            for (const auto& hint : ssdp_signals) {
                if (!matches_any_token(hint, rule.match_ssdp_tokens, matched_token)) {
                    continue;
                }
                confidence += rule.weight_ssdp;
                maybe_append_reason(evidence, "SSDP matched token: " + matched_token);
                matched = true;
                break;
            }
        }

        if (!rule.match_open_ports.empty()) {
            int matched_ports = 0;
            if (contains_any_port(ports, rule.match_open_ports, matched_ports)) {
                confidence += std::max(1, matched_ports) * rule.weight_open_port;
                maybe_append_reason(evidence, "open-port match count: " + std::to_string(matched_ports));
                matched = true;
            }
        }

        if (!rule.match_user_labels.empty()) {
            for (const auto& label : user_signals) {
                if (!matches_any_token(label, rule.match_user_labels, matched_token)) {
                    continue;
                }
                confidence += rule.weight_user_label;
                maybe_append_reason(evidence, "user label matched: " + matched_token);
                matched = true;
                break;
            }
        }

        if (!matched || confidence < options.min_confidence) {
            continue;
        }

        confidence = clamp_confidence(confidence, options.min_confidence, rule.max_confidence);
        out.push_back(FingerprintGuess{
            .rule_id = rule.rule_id,
            .device_type = rule.device_type,
            .vendor = rule.vendor,
            .model = rule.model,
            .confidence = confidence,
            .evidence = std::move(evidence)
        });
    }

    std::sort(out.begin(), out.end(), [](const FingerprintGuess& lhs, const FingerprintGuess& rhs) {
        if (lhs.confidence != rhs.confidence) {
            return lhs.confidence > rhs.confidence;
        }
        return lhs.rule_id < rhs.rule_id;
    });

    Logger::instance().info("fingerprint_engine_v1", "generated " + std::to_string(out.size()) + " fingerprint guess(es)");
    return Result<std::vector<FingerprintGuess>>::ok(std::move(out));
}

} // namespace netsentinel::engine
