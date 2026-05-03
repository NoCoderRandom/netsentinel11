#include "netsentinel/engine/scan_scope.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string_view>

namespace {

std::uint32_t parse_octet(std::string_view value, bool& ok) {
    ok = false;
    if (value.empty()) {
        return 0;
    }
    int octet = 0;
    for (const char ch : value) {
        if (ch < '0' || ch > '9') {
            return 0;
        }
        octet = octet * 10 + (ch - '0');
        if (octet > 255) {
            return 0;
        }
    }
    ok = true;
    return static_cast<std::uint32_t>(octet);
}

std::string octets_to_string(std::uint32_t value) {
    std::array<int, 4> octets{
        static_cast<int>((value >> 24) & 0xFF),
        static_cast<int>((value >> 16) & 0xFF),
        static_cast<int>((value >> 8) & 0xFF),
        static_cast<int>(value & 0xFF)
    };
    std::ostringstream out;
    out << octets[0] << "." << octets[1] << "." << octets[2] << "." << octets[3];
    return out.str();
}

std::uint32_t parse_ipv4_to_u32(const std::string& text, bool& ok) {
    ok = false;
    auto first = text.find('.');
    auto second = text.find('.', first == std::string::npos ? 0 : first + 1);
    auto third = text.find('.', second == std::string::npos ? 0 : second + 1);
    auto fourth = text.find('.', third == std::string::npos ? 0 : third + 1);
    if (first == std::string::npos || second == std::string::npos || third == std::string::npos || fourth != std::string::npos) {
        return 0;
    }
    const std::uint32_t a = parse_octet(std::string_view{text.data(), first}, ok);
    if (!ok) return 0;
    const std::uint32_t b = parse_octet(std::string_view{text.data() + first + 1, second - first - 1}, ok);
    if (!ok) return 0;
    const std::uint32_t c = parse_octet(std::string_view{text.data() + second + 1, third - second - 1}, ok);
    if (!ok) return 0;
    const std::uint32_t d = parse_octet(std::string_view{text.data() + third + 1, text.size() - third - 1}, ok);
    if (!ok) return 0;
    ok = true;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::uint32_t mask_from_prefix(int prefix) {
    if (prefix <= 0) {
        return 0;
    }
    if (prefix >= 32) {
        return 0xFFFFFFFFu;
    }
    return (0xFFFFFFFFu << (32 - prefix)) & 0xFFFFFFFFu;
}

bool is_private_prefix(std::uint32_t value) {
    const std::array<std::uint32_t, 3> network = {
        (10u << 24),
        (172u << 24) | (16u << 16),
        (192u << 24) | (168u << 16)
    };

    if ((value & 0xFF000000u) == network[0]) return true;
    if ((value & 0xFFF00000u) == ((172u << 24) | (16u << 16))) return true;
    if ((value & 0xFFFF0000u) == network[2]) return true;
    // 192.0.2.0/24 test reservations are intentionally excluded as non-private.
    return false;
}

std::string summarize_host_limits(std::size_t estimated_host_count, bool local) {
    if (local) {
        return local ? "Local private range detected." : "";
    }
    return "Non-local range requested. Additional authorization confirmation required.";
}

} // namespace

namespace netsentinel::engine {

Result<ScanScopeProposal> propose_scan_scope_from_adapter(const AdapterInventoryEntry& adapter, std::size_t max_host_count) {
    if (adapter.ipv4_addresses.empty()) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "adapter has no IPv4 address",
            "scope selection requires an IPv4 address for a local subnet"
        );
    }

    bool ok = false;
    const auto addr = parse_ipv4_to_u32(adapter.ipv4_addresses[0], ok);
    if (!ok) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "invalid adapter IPv4 address",
            "cannot parse adapter IPv4 address for scan-scope inference"
        );
    }

    const int prefix = 24;
    const std::uint32_t mask = mask_from_prefix(prefix);
    const std::uint32_t network = addr & mask;
    const std::uint32_t broadcast = network | (~mask);
    const std::uint32_t first = network + 1;
    const std::uint32_t last = broadcast - 1;
    const std::size_t host_count = broadcast >= network ? static_cast<std::size_t>(broadcast - network - 1) : 0;

    ScanScopeProposal proposal;
    proposal.network_cidr = octets_to_string(network) + "/24";
    proposal.scope_text = octets_to_string(first) + "-" + octets_to_string(last);
    proposal.first_host = octets_to_string(first);
    proposal.last_host = octets_to_string(last);
    proposal.gateway = adapter.gateway.value_or("unknown");
    proposal.estimated_host_count = host_count;
    proposal.local_only = is_private_prefix(network);
    if (!proposal.local_only) {
        proposal.warning = summarize_host_limits(host_count, false);
    } else if (host_count > max_host_count) {
        proposal.warning = "Estimated host count exceeds configured cap; confirm manually before scan.";
    } else {
        proposal.warning = "Scope auto-selected from adapter IPv4 subnet.";
    }

    if (!proposal.local_only) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "non-local selection blocked",
            "custom confirmation required for non-private CIDR"
        );
    }
    if (host_count > max_host_count) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "scope host-count safety cap exceeded",
            "reduce network size or confirm with explicit custom scope mode"
        );
    }
    return Result<ScanScopeProposal>::ok(std::move(proposal));
}

Result<ScanScopeProposal> propose_scan_scope_from_custom_cidr(const std::string& cidr_or_range, bool allow_non_local, bool confirmed, std::size_t max_host_count) {
    const auto slash = cidr_or_range.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= cidr_or_range.size()) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "missing CIDR prefix",
            "custom scope must use CIDR form like 192.168.1.0/24"
        );
    }

    bool ok = false;
    const auto base_addr = parse_ipv4_to_u32(cidr_or_range.substr(0, slash), ok);
    if (!ok) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "invalid CIDR address",
            "custom scope should start with a valid IPv4 CIDR network"
        );
    }

    std::uint32_t prefix = 0;
    for (std::size_t i = slash + 1; i < cidr_or_range.size(); ++i) {
        const char ch = cidr_or_range[i];
        if (ch < '0' || ch > '9') {
            return Result<ScanScopeProposal>::fail(
                ErrorCode::invalid_input,
                "invalid CIDR prefix",
                "CIDR prefix must be numeric"
            );
        }
        prefix = prefix * 10 + static_cast<std::uint32_t>(ch - '0');
        if (prefix > 32) {
            return Result<ScanScopeProposal>::fail(
                ErrorCode::invalid_input,
                "invalid CIDR prefix",
                "CIDR prefix must be 0..32"
            );
        }
    }

    const std::uint32_t mask = mask_from_prefix(static_cast<int>(prefix));
    const std::uint32_t network = base_addr & mask;
    const std::uint32_t broadcast = network | (~mask);
    const std::size_t host_count = broadcast >= network ? static_cast<std::size_t>(broadcast - network - 1) : 0;
    const std::uint32_t first = network + 1;
    const std::uint32_t last = broadcast - 1;
    const bool local_only = is_private_prefix(network);

    ScanScopeProposal proposal;
    proposal.network_cidr = cidr_or_range;
    proposal.scope_text = octets_to_string(first) + "-" + octets_to_string(last);
    proposal.first_host = octets_to_string(first);
    proposal.last_host = octets_to_string(last);
    proposal.estimated_host_count = host_count;
    proposal.local_only = local_only;

    if (!local_only) {
        proposal.warning = summarize_host_limits(host_count, false);
    } else {
        proposal.warning = "Custom CIDR resolved as private scope.";
    }

    if (host_count > max_host_count) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "scan scope safety cap exceeded",
            "host count is above the configured cap; raise the cap explicitly for larger authorized scans"
        );
    }
    if (!local_only && !allow_non_local) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "non-local range blocked",
            "non-local scan requires explicit allow_non_local=true"
        );
    }
    if (!local_only && !confirmed) {
        return Result<ScanScopeProposal>::fail(
            ErrorCode::invalid_input,
            "non-local range blocked",
            "non-local range requires explicit confirmation"
        );
    }
    return Result<ScanScopeProposal>::ok(std::move(proposal));
}

} // namespace netsentinel::engine
