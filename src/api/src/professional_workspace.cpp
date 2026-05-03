#include "netsentinel/api/professional_workspace.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>

namespace netsentinel::api {

namespace {

std::string now_utc_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string{buffer};
}

std::string escape_field(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (const char ch : value) {
        if (ch == '\\') {
            out += "\\\\";
        } else if (ch == '|') {
            out += "\\|";
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

std::string unescape_field(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        const char ch = value[i];
        if (ch != '\\' || i + 1 >= value.size()) {
            out.push_back(ch);
            continue;
        }
        const char next = value[++i];
        if (next == 'n') {
            out.push_back('\n');
        } else if (next == 'r') {
            out.push_back('\r');
        } else {
            out.push_back(next);
        }
    }
    return out;
}

std::vector<std::string> split_record(const std::string& line) {
    std::vector<std::string> out;
    std::string current;
    bool escaped = false;
    for (const char ch : line) {
        if (escaped) {
            current.push_back('\\');
            current.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '|') {
            out.push_back(unescape_field(current));
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    if (escaped) {
        current.push_back('\\');
    }
    out.push_back(unescape_field(current));
    return out;
}

std::string join_csv(const std::vector<std::string>& values) {
    std::string out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            out += ",";
        }
        out += values[i];
    }
    return out;
}

std::vector<std::string> split_csv(const std::string& text) {
    std::vector<std::string> out;
    std::string current;
    for (const char ch : text) {
        if (ch == ',') {
            if (!current.empty()) {
                out.push_back(current);
            }
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) {
        out.push_back(current);
    }
    return out;
}

std::vector<std::string> default_controls() {
    return {
        "local-first-file-bundle",
        "no-cloud-subscription-required",
        "consultant-import-export",
        "multi-site-and-network-aware",
        "owners-tags-notes-issue-states",
        "report-template-selection",
        "no-network-scan-during-import-export"
    };
}

std::string site_to_line(const ProfessionalSiteRecord& site) {
    return std::string{"SITE|"} +
        escape_field(site.site_id) + "|" +
        escape_field(site.site_name) + "|" +
        escape_field(site.network_cidr) + "|" +
        escape_field(site.owner) + "|" +
        escape_field(join_csv(site.tags)) + "|" +
        escape_field(site.issue_state) + "|" +
        escape_field(site.report_template) + "|" +
        escape_field(site.notes);
}

} // namespace

ProfessionalWorkspacePack make_demo_professional_workspace_pack() {
    ProfessionalWorkspacePack pack{};
    pack.consultant_name = "local-consultant";
    pack.created_utc = now_utc_iso8601();
    pack.collaboration_controls = default_controls();
    pack.sites = {
        {
            .site_id = "home-lab",
            .site_name = "Home Lab",
            .network_cidr = "192.168.50.0/24",
            .owner = "Household",
            .tags = {"authorized-lan", "router-truth"},
            .issue_state = "monitoring",
            .report_template = "technical",
            .notes = "Authorized local test network for NetSentinel11 validation."
        },
        {
            .site_id = "client-office",
            .site_name = "Client Office",
            .network_cidr = "192.168.1.0/24",
            .owner = "Client Owner",
            .tags = {"consulting", "authorized-before-scan"},
            .issue_state = "open",
            .report_template = "executive",
            .notes = "File-based collaboration example. Scan only after explicit authorization."
        }
    };
    return pack;
}

ProfessionalWorkspacePack make_single_site_professional_workspace_pack(
    const std::string& consultant_name,
    const ProfessionalSiteRecord& site
) {
    ProfessionalWorkspacePack pack{};
    pack.consultant_name = consultant_name.empty() ? "local-consultant" : consultant_name;
    pack.created_utc = now_utc_iso8601();
    pack.collaboration_controls = default_controls();
    pack.sites.push_back(site);
    return pack;
}

std::string export_professional_workspace_pack(const ProfessionalWorkspacePack& pack) {
    std::ostringstream out;
    out << "NETSENTINEL_PRO_WORKSPACE_BUNDLE_V1\n";
    out << "CONSULTANT|" << escape_field(pack.consultant_name) << "|" << escape_field(pack.created_utc.empty() ? now_utc_iso8601() : pack.created_utc) << "\n";
    for (const auto& control : pack.collaboration_controls.empty() ? default_controls() : pack.collaboration_controls) {
        out << "CONTROL|" << escape_field(control) << "\n";
    }
    for (const auto& site : pack.sites) {
        out << site_to_line(site) << "\n";
    }
    return out.str();
}

ProfessionalWorkspaceImportResult import_professional_workspace_pack(const std::string& text) {
    ProfessionalWorkspaceImportResult result{};
    std::istringstream in{text};
    std::string line;
    bool saw_header = false;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        if (!saw_header) {
            if (line != "NETSENTINEL_PRO_WORKSPACE_BUNDLE_V1") {
                result.message = "Unsupported professional workspace bundle header.";
                return result;
            }
            saw_header = true;
            continue;
        }
        const auto fields = split_record(line);
        if (fields.empty()) {
            continue;
        }
        if (fields[0] == "CONSULTANT" && fields.size() >= 3) {
            result.pack.consultant_name = fields[1];
            result.pack.created_utc = fields[2];
            continue;
        }
        if (fields[0] == "CONTROL" && fields.size() >= 2) {
            result.pack.collaboration_controls.push_back(fields[1]);
            continue;
        }
        if (fields[0] == "SITE" && fields.size() >= 9) {
            ProfessionalSiteRecord site{};
            site.site_id = fields[1];
            site.site_name = fields[2];
            site.network_cidr = fields[3];
            site.owner = fields[4];
            site.tags = split_csv(fields[5]);
            site.issue_state = fields[6].empty() ? "monitoring" : fields[6];
            site.report_template = fields[7].empty() ? "technical" : fields[7];
            site.notes = fields[8];
            result.pack.sites.push_back(site);
            continue;
        }
    }
    if (!saw_header) {
        result.message = "Professional workspace bundle is empty.";
        return result;
    }
    if (result.pack.consultant_name.empty()) {
        result.pack.consultant_name = "local-consultant";
    }
    if (result.pack.created_utc.empty()) {
        result.pack.created_utc = now_utc_iso8601();
    }
    if (result.pack.collaboration_controls.empty()) {
        result.pack.collaboration_controls = default_controls();
    }
    result.success = true;
    result.message = "Professional workspace bundle imported locally.";
    return result;
}

bool write_professional_workspace_pack(const ProfessionalWorkspacePack& pack, const std::string& path, std::string& error_message) {
    std::ofstream out{path, std::ios::trunc};
    if (!out.is_open()) {
        error_message = "Unable to open professional workspace export path.";
        return false;
    }
    out << export_professional_workspace_pack(pack);
    if (!out.good()) {
        error_message = "Unable to fully write professional workspace export.";
        return false;
    }
    return true;
}

ProfessionalWorkspaceImportResult read_professional_workspace_pack(const std::string& path) {
    std::ifstream in{path};
    if (!in.is_open()) {
        ProfessionalWorkspaceImportResult result{};
        result.message = "Unable to open professional workspace import path.";
        return result;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return import_professional_workspace_pack(buffer.str());
}

std::string professional_workspace_pack_markdown(const ProfessionalWorkspacePack& pack) {
    std::ostringstream out;
    out << "# Professional Workspace Pack\n\n";
    out << "- Consultant: " << pack.consultant_name << "\n";
    out << "- Created UTC: " << (pack.created_utc.empty() ? "(not set)" : pack.created_utc) << "\n";
    out << "- Sites: " << pack.sites.size() << "\n\n";
    out << "## Collaboration controls\n\n";
    const auto controls = pack.collaboration_controls.empty() ? default_controls() : pack.collaboration_controls;
    for (const auto& control : controls) {
        out << "- " << control << "\n";
    }
    out << "\n## Sites\n\n";
    for (const auto& site : pack.sites) {
        out << "### " << (site.site_name.empty() ? site.site_id : site.site_name) << "\n\n";
        out << "- Site ID: " << site.site_id << "\n";
        out << "- Network CIDR: " << site.network_cidr << "\n";
        out << "- Owner: " << site.owner << "\n";
        out << "- Tags: " << (site.tags.empty() ? "(none)" : join_csv(site.tags)) << "\n";
        out << "- Issue state: " << site.issue_state << "\n";
        out << "- Report template: " << site.report_template << "\n";
        out << "- Notes: " << (site.notes.empty() ? "(none)" : site.notes) << "\n\n";
    }
    out << "## Safety\n\n";
    out << "- This file-based workflow does not require a cloud service.\n";
    out << "- Import/export does not scan any network.\n";
    out << "- Consultants must scan only explicitly authorized client networks.\n";
    return out.str();
}

} // namespace netsentinel::api
