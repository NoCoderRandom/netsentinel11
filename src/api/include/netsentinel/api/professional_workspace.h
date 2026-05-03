#pragma once

#include <string>
#include <vector>

namespace netsentinel::api {

struct ProfessionalSiteRecord {
    std::string site_id;
    std::string site_name;
    std::string network_cidr;
    std::string owner;
    std::vector<std::string> tags{};
    std::string issue_state = "monitoring";
    std::string report_template = "technical";
    std::string notes;
};

struct ProfessionalWorkspacePack {
    std::string consultant_name = "local-consultant";
    std::string created_utc;
    std::vector<ProfessionalSiteRecord> sites{};
    std::vector<std::string> collaboration_controls{};
};

struct ProfessionalWorkspaceImportResult {
    bool success = false;
    std::string message;
    ProfessionalWorkspacePack pack{};
};

ProfessionalWorkspacePack make_demo_professional_workspace_pack();
ProfessionalWorkspacePack make_single_site_professional_workspace_pack(
    const std::string& consultant_name,
    const ProfessionalSiteRecord& site
);
std::string export_professional_workspace_pack(const ProfessionalWorkspacePack& pack);
ProfessionalWorkspaceImportResult import_professional_workspace_pack(const std::string& text);
bool write_professional_workspace_pack(const ProfessionalWorkspacePack& pack, const std::string& path, std::string& error_message);
ProfessionalWorkspaceImportResult read_professional_workspace_pack(const std::string& path);
std::string professional_workspace_pack_markdown(const ProfessionalWorkspacePack& pack);

} // namespace netsentinel::api
