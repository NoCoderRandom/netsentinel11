#pragma once

#include <string>
#include <vector>

namespace netsentinel::api {

struct AcceptanceFeatureStatus {
    std::string feature;
    std::string status;
    std::string evidence;
    std::string limitation;
};

struct AcceptanceAuditResult {
    bool success = false;
    bool release_ready = false;
    std::vector<AcceptanceFeatureStatus> matrix{};
    std::vector<std::string> release_blockers{};
    std::vector<std::string> impossible_without_router_support{};
    std::vector<std::string> impossible_without_agent{};
    std::vector<std::string> topology_limitations{};
    std::vector<std::string> roadmap_v1_0{};
    std::vector<std::string> roadmap_v1_1{};
    std::vector<std::string> roadmap_v2_0{};
    std::string message;
};

AcceptanceAuditResult run_final_acceptance_audit();
std::string acceptance_audit_markdown(const AcceptanceAuditResult& result);
std::string acceptance_audit_json(const AcceptanceAuditResult& result);

} // namespace netsentinel::api
