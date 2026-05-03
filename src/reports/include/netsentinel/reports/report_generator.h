#pragma once

#include <string>
#include <vector>

#include "netsentinel/storage/storage.h"

namespace netsentinel::reports {

struct ReportConfig {
    std::string report_type = "executive";
    std::string format = "html";
    netsentinel::storage::StorageConfig storage{};
    std::string output_path;
    bool mock_mode = true;
    std::string gateway = "192.168.1.1";
};

struct GeneratedReport {
    bool success = false;
    bool written = false;
    std::string report_type;
    std::string format;
    std::string output_path;
    std::string content;
    std::vector<std::string> warnings{};
    std::string message;
};

GeneratedReport generate_report(const ReportConfig& config);
GeneratedReport write_report(const ReportConfig& config);

} // namespace netsentinel::reports
