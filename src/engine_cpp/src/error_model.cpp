#include "netsentinel/engine/error_model.h"

namespace netsentinel::engine {

std::string to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::ok:
            return "ok";
        case ErrorCode::invalid_input:
            return "invalid_input";
        case ErrorCode::permission_denied:
            return "permission_denied";
        case ErrorCode::adapter_unavailable:
            return "adapter_unavailable";
        case ErrorCode::cancelled:
            return "cancelled";
        case ErrorCode::timeout:
            return "timeout";
        case ErrorCode::internal:
            return "internal";
    }
    return "unknown";
}

} // namespace netsentinel::engine

