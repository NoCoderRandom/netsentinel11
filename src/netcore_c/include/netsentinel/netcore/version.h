#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NETSENTINEL_NETCORE_VERSION_MAJOR 0
#define NETSENTINEL_NETCORE_VERSION_MINOR 1
#define NETSENTINEL_NETCORE_VERSION_PATCH 0

const char* ns_core_version(void);

#ifdef __cplusplus
}
#endif

