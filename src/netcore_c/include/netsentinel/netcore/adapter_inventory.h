#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct ns_adapter_info {
    char* interface_id;
    char* friendly_name;
    char* mac_address;
    char* gateway;
    int dhcp_enabled;
    long long link_speed_mbps;
    int up;

    char** ipv4_addresses;
    int ipv4_count;
    char** ipv6_addresses;
    int ipv6_count;
    char** dns_servers;
    int dns_servers_count;
} ns_adapter_info;

/* Returns 0 on success and fills out_adapters/out_count.
   Returns negative for input or API errors. */
int ns_list_network_adapters(ns_adapter_info** out_adapters, int* out_count);

/* Releases memory returned by ns_list_network_adapters. Safe to call with null. */
void ns_free_network_adapters(ns_adapter_info* adapters, int count);

#ifdef __cplusplus
}
#endif
