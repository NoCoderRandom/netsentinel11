#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ns_arp_discovery_result {
    char* ip_address;
    char* mac_address;
    long long latency_ms;
    char* adapter_id;
} ns_arp_discovery_result;

int ns_arp_discover(
    const char* cidr_or_range,
    int max_host_count,
    int only_local,
    ns_arp_discovery_result** out_results,
    int* out_count
);
void ns_free_arp_discovery(ns_arp_discovery_result* results, int count);

#ifdef __cplusplus
}
#endif

