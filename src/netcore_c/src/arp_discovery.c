#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#endif

#include "netsentinel/netcore/arp_discovery.h"

static char* dup_text(const char* value) {
    if (!value) {
        return NULL;
    }
    const size_t size = strlen(value);
    char* out = (char*)malloc(size + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, value, size + 1);
    return out;
}

#ifdef _WIN32
static int parse_ipv4_literal(const char* text, unsigned int* out_host_order) {
    struct in_addr addr;
    if (!text || !out_host_order || inet_pton(AF_INET, text, &addr) != 1) {
        return -1;
    }
    *out_host_order = ntohl(addr.s_addr);
    return 0;
}

static int parse_scope(
    const char* cidr_or_range,
    unsigned int* start_host_order,
    unsigned int* end_host_order,
    unsigned int* network_host_order,
    unsigned int* mask_host_order
) {
    if (!cidr_or_range || !start_host_order || !end_host_order || !network_host_order || !mask_host_order) {
        return -1;
    }

    const char* slash = strchr(cidr_or_range, '/');
    const char* dash = strchr(cidr_or_range, '-');
    if (slash) {
        char ip_text[64];
        const size_t ip_length = (size_t)(slash - cidr_or_range);
        if (ip_length == 0 || ip_length >= sizeof(ip_text)) {
            return -1;
        }
        memcpy(ip_text, cidr_or_range, ip_length);
        ip_text[ip_length] = '\0';

        char* end = NULL;
        const long prefix = strtol(slash + 1, &end, 10);
        if (!end || *end != '\0' || prefix < 0 || prefix > 32) {
            return -1;
        }

        unsigned int ip = 0;
        if (parse_ipv4_literal(ip_text, &ip) != 0) {
            return -1;
        }
        const unsigned int mask = prefix == 0 ? 0U : (0xFFFFFFFFU << (32 - prefix));
        const unsigned int network = ip & mask;
        const unsigned int broadcast = network | ~mask;
        *start_host_order = prefix >= 31 ? network : network + 1U;
        *end_host_order = prefix >= 31 ? broadcast : broadcast - 1U;
        *network_host_order = network;
        *mask_host_order = mask;
        return 0;
    }

    if (dash) {
        char start_text[64];
        char end_text[64];
        const size_t start_length = (size_t)(dash - cidr_or_range);
        const size_t end_length = strlen(dash + 1);
        if (start_length == 0 || start_length >= sizeof(start_text) || end_length == 0 || end_length >= sizeof(end_text)) {
            return -1;
        }
        memcpy(start_text, cidr_or_range, start_length);
        start_text[start_length] = '\0';
        memcpy(end_text, dash + 1, end_length + 1);
        if (parse_ipv4_literal(start_text, start_host_order) != 0 ||
            parse_ipv4_literal(end_text, end_host_order) != 0) {
            return -1;
        }
        if (*start_host_order > *end_host_order) {
            const unsigned int tmp = *start_host_order;
            *start_host_order = *end_host_order;
            *end_host_order = tmp;
        }
        *network_host_order = *start_host_order;
        *mask_host_order = 0U;
        return 0;
    }

    if (parse_ipv4_literal(cidr_or_range, start_host_order) != 0) {
        return -1;
    }
    *end_host_order = *start_host_order;
    *network_host_order = *start_host_order;
    *mask_host_order = 0xFFFFFFFFU;
    return 0;
}

static int mac_is_broadcast_or_empty(const unsigned char* mac, unsigned long length) {
    if (!mac || length == 0) {
        return 1;
    }
    int all_zero = 1;
    int all_ff = 1;
    for (unsigned long i = 0; i < length; ++i) {
        if (mac[i] != 0x00) {
            all_zero = 0;
        }
        if (mac[i] != 0xFF) {
            all_ff = 0;
        }
    }
    return all_zero || all_ff;
}

static char* format_mac(const unsigned char* mac, unsigned long length) {
    if (!mac || length == 0) {
        return dup_text("");
    }
    const size_t output_size = (size_t)(length * 3);
    char* text = (char*)malloc(output_size);
    if (!text) {
        return NULL;
    }
    char* cursor = text;
    size_t remaining = output_size;
    for (unsigned long i = 0; i < length; ++i) {
        const int written = snprintf(cursor, remaining, i == 0 ? "%02X" : ":%02X", mac[i]);
        if (written <= 0 || (size_t)written >= remaining) {
            free(text);
            return NULL;
        }
        cursor += (size_t)written;
        remaining -= (size_t)written;
    }
    return text;
}

static char* format_interface_id(unsigned long interface_index) {
    char text[64];
    snprintf(text, sizeof(text), "ifindex-%lu", interface_index);
    return dup_text(text);
}

static int append_result(
    ns_arp_discovery_result* results,
    int* count,
    int max_host_count,
    const char* ip_address,
    const unsigned char* mac,
    unsigned long mac_length,
    unsigned long interface_index
) {
    if (!results || !count || *count >= max_host_count || !ip_address) {
        return 0;
    }
    ns_arp_discovery_result* row = &results[*count];
    row->ip_address = dup_text(ip_address);
    row->mac_address = format_mac(mac, mac_length);
    row->latency_ms = 0;
    row->adapter_id = format_interface_id(interface_index);
    if (!row->ip_address || !row->mac_address || !row->adapter_id) {
        free(row->ip_address);
        free(row->mac_address);
        free(row->adapter_id);
        memset(row, 0, sizeof(*row));
        return -1;
    }
    ++(*count);
    return 0;
}
#endif

int ns_arp_discover(
    const char* cidr_or_range,
    int max_host_count,
    int only_local,
    ns_arp_discovery_result** out_results,
    int* out_count
) {
    if (!cidr_or_range || !out_results || !out_count || max_host_count <= 0) {
        return -1;
    }
    (void)only_local;
    *out_results = NULL;
    *out_count = 0;

#ifdef _WIN32
    unsigned int start_ip = 0;
    unsigned int end_ip = 0;
    unsigned int network = 0;
    unsigned int mask = 0;
    if (parse_scope(cidr_or_range, &start_ip, &end_ip, &network, &mask) != 0) {
        return -1;
    }

    ns_arp_discovery_result* results = (ns_arp_discovery_result*)calloc((size_t)max_host_count, sizeof(ns_arp_discovery_result));
    if (!results) {
        return -2;
    }

    ULONG table_size = 0;
    DWORD status = GetIpNetTable(NULL, &table_size, FALSE);
    if (status != ERROR_INSUFFICIENT_BUFFER || table_size == 0) {
        free(results);
        return -4;
    }

    PMIB_IPNETTABLE table = (PMIB_IPNETTABLE)malloc((size_t)table_size);
    if (!table) {
        free(results);
        return -2;
    }

    status = GetIpNetTable(table, &table_size, FALSE);
    if (status != NO_ERROR) {
        free(table);
        free(results);
        return -4;
    }

    int count = 0;
    for (DWORD i = 0; i < table->dwNumEntries && count < max_host_count; ++i) {
        const MIB_IPNETROW* row = &table->table[i];
        if (mac_is_broadcast_or_empty(row->bPhysAddr, row->dwPhysAddrLen)) {
            continue;
        }
        const unsigned int ip_host_order = ntohl(row->dwAddr);
        if (ip_host_order < start_ip || ip_host_order > end_ip) {
            continue;
        }
        if (mask != 0U && ((ip_host_order & mask) != (network & mask))) {
            continue;
        }
        if ((ip_host_order & 0xF0000000U) == 0xE0000000U) {
            continue;
        }
        struct in_addr addr;
        addr.S_un.S_addr = row->dwAddr;
        char ip_text[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &addr, ip_text, (size_t)sizeof(ip_text))) {
            continue;
        }
        if (append_result(
                results,
                &count,
                max_host_count,
                ip_text,
                row->bPhysAddr,
                row->dwPhysAddrLen,
                row->dwIndex
            ) != 0) {
            free(table);
            ns_free_arp_discovery(results, count);
            return -3;
        }
    }
    free(table);

    *out_results = results;
    *out_count = count;
    return 0;
#else
    return -5;
#endif
}

void ns_free_arp_discovery(ns_arp_discovery_result* results, int count) {
    if (!results) {
        return;
    }
    for (int i = 0; i < count; ++i) {
        free(results[i].ip_address);
        free(results[i].mac_address);
        free(results[i].adapter_id);
    }
    free(results);
}
