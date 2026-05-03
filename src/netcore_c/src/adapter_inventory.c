#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <winsock2.h>
#endif

#include "netsentinel/netcore/adapter_inventory.h"

typedef struct ns_string_list {
    char** values;
    int count;
} ns_string_list;

static void ns_string_list_init(ns_string_list* list) {
    if (!list) {
        return;
    }
    list->values = NULL;
    list->count = 0;
}

static void ns_string_list_free(ns_string_list* list) {
    if (!list || !list->values) {
        return;
    }
    for (int i = 0; i < list->count; ++i) {
        free(list->values[i]);
    }
    free(list->values);
    list->values = NULL;
    list->count = 0;
}

static char* ns_dup_string(const char* value) {
    if (!value) {
        return NULL;
    }
    const size_t length = strlen(value);
    char* copy = (char*)malloc(length + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, value, length + 1);
    return copy;
}

static char* ns_dup_empty_string(void) {
    char* copy = (char*)malloc(1);
    if (!copy) {
        return NULL;
    }
    copy[0] = '\0';
    return copy;
}

#ifdef _WIN32
static char* ns_duplicate_wide_string(const wchar_t* value) {
    if (!value || value[0] == L'\0') {
        return ns_dup_empty_string();
    }
    const int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    if (required <= 0) {
        return ns_dup_empty_string();
    }
    char* output = (char*)malloc((size_t)required);
    if (!output) {
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, value, -1, output, required, NULL, NULL) <= 0) {
        free(output);
        return ns_dup_empty_string();
    }
    return output;
}

static char* ns_format_mac(const IP_ADAPTER_ADDRESSES* adapter) {
    if (!adapter || adapter->PhysicalAddressLength == 0) {
        return ns_dup_empty_string();
    }
    const int expected = (int)((adapter->PhysicalAddressLength * 2) + (adapter->PhysicalAddressLength > 0 ? adapter->PhysicalAddressLength - 1 : 0) + 1);
    char* text = (char*)malloc((size_t)expected);
    if (!text) {
        return NULL;
    }
    char* cursor = text;
    size_t remaining = (size_t)expected;
    for (unsigned int i = 0; i < adapter->PhysicalAddressLength; ++i) {
        if (i > 0) {
            if (remaining < 2) {
                free(text);
                return NULL;
            }
            *cursor++ = ':';
            --remaining;
        }
        const int written = snprintf(cursor, remaining, "%02X", adapter->PhysicalAddress[i]);
        if (written <= 0 || (size_t)written >= remaining) {
            free(text);
            return NULL;
        }
        cursor += (size_t)written;
        remaining -= (size_t)written;
    }
    if (remaining > 0) {
        *cursor = '\0';
    }
    return text;
}

static int ns_list_append(ns_string_list* list, const char* value) {
    if (!list || !value || value[0] == '\0') {
        return 0;
    }
    char** next_values = (char**)realloc(list->values, (size_t)(list->count + 1) * sizeof(char*));
    if (!next_values) {
        return -1;
    }
    list->values = next_values;
    char* copy = ns_dup_string(value);
    if (!copy) {
        return -1;
    }
    list->values[list->count++] = copy;
    return 0;
}

static int ns_add_socket_address_to_list(ns_string_list* list, const SOCKADDR* address) {
    if (!list || !address) {
        return 0;
    }
    char text[INET6_ADDRSTRLEN];
    if (address->sa_family == AF_INET) {
        const SOCKADDR_IN* v4 = (const SOCKADDR_IN*)address;
        if (inet_ntop(AF_INET, &v4->sin_addr, text, (socklen_t)sizeof(text)) == NULL) {
            return 0;
        }
        return ns_list_append(list, text);
    }
    if (address->sa_family == AF_INET6) {
        const SOCKADDR_IN6* v6 = (const SOCKADDR_IN6*)address;
        if (inet_ntop(AF_INET6, &v6->sin6_addr, text, (socklen_t)sizeof(text)) == NULL) {
            return 0;
        }
        return ns_list_append(list, text);
    }
    return 0;
}

static int ns_collect_unicast_addresses(const IP_ADAPTER_ADDRESSES* adapter, ns_string_list* ipv4, ns_string_list* ipv6) {
    const IP_ADAPTER_UNICAST_ADDRESS* current = adapter->FirstUnicastAddress;
    while (current) {
        if (current->Address.lpSockaddr) {
            if (current->Address.lpSockaddr->sa_family == AF_INET) {
                if (ns_add_socket_address_to_list(ipv4, current->Address.lpSockaddr) != 0) {
                    return -1;
                }
            } else if (current->Address.lpSockaddr->sa_family == AF_INET6) {
                if (ns_add_socket_address_to_list(ipv6, current->Address.lpSockaddr) != 0) {
                    return -1;
                }
            }
        }
        current = current->Next;
    }
    return 0;
}

static int ns_collect_gateway(const IP_ADAPTER_ADDRESSES* adapter, ns_string_list* gateways) {
    const IP_ADAPTER_GATEWAY_ADDRESS_LH* current = adapter->FirstGatewayAddress;
    while (current) {
        if (current->Address.lpSockaddr) {
            if (ns_add_socket_address_to_list(gateways, current->Address.lpSockaddr) != 0) {
                return -1;
            }
        }
        current = current->Next;
    }
    return 0;
}

static int ns_collect_dns(const IP_ADAPTER_ADDRESSES* adapter, ns_string_list* dns_servers) {
    const IP_ADAPTER_DNS_SERVER_ADDRESS* current = adapter->FirstDnsServerAddress;
    while (current) {
        if (current->Address.lpSockaddr) {
            if (ns_add_socket_address_to_list(dns_servers, current->Address.lpSockaddr) != 0) {
                return -1;
            }
        }
        current = current->Next;
    }
    return 0;
}

static int ns_fill_adapter_entry(const IP_ADAPTER_ADDRESSES* source, ns_adapter_info* target) {
    memset(target, 0, sizeof(*target));

    target->interface_id = ns_dup_string(source->AdapterName);
    if (!target->interface_id) {
        target->interface_id = ns_dup_empty_string();
        if (!target->interface_id) {
            return -1;
        }
    }

    target->friendly_name = ns_duplicate_wide_string(source->FriendlyName);
    if (!target->friendly_name) {
        return -1;
    }
    if (target->friendly_name[0] == '\0') {
        free(target->friendly_name);
        target->friendly_name = ns_dup_string(target->interface_id);
        if (!target->friendly_name) {
            return -1;
        }
    }

    target->mac_address = ns_format_mac(source);
    if (!target->mac_address) {
        return -1;
    }

    target->gateway = ns_dup_empty_string();
    if (!target->gateway) {
        return -1;
    }
    target->dns_servers_count = 0;
    target->dns_servers = NULL;
    target->ipv4_count = 0;
    target->ipv4_addresses = NULL;
    target->ipv6_count = 0;
    target->ipv6_addresses = NULL;

    target->dhcp_enabled = source->Dhcpv4Enabled ? 1 : 0;
    target->link_speed_mbps = (long long)(source->TransmitLinkSpeed / 1000000ULL);
    target->up = (source->OperStatus == IfOperStatusUp) ? 1 : 0;

    ns_string_list ipv4;
    ns_string_list ipv6;
    ns_string_list gateways;
    ns_string_list dns_servers;
    ns_string_list_init(&ipv4);
    ns_string_list_init(&ipv6);
    ns_string_list_init(&gateways);
    ns_string_list_init(&dns_servers);

    if (ns_collect_unicast_addresses(source, &ipv4, &ipv6) != 0) {
        ns_string_list_free(&ipv4);
        ns_string_list_free(&ipv6);
        ns_string_list_free(&gateways);
        ns_string_list_free(&dns_servers);
        return -1;
    }
    if (ns_collect_gateway(source, &gateways) != 0) {
        ns_string_list_free(&ipv4);
        ns_string_list_free(&ipv6);
        ns_string_list_free(&gateways);
        ns_string_list_free(&dns_servers);
        return -1;
    }
    if (ns_collect_dns(source, &dns_servers) != 0) {
        ns_string_list_free(&ipv4);
        ns_string_list_free(&ipv6);
        ns_string_list_free(&gateways);
        ns_string_list_free(&dns_servers);
        return -1;
    }

    if (gateways.count > 0 && gateways.values && gateways.values[0]) {
        free(target->gateway);
        target->gateway = ns_dup_string(gateways.values[0]);
        if (!target->gateway) {
            ns_string_list_free(&ipv4);
            ns_string_list_free(&ipv6);
            ns_string_list_free(&gateways);
            ns_string_list_free(&dns_servers);
            return -1;
        }
    }

    target->ipv4_addresses = ipv4.values;
    target->ipv4_count = ipv4.count;
    target->ipv6_addresses = ipv6.values;
    target->ipv6_count = ipv6.count;
    target->dns_servers = dns_servers.values;
    target->dns_servers_count = dns_servers.count;

    ns_string_list_init(&ipv4);
    ns_string_list_init(&ipv6);
    ns_string_list_init(&dns_servers);
    ns_string_list_init(&gateways);
    return 0;
}
#endif

int ns_list_network_adapters(ns_adapter_info** out_adapters, int* out_count) {
    if (!out_adapters || !out_count) {
        return -1;
    }
    *out_adapters = NULL;
    *out_count = 0;

#ifdef _WIN32
    ULONG required = 0;
    const DWORD query_size = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
        NULL,
        NULL,
        &required
    );
    if (query_size != ERROR_BUFFER_OVERFLOW && query_size != ERROR_SUCCESS) {
        return -2;
    }

    if (required == 0) {
        return 0;
    }
    IP_ADAPTER_ADDRESSES* buffer = (IP_ADAPTER_ADDRESSES*)malloc(required);
    if (!buffer) {
        return -3;
    }

    const DWORD query_result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
        NULL,
        buffer,
        &required
    );
    if (query_result != ERROR_SUCCESS) {
        free(buffer);
        return -4;
    }

    int adapter_count = 0;
    for (const IP_ADAPTER_ADDRESSES* adapter = buffer; adapter; adapter = adapter->Next) {
        ++adapter_count;
    }
    if (adapter_count <= 0) {
        free(buffer);
        return 0;
    }

    ns_adapter_info* adapters = (ns_adapter_info*)calloc((size_t)adapter_count, sizeof(ns_adapter_info));
    if (!adapters) {
        free(buffer);
        return -5;
    }

    int written_count = 0;
    for (const IP_ADAPTER_ADDRESSES* adapter = buffer; adapter; adapter = adapter->Next) {
        if (written_count >= adapter_count) {
            break;
        }
        if (ns_fill_adapter_entry(adapter, &adapters[written_count]) != 0) {
            ns_free_network_adapters(adapters, written_count);
            free(buffer);
            return -6;
        }
        ++written_count;
    }

    free(buffer);
    if (written_count == 0) {
        free(adapters);
        return 0;
    }
    *out_adapters = adapters;
    *out_count = written_count;
#else
    (void)out_adapters;
    (void)out_count;
#endif

    return 0;
}

void ns_free_network_adapters(ns_adapter_info* adapters, int count) {
    if (!adapters || count <= 0) {
        free(adapters);
        return;
    }
    for (int i = 0; i < count; ++i) {
        free(adapters[i].interface_id);
        free(adapters[i].friendly_name);
        free(adapters[i].mac_address);
        free(adapters[i].gateway);

        for (int j = 0; j < adapters[i].ipv4_count; ++j) {
            free(adapters[i].ipv4_addresses[j]);
        }
        free(adapters[i].ipv4_addresses);
        for (int j = 0; j < adapters[i].ipv6_count; ++j) {
            free(adapters[i].ipv6_addresses[j]);
        }
        free(adapters[i].ipv6_addresses);
        for (int j = 0; j < adapters[i].dns_servers_count; ++j) {
            free(adapters[i].dns_servers[j]);
        }
        free(adapters[i].dns_servers);
    }
    free(adapters);
}
