#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <ws2tcpip.h>
#endif

#include "netsentinel/netcore/netcore_boundary.h"

static long long ns_current_millis(void) {
    return (long long)(clock() * 1000LL / (long long)CLOCKS_PER_SEC);
}

static char* ns_duplicate_text(const char* value) {
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

static void ns_fill_base_result(ns_probe_result* out, const char* target) {
    if (!out) {
        return;
    }
    out->success = 0;
    out->timed_out = 0;
    out->elapsed_ms = 0;
    out->target = ns_duplicate_text(target);
    out->details = NULL;
}

static void ns_set_result_details(ns_probe_result* out, const char* details) {
    if (!out || !details) {
        return;
    }
    if (out->details) {
        free(out->details);
        out->details = NULL;
    }
    out->details = ns_duplicate_text(details);
}

static const char* ns_icmp_status_to_text(DWORD status) {
    switch (status) {
        case IP_SUCCESS:
            return "icmp reply received";
        case IP_BUF_TOO_SMALL:
            return "icmp response buffer too small";
        case IP_DEST_HOST_UNREACHABLE:
            return "icmp destination host unreachable";
        case IP_DEST_NET_UNREACHABLE:
            return "icmp destination network unreachable";
        case IP_REQ_TIMED_OUT:
            return "icmp request timed out";
        case IP_TTL_EXPIRED_REASSEM:
            return "icmp ttl expired during route";
        case IP_TTL_EXPIRED_TRANSIT:
            return "icmp ttl expired during transit";
        case IP_BAD_DESTINATION:
            return "icmp destination address malformed";
        default:
            return "icmp response received with non-success status";
    }
}

static int ns_set_invalid_request(const char* target, const ns_timeout_config* config, const ns_cancel_token* token, ns_probe_result* out) {
    ns_fill_base_result(out, target);
    if (config && (config->total_timeout_ms < 0 || config->connect_timeout_ms < 0)) {
        ns_set_result_details(out, "probe requested with negative timeout");
        return -1;
    }
    if (token && ns_cancel_token_is_requested(token)) {
        ns_set_result_details(out, "probe cancelled before start");
        return 1;
    }
    return 0;
}

int ns_rate_limiter_init(ns_rate_limiter* limiter, unsigned int max_per_second) {
    if (!limiter || max_per_second == 0) {
        return -1;
    }
    limiter->max_per_second = max_per_second;
    limiter->used_in_window = 0;
    limiter->window_start_ms = ns_current_millis();
    limiter->initialized = 1;
    return 0;
}

void ns_rate_limiter_destroy(ns_rate_limiter* limiter) {
    if (!limiter) {
        return;
    }
    limiter->initialized = 0;
    limiter->used_in_window = 0;
    limiter->max_per_second = 0;
    limiter->window_start_ms = 0;
}

int ns_rate_limiter_acquire(ns_rate_limiter* limiter) {
    if (!limiter || !limiter->initialized) {
        return -1;
    }

    const long long now = ns_current_millis();
    if (now - limiter->window_start_ms >= 1000) {
        limiter->window_start_ms = now;
        limiter->used_in_window = 0;
    }

    if (limiter->used_in_window >= limiter->max_per_second) {
        return 1;
    }

    ++limiter->used_in_window;
    return 0;
}

void ns_cancel_token_init(ns_cancel_token* token) {
    if (!token) {
        return;
    }
    token->requested = 0;
}

void ns_cancel_token_request(ns_cancel_token* token) {
    if (!token) {
        return;
    }
    token->requested = 1;
}

int ns_cancel_token_is_requested(const ns_cancel_token* token) {
    if (!token) {
        return 0;
    }
    return token->requested != 0;
}

int ns_ping_probe_stub(const char* target, const ns_timeout_config* config, const ns_cancel_token* token, ns_probe_result* out) {
    if (!target || !config || !out) {
        return -1;
    }
    const long long start = ns_current_millis();
    if (ns_set_invalid_request(target, config, token, out) != 0) {
        return !ns_cancel_token_is_requested(token) ? -1 : 1;
    }

    if (config->total_timeout_ms == 0) {
        out->timed_out = 1;
        ns_set_result_details(out, "probe skipped due to zero timeout configuration");
        out->elapsed_ms = 0;
        return 0;
    }

    out->success = 1;
    ns_set_result_details(out, "probe completed in safe stub mode");
    out->elapsed_ms = ns_current_millis() - start;
    return 0;
}

int ns_ping_probe_ipv4(const char* target, const ns_timeout_config* config, const ns_cancel_token* token, ns_probe_result* out) {
    if (!target || !config || !out) {
        return -1;
    }
    const long long start = ns_current_millis();
    if (ns_set_invalid_request(target, config, token, out) != 0) {
        if (ns_cancel_token_is_requested(token)) {
            return 1;
        }
        return -1;
    }

    if (config->total_timeout_ms == 0) {
        out->timed_out = 1;
        ns_set_result_details(out, "probe skipped due to zero timeout configuration");
        out->elapsed_ms = 0;
        return 0;
    }

#if defined(_WIN32)
    const unsigned long ip = inet_addr(target);
    if (ip == INADDR_NONE && strcmp(target, "255.255.255.255") != 0) {
        ns_set_result_details(out, "target is not a valid IPv4 literal");
        return -1;
    }

    const DWORD timeout_ms = (DWORD)(config->total_timeout_ms > 0 ? config->total_timeout_ms : 1);
    const HANDLE handle = IcmpCreateFile();
    if (handle == INVALID_HANDLE_VALUE) {
        ns_set_result_details(out, "icmp handle could not be created");
        return -1;
    }

    char request_payload[] = "ns11";
    const DWORD reply_buffer_size = sizeof(ICMP_ECHO_REPLY) + sizeof(request_payload);
    void* reply_buffer = malloc((size_t)reply_buffer_size);
    if (!reply_buffer) {
        IcmpCloseHandle(handle);
        ns_set_result_details(out, "icmp reply buffer allocation failed");
        return -1;
    }

    const DWORD sent = IcmpSendEcho(
        handle,
        ip,
        request_payload,
        (WORD)sizeof(request_payload),
        NULL,
        reply_buffer,
        reply_buffer_size,
        timeout_ms
    );
    if (ns_cancel_token_is_requested(token)) {
        free(reply_buffer);
        IcmpCloseHandle(handle);
        ns_set_result_details(out, "probe cancelled");
        return 1;
    }

    if (sent == 0) {
        const DWORD status = GetLastError();
        out->timed_out = (status == IP_REQ_TIMED_OUT) ? 1 : 0;
        out->elapsed_ms = ns_current_millis() - start;
        ns_set_result_details(out, ns_icmp_status_to_text(status));
        free(reply_buffer);
        IcmpCloseHandle(handle);
        return status == IP_REQ_TIMED_OUT || status == IP_DEST_NET_UNREACHABLE || status == IP_DEST_HOST_UNREACHABLE ? 0 : -1;
    }

    const ICMP_ECHO_REPLY* reply = (const ICMP_ECHO_REPLY*)reply_buffer;
    out->success = reply->Status == IP_SUCCESS ? 1 : 0;
    out->timed_out = reply->Status == IP_REQ_TIMED_OUT ? 1 : 0;
    out->elapsed_ms = (long long)reply->RoundTripTime;
    ns_set_result_details(out, ns_icmp_status_to_text(reply->Status));
    free(reply_buffer);
    IcmpCloseHandle(handle);
    return 0;
#else
    ns_set_result_details(out, "icmp probing not supported on this platform");
    out->timed_out = 1;
    out->elapsed_ms = ns_current_millis() - start;
    return -1;
#endif
}

int ns_tcp_connect_probe(const char* target, int port, const ns_timeout_config* config, const ns_cancel_token* token, ns_probe_result* out) {
    if (!target || !config || !out) {
        return -1;
    }
    const long long start = ns_current_millis();
    if (ns_set_invalid_request(target, config, token, out) != 0) {
        if (ns_cancel_token_is_requested(token)) {
            return 1;
        }
        return -1;
    }
    if (port <= 0 || port > 65535) {
        out->timed_out = 0;
        ns_set_result_details(out, "invalid TCP port");
        out->elapsed_ms = 0;
        return -1;
    }
    if (config->total_timeout_ms == 0) {
        out->timed_out = 1;
        ns_set_result_details(out, "probe skipped due to zero timeout configuration");
        out->elapsed_ms = 0;
        return 0;
    }

#if defined(_WIN32)
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        ns_set_result_details(out, "winsock initialization failed");
        return -1;
    }

    const SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        ns_set_result_details(out, "socket creation failed");
        WSACleanup();
        return -1;
    }

    u_long non_blocking = 1;
    if (ioctlsocket(sock, FIONBIO, &non_blocking) != 0) {
        closesocket(sock);
        WSACleanup();
        ns_set_result_details(out, "failed to enable non-blocking socket mode");
        return -1;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((unsigned short)port);
    const unsigned long ip = inet_addr(target);
    if (ip == INADDR_NONE && strcmp(target, "255.255.255.255") != 0) {
        closesocket(sock);
        WSACleanup();
        ns_set_result_details(out, "target is not a valid IPv4 literal");
        return -1;
    }
    dest.sin_addr.s_addr = ip;

    const int rc = connect(sock, (struct sockaddr*)&dest, sizeof(dest));
    if (rc != 0) {
        const int connect_error = WSAGetLastError();
        if (connect_error != WSAEWOULDBLOCK && connect_error != WSAEINPROGRESS && connect_error != WSAEALREADY) {
            out->timed_out = 0;
            out->success = 0;
            out->elapsed_ms = ns_current_millis() - start;
            ns_set_result_details(out, "tcp connect failed immediately");
            closesocket(sock);
            WSACleanup();
            return 0;
        }
    } else {
        out->success = 1;
        out->elapsed_ms = ns_current_millis() - start;
        ns_set_result_details(out, "tcp connect succeeded immediately");
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    const long long remaining_ms = config->total_timeout_ms > config->connect_timeout_ms ? config->connect_timeout_ms : config->total_timeout_ms;
    const long long deadline_ms = remaining_ms > 0 ? remaining_ms : 250;
    const long timeout_sec = (long)(deadline_ms / 1000);
    const long timeout_usec = (long)((deadline_ms % 1000) * 1000);

    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = timeout_usec;
    const int ready = select(0, NULL, &write_fds, NULL, &timeout);
    if (ready > 0 && FD_ISSET(sock, &write_fds)) {
        int socket_error = 0;
        int socket_error_size = (int)sizeof(socket_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&socket_error, &socket_error_size) != 0) {
            out->success = 0;
            ns_set_result_details(out, "could not read socket error state");
        } else if (socket_error == 0) {
            out->success = 1;
            ns_set_result_details(out, "tcp connect succeeded");
        } else {
            out->success = 0;
            if (socket_error == WSAETIMEDOUT) {
                out->timed_out = 1;
                ns_set_result_details(out, "tcp connect timed out");
            } else if (socket_error == WSAECONNREFUSED) {
                ns_set_result_details(out, "tcp connect refused (port closed)");
            } else {
                ns_set_result_details(out, "tcp connect failed");
            }
        }
    } else if (ready == 0) {
        out->timed_out = 1;
        out->success = 0;
        ns_set_result_details(out, "tcp connect timed out");
    } else {
        out->success = 0;
        ns_set_result_details(out, "select call failed during tcp connect");
    }

    out->elapsed_ms = ns_current_millis() - start;
    closesocket(sock);
    WSACleanup();
    return 0;
#else
    ns_set_result_details(out, "tcp probing not supported on this platform");
    out->timed_out = 1;
    out->elapsed_ms = ns_current_millis() - start;
    return -1;
#endif
}

void ns_free_probe_result(ns_probe_result* result) {
    if (!result) {
        return;
    }
    free(result->target);
    free(result->details);
    result->target = NULL;
    result->details = NULL;
}
