#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct ns_timeout_config {
    long long connect_timeout_ms;
    long long total_timeout_ms;
} ns_timeout_config;

typedef struct ns_rate_limiter {
    unsigned int max_per_second;
    unsigned int used_in_window;
    long long window_start_ms;
    int initialized;
} ns_rate_limiter;

typedef struct ns_cancel_token {
    int requested;
} ns_cancel_token;

typedef struct ns_probe_result {
    int success;
    int timed_out;
    long long elapsed_ms;
    char* target;
    char* details;
} ns_probe_result;

int ns_rate_limiter_init(ns_rate_limiter* limiter, unsigned int max_per_second);
void ns_rate_limiter_destroy(ns_rate_limiter* limiter);
int ns_rate_limiter_acquire(ns_rate_limiter* limiter);

void ns_cancel_token_init(ns_cancel_token* token);
void ns_cancel_token_request(ns_cancel_token* token);
int ns_cancel_token_is_requested(const ns_cancel_token* token);

int ns_ping_probe_stub(const char* target, const ns_timeout_config* config, const ns_cancel_token* token, ns_probe_result* out);
int ns_ping_probe_ipv4(const char* target, const ns_timeout_config* config, const ns_cancel_token* token, ns_probe_result* out);
int ns_tcp_connect_probe(const char* target, int port, const ns_timeout_config* config, const ns_cancel_token* token, ns_probe_result* out);
void ns_free_probe_result(ns_probe_result* result);

#ifdef __cplusplus
}
#endif
