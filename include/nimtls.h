/*
 * nimtls C-ABI Header
 *
 * Sans-I/O static TLS engine backed by BearSSL with tiered OS/embedded trust
 * resolution and actionable TLS diagnostics.
 */

#ifndef NIMTLS_H
#define NIMTLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(NIMTLS_SHARED_IMPORT)
  #define NIMTLS_API __declspec(dllimport)
#else
  #define NIMTLS_API
#endif

typedef void *nimtls_engine_t;

typedef enum {
    NIMTLS_ACTION_NEED_WRITE     = 0,
    NIMTLS_ACTION_NEED_READ      = 1,
    NIMTLS_ACTION_APP_DATA_READY = 2,
    NIMTLS_ACTION_READY          = 3,
    NIMTLS_ACTION_CLOSED         = 4,
    NIMTLS_ACTION_ERROR          = 5
} nimtls_action_t;

/* Library metadata and trust store inspection */
NIMTLS_API const char *nimtls_version(void);
NIMTLS_API int nimtls_has_embedded_roots(void);
NIMTLS_API int nimtls_truststore_info(char *out_source, size_t source_cap, int *out_cert_count);

/* Sans-I/O Engine lifecycle */
NIMTLS_API nimtls_engine_t nimtls_client_new(
    const char *server_name,
    const char *ca_bundle_path,
    int insecure_skip_verify
);

NIMTLS_API nimtls_engine_t nimtls_client_new_with_pem(
    const char *server_name,
    const char *ca_pem,
    size_t ca_pem_len,
    int insecure_skip_verify
);

NIMTLS_API nimtls_engine_t nimtls_server_new(
    const char *cert_pem,
    size_t cert_pem_len,
    const char *key_pem,
    size_t key_pem_len
);

NIMTLS_API void nimtls_engine_free(nimtls_engine_t engine);

/* Sans-I/O State Machine */
NIMTLS_API int nimtls_engine_next_action(nimtls_engine_t engine);
NIMTLS_API size_t nimtls_engine_feed_encrypted(nimtls_engine_t engine, const uint8_t *data, size_t len);
NIMTLS_API size_t nimtls_engine_drain_encrypted(nimtls_engine_t engine, uint8_t *dest, size_t cap);
NIMTLS_API size_t nimtls_engine_write_plaintext(nimtls_engine_t engine, const uint8_t *data, size_t len);
NIMTLS_API size_t nimtls_engine_read_plaintext(nimtls_engine_t engine, uint8_t *dest, size_t cap);
NIMTLS_API void nimtls_engine_flush(nimtls_engine_t engine);
NIMTLS_API void nimtls_engine_close(nimtls_engine_t engine);

/* Actionable diagnostics */
NIMTLS_API int nimtls_engine_last_error_code(nimtls_engine_t engine);
NIMTLS_API size_t nimtls_engine_last_error_diagnostic(nimtls_engine_t engine, char *out_buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* NIMTLS_H */
