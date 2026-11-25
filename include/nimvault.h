/*
 * nimvault C-ABI Header
 *
 * Sans-I/O static TLS engine backed by BearSSL with tiered OS/embedded trust
 * resolution and actionable TLS diagnostics.
 */

#ifndef NIMVAULT_H
#define NIMVAULT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(NIMVAULT_SHARED_IMPORT)
  #define NV_API __declspec(dllimport)
#else
  #define NV_API
#endif

typedef void *nimvault_engine_t;

typedef enum {
    NIMVAULT_ACTION_NEED_WRITE     = 0,
    NIMVAULT_ACTION_NEED_READ      = 1,
    NIMVAULT_ACTION_APP_DATA_READY = 2,
    NIMVAULT_ACTION_READY          = 3,
    NIMVAULT_ACTION_CLOSED         = 4,
    NIMVAULT_ACTION_ERROR          = 5
} nimvault_action_t;

/* Library metadata and trust store inspection */
NV_API const char *nimvault_version(void);
NV_API int nimvault_has_embedded_roots(void);
NV_API int nimvault_truststore_info(char *out_source, size_t source_cap, int *out_cert_count);

/* Sans-I/O Engine lifecycle */
NV_API nimvault_engine_t nimvault_client_new(
    const char *server_name,
    const char *ca_bundle_path,
    int insecure_skip_verify
);

NV_API nimvault_engine_t nimvault_client_new_with_pem(
    const char *server_name,
    const char *ca_pem,
    size_t ca_pem_len,
    int insecure_skip_verify
);

NV_API nimvault_engine_t nimvault_server_new(
    const char *cert_pem,
    size_t cert_pem_len,
    const char *key_pem,
    size_t key_pem_len
);

NV_API void nimvault_engine_free(nimvault_engine_t engine);

/* Sans-I/O State Machine */
NV_API int nimvault_engine_next_action(nimvault_engine_t engine);
NV_API size_t nimvault_engine_feed_encrypted(nimvault_engine_t engine, const uint8_t *data, size_t len);
NV_API size_t nimvault_engine_drain_encrypted(nimvault_engine_t engine, uint8_t *dest, size_t cap);
NV_API size_t nimvault_engine_write_plaintext(nimvault_engine_t engine, const uint8_t *data, size_t len);
NV_API size_t nimvault_engine_read_plaintext(nimvault_engine_t engine, uint8_t *dest, size_t cap);
NV_API void nimvault_engine_flush(nimvault_engine_t engine);
NV_API void nimvault_engine_close(nimvault_engine_t engine);

/* Actionable diagnostics */
NV_API int nimvault_engine_last_error_code(nimvault_engine_t engine);
NV_API size_t nimvault_engine_last_error_diagnostic(nimvault_engine_t engine, char *out_buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* NIMVAULT_H */
