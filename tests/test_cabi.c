/*
 * C99 verification test for nimvault C-ABI (include/nimvault.h).
 * Tests version, truststore info, in-memory Sans-I/O TLS handshake,
 * encrypted plaintext exchange, and actionable error diagnostics from C.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nimvault.h"

static char *read_file_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    *out_len = n;
    return buf;
}

static int pump_pair(nimvault_engine_t client, nimvault_engine_t server) {
    uint8_t buf[4096];
    for (int step = 0; step < 200; step++) {
        int progressed = 0;
        int ca = nimvault_engine_next_action(client);
        int sa = nimvault_engine_next_action(server);

        if (ca == NIMVAULT_ACTION_ERROR || sa == NIMVAULT_ACTION_ERROR) {
            return 0;
        }
        if (ca == NIMVAULT_ACTION_READY && sa == NIMVAULT_ACTION_READY) {
            return 1;
        }
        if (ca == NIMVAULT_ACTION_NEED_WRITE) {
            size_t n = nimvault_engine_drain_encrypted(client, buf, sizeof(buf));
            if (n > 0) {
                size_t fed = 0;
                while (fed < n) {
                    size_t c = nimvault_engine_feed_encrypted(server, buf + fed, n - fed);
                    if (c == 0) break;
                    fed += c;
                }
                progressed = 1;
            }
        }
        if (sa == NIMVAULT_ACTION_NEED_WRITE) {
            size_t n = nimvault_engine_drain_encrypted(server, buf, sizeof(buf));
            if (n > 0) {
                size_t fed = 0;
                while (fed < n) {
                    size_t c = nimvault_engine_feed_encrypted(client, buf + fed, n - fed);
                    if (c == 0) break;
                    fed += c;
                }
                progressed = 1;
            }
        }
        if (!progressed) break;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <cert.pem> <key.pem> [hostname]\n", argv[0]);
        return 2;
    }
    const char *expected_host = (argc >= 4) ? argv[3] : "cabi.nimvault.test";

    printf("[C-ABI] nimvault version: %s\n", nimvault_version());
    printf("[C-ABI] embedded roots:   %d\n", nimvault_has_embedded_roots());

    char src[256];
    int cert_count = 0;
    int ok = nimvault_truststore_info(src, sizeof(src), &cert_count);
    printf("[C-ABI] truststore ok=%d source=%s certs=%d\n", ok, src, cert_count);
    if (!ok || cert_count <= 0) {
        fprintf(stderr, "FAIL: truststore resolution failed in C-ABI\n");
        return 1;
    }

    size_t cert_len = 0, key_len = 0;
    char *cert_pem = read_file_all(argv[1], &cert_len);
    char *key_pem = read_file_all(argv[2], &key_len);
    if (!cert_pem || !key_pem) {
        fprintf(stderr, "FAIL: could not read cert/key PEM files\n");
        return 1;
    }

    /* 1. Verified handshake + encrypted roundtrip */
    nimvault_engine_t client = nimvault_client_new_with_pem(expected_host, cert_pem, cert_len, 0);
    nimvault_engine_t server = nimvault_server_new(cert_pem, cert_len, key_pem, key_len);
    if (!client || !server) {
        fprintf(stderr, "FAIL: failed to allocate C-ABI engines\n");
        return 1;
    }

    if (!pump_pair(client, server)) {
        char diag[512];
        nimvault_engine_last_error_diagnostic(client, diag, sizeof(diag));
        fprintf(stderr, "FAIL: verified handshake failed:\n%s\n", diag);
        return 1;
    }

    const char *msg = "hello from C99 over nimvault Sans-I/O!";
    size_t msg_len = strlen(msg);
    size_t written = nimvault_engine_write_plaintext(client, (const uint8_t *)msg, msg_len);
    nimvault_engine_flush(client);

    uint8_t wire[4096];
    size_t wn = nimvault_engine_drain_encrypted(client, wire, sizeof(wire));
    nimvault_engine_feed_encrypted(server, wire, wn);

    char plain[256] = {0};
    size_t rn = nimvault_engine_read_plaintext(server, (uint8_t *)plain, sizeof(plain) - 1);
    if (written != msg_len || rn != msg_len || strcmp(plain, msg) != 0) {
        fprintf(stderr, "FAIL: plaintext mismatch (got '%s')\n", plain);
        return 1;
    }
    printf("[C-ABI] Verified TLS 1.2 handshake & encrypted payload OK: '%s'\n", plain);

    nimvault_engine_free(client);
    nimvault_engine_free(server);

    /* 2. Hostname mismatch diagnostic verification */
    nimvault_engine_t bad_client = nimvault_client_new_with_pem("wrong.example", cert_pem, cert_len, 0);
    nimvault_engine_t server2 = nimvault_server_new(cert_pem, cert_len, key_pem, key_len);
    if (pump_pair(bad_client, server2)) {
        fprintf(stderr, "FAIL: expected hostname mismatch error\n");
        return 1;
    }
    int err_code = nimvault_engine_last_error_code(bad_client);
    char diag[1024];
    nimvault_engine_last_error_diagnostic(bad_client, diag, sizeof(diag));
    if (err_code != 56 || strstr(diag, "wrong.example") == NULL) {
        fprintf(stderr, "FAIL: unexpected error code %d or diagnostic: %s\n", err_code, diag);
        return 1;
    }
    printf("[C-ABI] Actionable hostname mismatch diagnostic OK (code=%d)\n", err_code);

    nimvault_engine_free(bad_client);
    nimvault_engine_free(server2);
    free(cert_pem);
    free(key_pem);
    return 0;
}
