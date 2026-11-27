/*
 * Minimal C99 example linking against libnimtls.
 *
 * Build shared lib:
 *   nim c --app:lib -d:release -d:nimtlsEmbedRoots -o:libnimtls.so src/nimtls/cabi.nim
 * Compile & run:
 *   gcc -Iinclude examples/c_embed.c -L. -lnimtls -Wl,-rpath,. -o c_embed
 *   ./c_embed
 */

#include <stdio.h>
#include "nimtls.h"

int main(void) {
    char source[256];
    int cert_count = 0;

    printf("nimtls %s (embedded roots: %s)\n",
           nimtls_version(),
           nimtls_has_embedded_roots() ? "yes" : "no");

    if (nimtls_truststore_info(source, sizeof(source), &cert_count)) {
        printf("trust store: %s (%d roots)\n", source, cert_count);
    } else {
        printf("trust store unavailable: %s\n", source);
        return 1;
    }

    nimtls_engine_t eng = nimtls_client_new("example.com", NULL, 0);
    if (!eng) {
        fprintf(stderr, "failed to create client engine\n");
        return 1;
    }

    uint8_t hello[2048];
    if (nimtls_engine_next_action(eng) == NIMTLS_ACTION_NEED_WRITE) {
        size_t n = nimtls_engine_drain_encrypted(eng, hello, sizeof(hello));
        printf("generated TLS ClientHello: %zu bytes ready for any socket\n", n);
    }

    nimtls_engine_free(eng);
    return 0;
}
