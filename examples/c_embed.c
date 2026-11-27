/*
 * Minimal C99 example linking against libnimvault.
 *
 * Build shared lib:
 *   nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:libnimvault.so src/nimvault/cabi.nim
 * Compile & run:
 *   gcc -Iinclude examples/c_embed.c -L. -lnimvault -Wl,-rpath,. -o c_embed
 *   ./c_embed
 */

#include <stdio.h>
#include "nimvault.h"

int main(void) {
    char source[256];
    int cert_count = 0;

    printf("nimvault %s (embedded roots: %s)\n",
           nimvault_version(),
           nimvault_has_embedded_roots() ? "yes" : "no");

    if (nimvault_truststore_info(source, sizeof(source), &cert_count)) {
        printf("trust store: %s (%d roots)\n", source, cert_count);
    } else {
        printf("trust store unavailable: %s\n", source);
        return 1;
    }

    nimvault_engine_t eng = nimvault_client_new("example.com", NULL, 0);
    if (!eng) {
        fprintf(stderr, "failed to create client engine\n");
        return 1;
    }

    uint8_t hello[2048];
    if (nimvault_engine_next_action(eng) == NIMVAULT_ACTION_NEED_WRITE) {
        size_t n = nimvault_engine_drain_encrypted(eng, hello, sizeof(hello));
        printf("generated TLS ClientHello: %zu bytes ready for any socket\n", n);
    }

    nimvault_engine_free(eng);
    return 0;
}
