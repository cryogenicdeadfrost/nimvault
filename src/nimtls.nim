# Public umbrella module for nimtls.
# Compile with -d:nimtlsEmbedRoots if you want the fallback Mozilla CA bundle baked in.

import ./nimtls/[errors, truststore, x509, backend_bearssl, engine, keygen, client, async_client]
export errors, truststore, x509, backend_bearssl, engine, keygen, client, async_client

const NimtlsVersion* = "0.3.1"
