# Public umbrella module for nimvault.
# Compile with -d:nimvaultEmbedRoots if you want the fallback Mozilla CA bundle baked in.

import ./nimvault/[errors, truststore, x509, backend_bearssl, engine, keygen, client, async_client]
export errors, truststore, x509, backend_bearssl, engine, keygen, client, async_client

const NimvaultVersion* = "0.2.0"
