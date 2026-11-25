## nimvault — Zero-dependency static TLS, tiered OS/embedded trust store,
## Sans-I/O engine, sync/async adapters, C-ABI, and actionable TLS diagnostics.

import ./nimvault/[errors, truststore, x509, backend_bearssl, engine, keygen, client, async_client]
export errors, truststore, x509, backend_bearssl, engine, keygen, client, async_client
