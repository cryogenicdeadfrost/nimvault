# nimvault

Static TLS, OS/embedded CA root resolution, a Sans-I/O state machine, and readable TLS errors for Nim. No `-d:ssl`, no OpenSSL, no `libssl.dll` chasing you into prod.

Built because shipping a 500 KB Nim binary only for it to crash with `could not load: libssl.so.1.1` or `No SSL/TLS CA certificates found` on Windows or Alpine is a rite of passage nobody asked for.

---

## What it does

- **Static BearSSL 0.6 via `{.compile.}`:** Vendored MIT C99 source compiled directly by `nim c`. Zero CMake, zero Make, zero runtime OpenSSL `dlopen`. On Windows, the release CLI imports only `KERNEL32.dll`, `ADVAPI32.dll`, and `msvcrt.dll`.
- **Tiered CA trust store:** Resolves root certificates in order:
  1. Explicit path (`caBundlePath` / `--ca-file`)
  2. `SSL_CERT_FILE` / `NIMVAULT_CA_BUNDLE`
  3. Native OS store — Windows CryptoAPI `ROOT` (`crypt32.dll`), standard Linux/BSD CA bundle paths, macOS `/etc/ssl/cert.pem` & `SystemRootCertificates.keychain`
  4. Compile-time embedded Mozilla CA bundle (`-d:nimvaultEmbedRoots`, ~200 KB via `staticRead`) so even a `FROM scratch` container works out of the box.
- **Sans-I/O core (`TlsEngine`):** Pure state machine with zero socket code. The same engine drives `std/net` (sync), `std/asyncdispatch` (async), custom loops (Chronos, `io_uring`, memory), and the C-ABI (`include/nimvault.h`).
- **Diagnostics that actually say what broke:** Maps BearSSL X.509 codes and RFC 5246 alerts into `VaultError` (`kind`, `code`, `alertCode`, `message`, `likelyCause`, `suggestion`). Captures the peer leaf cert *before* verification fails so `nimvault probe` still prints Subject/SANs/expiry on broken certs.
- **Built-in CLI:** `trust`, `probe`, `keygen` (ECDSA P-256 + self-signed X.509 v3 with SANs), and `version`.

## Caveat (read before filing an issue)

BearSSL implements **TLS 1.0–1.2** (`ECDHE+AES-GCM` and `ECDHE+ChaCha20-Poly1305`), **not TLS 1.3**. That still covers nearly the entire public internet, and keeps the static backend tiny and audit-friendly. If you hit a strict TLS-1.3-only endpoint, `nimvault` tells you that explicitly instead of throwing `sslv3 alert handshake failure`.

---

## CLI

```bash
nim c -d:release -d:nimvaultEmbedRoots -o:nimvault src/nimvault_cli.nim
```

```bash
# Check which trust store won and how many CAs loaded
./nimvault trust

# Inspect a live TLS endpoint (add --json or --insecure when debugging)
./nimvault probe github.com
./nimvault probe github.com --sni wrong.example.com

# Generate an ECDSA P-256 keypair + self-signed X.509 v3 cert with SANs
./nimvault keygen --cn localhost --san localhost --san api.local \
  --cert-out dev.cert.pem --key-out dev.key.pem
```

---

## Library Usage

Compile your app with `-d:nimvaultEmbedRoots` if you want the fallback Mozilla CA bundle baked in. Do **not** pass `-d:ssl`.

### Sync (`std/net`)

```nim
import nimvault

let res = httpGet("example.com", "/")
if res.isOk:
  echo res.val.statusCode, " via ", res.val.peerInfo.protocolVersion,
       " (", res.val.peerInfo.cipherSuite, ")"
else:
  echo formatDiagnostic(res.err)
```

### Async (`std/asyncdispatch`)

```nim
import std/asyncdispatch
import nimvault

proc main() {.async.} =
  let conn = await connectAsync("example.com", 443)
  if conn.isErr:
    echo formatDiagnostic(conn.err)
    return
  let s = conn.val
  discard await s.sendAsync("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
  let chunk = await s.recvAsync(4096)
  if chunk.isOk: echo chunk.val
  await s.closeAsync()

waitFor main()
```

### Sans-I/O (`TlsEngine`)

```nim
import nimvault

let eng = newClientEngine(defaultTlsConfig("example.com")).get()
var buf: array[4096, byte]

while true:
  case eng.nextAction()
  of taNeedWrite:
    let n = eng.drainEncrypted(buf)
    # write buf[0 ..< n] to whatever transport you own
  of taNeedRead:
    # read encrypted bytes from transport -> discard eng.feedEncrypted(...)
    break
  of taAppDataReady:
    let n = eng.readPlaintext(buf)
    # consume decrypted bytes in buf[0 ..< n]
  of taReady:
    discard eng.writePlaintext("ping")
    eng.flush()
  of taClosed: break
  of taError:
    echo formatDiagnostic(eng.lastError())
    break
```

### C-ABI (`include/nimvault.h`)

```bash
# Linux
nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:libnimvault.so src/nimvault/cabi.nim
gcc -Iinclude tests/test_cabi.c -L. -lnimvault -Wl,-rpath,. -o test_cabi

# macOS
nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:libnimvault.dylib src/nimvault/cabi.nim
cc -Iinclude tests/test_cabi.c -L. -lnimvault -Wl,-rpath,. -o test_cabi

# Windows (MinGW)
nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:nimvault.dll src/nimvault/cabi.nim
gcc -Iinclude tests/test_cabi.c nimvault.dll -o test_cabi.exe
```

---

## Layout

```
src/
├── nimvault.nim                  # Public library entry point
├── nimvault_cli.nim              # CLI entry point
└── nimvault/
    ├── errors.nim                # VaultResult[T], VaultError, alert/X.509 diagnostics
    ├── truststore.nim            # Env -> OS store -> staticRead Mozilla bundle
    ├── x509.nim                  # Pure-Nim PEM, SHA-256, ASN.1 DER parser & encoder
    ├── backend_bearssl.nim       # Static BearSSL bindings
    ├── engine.nim                # Sans-I/O TlsEngine (client + server)
    ├── keygen.nim                # ECDSA P-256 keygen + self-signed X.509 v3
    ├── client.nim                # std/net wrapper + probe() + httpGet()
    ├── async_client.nim          # std/asyncdispatch wrapper
    ├── cabi.nim                  # C-ABI exports
    ├── cli.nim                   # CLI commands
    └── private/
        ├── bearssl_shim.c        # Thin C wrapper + leaf-cert capturing X.509 vtable
        └── bearssl_sources.nim   # Generated {.compile.} list (tools/gen_bearssl_sources.nim)
include/nimvault.h                # C header
vendor/bearssl/                   # BearSSL 0.6 C source (MIT)
vendor/cacert.pem                 # Mozilla CA bundle (MPL-2.0)
```

---

## Tests

```bash
nim c -r --hints:off tests/test_errors.nim
nim c -r --hints:off -d:nimvaultEmbedRoots tests/test_truststore.nim
nim c -r --hints:off tests/test_truststore.nim
nim c -r --hints:off tests/test_x509_keygen.nim
nim c -r --hints:off -d:nimvaultEmbedRoots tests/test_engine_loopback.nim
nim c -r --hints:off -d:nimvaultEmbedRoots --threads:on tests/test_client_async.nim
```

---

## Licenses

- `nimvault`: MIT ([LICENSE](LICENSE))
- BearSSL 0.6: MIT (`vendor/bearssl/LICENSE.txt`)
- Mozilla CA bundle (`vendor/cacert.pem`): MPL-2.0 ([THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md))
