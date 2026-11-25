# nimvault

**Zero-dependency static TLS, tiered OS/embedded CA trust resolution, Sans-I/O state machine, C-ABI, and actionable TLS diagnostics for Nim.**

`nimvault` solves the three everyday SSL/TLS frustrations in Nim (`std/net`, `std/httpclient`, minimal Docker containers, and Windows deployments) without `-d:ssl`, without runtime `libssl.so`/`libssl.dll` `dlopen` crashes, and without CMake or Make.

---

## What `nimvault` Solves

1. **No more `"No SSL/TLS CA certificates found"` crashes — Tiered Trust Resolution:**
   Resolves roots in strict priority order:
   1. Explicit CA path (`caBundlePath` / `--ca-file`)
   2. `SSL_CERT_FILE` / `NIMVAULT_CA_BUNDLE` environment variable
   3. Native OS trust store:
      - **Windows:** CryptoAPI `ROOT` store (`crypt32.dll`)
      - **Linux/BSD:** `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, Alpine/Fedora/OpenBSD/FreeBSD standard paths
      - **macOS:** `/etc/ssl/cert.pem` & `SystemRootCertificates.keychain`
   4. **Compile-time embedded Mozilla CA bundle** (`-d:nimvaultEmbedRoots` via `staticRead`, ~200 KB) so even a `FROM scratch` Docker container verifies TLS out of the box.

2. **No more `libssl.so` / `libssl.dll` deployment traps — Zero-CMake Static Vendoring:**
   Vendors audited **BearSSL 0.6** (MIT-licensed, zero dynamic allocations, pure C99) and compiles it directly via Nim `{.compile.}` pragmas. Just run `nim c app.nim` — no `-d:ssl`, no `libssl-dev`, no CMake, no shipping DLLs beside `.exe`.

3. **No more cryptic `sslv3 alert handshake failure` errors — Actionable Diagnostics:**
   Maps BearSSL error codes, X.509 verification errors, and RFC 5246 TLS alert codes into structured `VaultError` diagnostics with `kind`, `code`, `alertCode`, `message`, `likelyCause`, and `suggestion` — and captures the peer's leaf certificate even when verification fails so `nimvault probe` shows *why* a certificate was rejected.

4. **One Sans-I/O Core for Sync, Async, Chronos & C-ABI:**
   `TlsEngine` is completely decoupled from sockets. The same state machine drives `std/net` (sync), `std/asyncdispatch` (async), custom transports (e.g. Chronos/io_uring), in-memory tests, and the exported C-ABI (`include/nimvault.h`).

---

## Scope & Transparency Note

`nimvault` wraps **BearSSL 0.6** to remain tiny, audited, zero-CMake, and MIT-licensed. BearSSL implements **TLS 1.0–1.2** with modern AEAD cipher suites (`ECDHE+AES-GCM` and `ECDHE+ChaCha20-Poly1305`) and strict X.509 validation. It does **not** implement TLS 1.3; if a remote endpoint is configured as TLS-1.3-only, `nimvault` explicitly surfaces that in its actionable diagnostic (`veProtocolVersionUnsupported` / `veHandshakeFailed`).

---

## Architecture

```
src/
├── nimvault.nim                  # Public library umbrella module
├── nimvault_cli.nim              # Standalone CLI entrypoint (`nimvault`)
└── nimvault/
    ├── errors.nim                # VaultResult[T], VaultError, BearSSL + TLS alert diagnostics
    ├── truststore.nim            # Tiered trust store (Env -> OS CryptoAPI/Linux/macOS -> staticRead)
    ├── x509.nim                  # Pure-Nim PEM codec, SHA-256, ASN.1 DER X.509 inspector & writer
    ├── backend_bearssl.nim       # Static BearSSL bindings via {.compile.}
    ├── engine.nim                # Sans-I/O TlsEngine (Client & Server)
    ├── keygen.nim                # OS-CSPRNG ECDSA P-256 keygen + self-signed X.509 v3 cert builder
    ├── client.nim                # Sync std/net adapter + probe() + httpGet()
    ├── async_client.nim          # Async std/asyncdispatch adapter
    ├── cabi.nim                  # C-ABI exports (matches include/nimvault.h)
    ├── cli.nim                   # CLI commands: trust, probe, keygen, version
    └── private/
        ├── bearssl_sources.nim   # Auto-generated {.compile.} list for vendor/bearssl/src/**/*.c
        └── bearssl_shim.c        # Thin C shim isolating BearSSL structs & capturing peer leaf certs
```

---

## Quick Start

### 1. Build the Standalone CLI (with Embedded Mozilla Roots)

```bash
nim c -d:release -d:nimvaultEmbedRoots -o:nimvault src/nimvault_cli.nim
```

```bash
# Inspect tiered CA trust resolution on this machine
./nimvault trust

# Probe a live HTTPS endpoint with zero OpenSSL installed
./nimvault probe github.com
./nimvault probe github.com --json

# Generate a dev ECDSA P-256 private key + self-signed X.509 v3 cert with SANs
./nimvault keygen --cn localhost --san localhost --san api.local \
  --cert-out dev.cert.pem --key-out dev.key.pem
```

### 2. Synchronous TLS Client (`std/net`, Zero `-d:ssl`)

```nim
import nimvault

# Compile with: nim c -d:nimvaultEmbedRoots app.nim
let res = httpGet("example.com", "/")
if res.isOk:
  echo "Status: ", res.val.statusCode
  echo "TLS:    ", res.val.peerInfo.protocolVersion, " / ", res.val.peerInfo.cipherSuite
  echo "Trust:  ", res.val.peerInfo.trustSource
else:
  echo formatDiagnostic(res.err)
```

### 3. Asynchronous TLS Client (`std/asyncdispatch`)

```nim
import std/asyncdispatch
import nimvault

proc main() {.async.} =
  let connRes = await connectAsync("example.com", 443)
  if not connRes.isOk:
    echo formatDiagnostic(connRes.err)
    return
  let vs = connRes.val
  discard await vs.sendAsync("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
  let resp = await vs.recvAsync(4096)
  if resp.isOk:
    echo resp.val
  await vs.closeAsync()

waitFor main()
```

### 4. Pure Sans-I/O `TlsEngine` (Zero Socket Coupling)

```nim
import nimvault

var eng = newClientEngine(defaultTlsConfig("example.com")).get()
var wireBuf: array[4096, byte]

while true:
  case eng.nextAction()
  of taNeedWrite:
    let n = eng.drainEncrypted(wireBuf)
    # write wireBuf[0 ..< n] to ANY transport (std/net, chronos, io_uring, memory)
  of taNeedRead:
    # read encrypted bytes from transport and call eng.feedEncrypted(...)
    break
  of taAppDataReady:
    let n = eng.readPlaintext(wireBuf)
    # process decrypted application bytes
  of taReady:
    discard eng.writePlaintext("ping")
    eng.flush()
  of taClosed:
    break
  of taError:
    echo formatDiagnostic(eng.lastError())
    break
```

### 5. C-ABI Shared Library (`include/nimvault.h`)

Build a standalone shared library usable from C, C++, Rust, Go, Zig, or Python:

```bash
# Linux
nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:libnimvault.so src/nimvault/cabi.nim
gcc -Iinclude tests/test_cabi.c -L. -lnimvault -Wl,-rpath,. -o test_cabi

# Windows (MinGW GCC)
nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:nimvault.dll src/nimvault/cabi.nim
gcc -Iinclude tests/test_cabi.c nimvault.dll -o test_cabi.exe
```

---

## Running Tests

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

- `nimvault`: **MIT License** (see [LICENSE](LICENSE))
- Vendored BearSSL 0.6: **MIT License** (see `vendor/bearssl/LICENSE.txt`)
- Vendored Mozilla CA bundle (`vendor/cacert.pem`): **MPL-2.0** (see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md))
