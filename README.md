# nimvault

Static TLS, CA trust store discovery, a Sans-I/O state machine, HTTP fetch, and readable handshake errors for Nim. No `-d:ssl`, no `libssl.so.1.1` vs `3.x` roulette, no copying `libcrypto.dll` next to your `.exe`.

If you have ever dropped a tiny Nim binary into an Alpine container or onto a fresh Windows box and immediately watched it faceplant with `could not load: libssl` or `No SSL/TLS CA certificates found`, this is for that.

---

## How it works

- **BearSSL 0.6 baked in via `{.compile.}`:** All 277 C files live under `src/nimvault/vendor/bearssl/` and get compiled straight by `nim c`. No CMake, no Make, no pkg-config. On Windows, the release binary only imports `KERNEL32.dll`, `ADVAPI32.dll`, and `msvcrt.dll`.
- **Tiered CA lookup:** Checks in order:
  1. Explicit CA file (`caBundlePath` / `--ca-file`) — fails loud if bad, never silently falls back
  2. `SSL_CERT_FILE` or `NIMVAULT_CA_BUNDLE`
  3. Native OS store: Windows CryptoAPI `ROOT` (`crypt32.dll`), standard Linux/BSD CA bundle paths, macOS `/etc/ssl/cert.pem` & `SystemRootCertificates.keychain`
  4. Compile-time embedded Mozilla roots (`-d:nimvaultEmbedRoots`, ~200 KB via `staticRead`) so even a `FROM scratch` image verifies certs.
- **Sans-I/O core (`TlsEngine`):** Zero socket code in the state machine. One engine drives `std/net` (sync client & server), `std/asyncdispatch` (async client & server), custom loops, and the C-ABI (`include/nimvault.h`).
- **Errors you can actually debug:** Translates BearSSL X.509 codes and RFC 5246 alerts into `VaultError` with cause + fix hints, and grabs the server's leaf cert *before* validation rejects it so `nimvault probe` still shows the Subject, SANs, and expiry on a broken handshake.

### One important caveat

BearSSL speaks **TLS 1.0–1.2** (`ECDHE+AES-GCM` and `ECDHE+ChaCha20-Poly1305`), **not TLS 1.3**. That still works against almost every server on the internet and keeps the vendored C backend tiny and audit-friendly. If you hit a strict TLS-1.3-only box, `nimvault` tells you straight up instead of dumping `sslv3 alert handshake failure`.

---

## Install

```bash
nimble install https://github.com/cryogenicdeadfrost/nimvault
```

Or build the standalone CLI directly from a clone:

```bash
nim c -d:release -d:nimvaultEmbedRoots -o:nimvault src/nimvault_cli.nim
```

Prebuilt binaries (`linux-amd64`, `macos-arm64`, `windows-amd64`) and C-ABI shared libs are also attached on the [Releases](https://github.com/cryogenicdeadfrost/nimvault/releases) page.

---

## CLI

```bash
# See which CA store won and how many roots loaded
nimvault trust

# Inspect a live TLS endpoint (--json or --insecure when debugging)
nimvault probe github.com
nimvault probe github.com --sni wrong.example.com

# Minimal HTTPS GET/HEAD without curl or OpenSSL
nimvault fetch --head https://example.com/

# Mint a dev ECDSA P-256 keypair + self-signed X.509 v3 cert with SANs
nimvault keygen --cn localhost --san localhost --san api.local \
  --cert-out dev.cert.pem --key-out dev.key.pem
```

---

## Library usage

Pass `-d:nimvaultEmbedRoots` when compiling if you want the fallback Mozilla CA bundle baked into your binary. Do **not** pass `-d:ssl`.

### Quick HTTPS fetch (with chunked decoding + redirects)

```nim
import nimvault

let res = fetch("https://example.com/")
if res.isOk:
  echo res.val.statusLine, " via ", res.val.peerInfo.cipherSuite
  echo res.val.body.len, " bytes"
else:
  echo prettyErr(res.err)
```

### Sync / Async sockets (client and server)

```nim
import std/asyncdispatch
import nimvault

proc main() {.async.} =
  let conn = await dialAsync("example.com", 443)
  if conn.isErr:
    echo prettyErr(conn.err)
    return
  let s = conn.val
  discard await s.sendAsync("HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
  let resp = await s.recvAsync(4096)
  if resp.isOk: echo resp.val
  await s.closeAsync()

waitFor main()
```

Need a local TLS server? Use `mintSelfSigned()` + `wrapServer()` (sync) or `wrapServerAsync()` (async). Full runnable examples live in [`examples/`](examples/):

- [`examples/fetch_https.nim`](examples/fetch_https.nim) — standalone HTTPS GET
- [`examples/async_fetch.nim`](examples/async_fetch.nim) — `std/asyncdispatch` client
- [`examples/local_https_server.nim`](examples/local_https_server.nim) — self-signed local HTTPS server
- [`examples/sans_io_mem.nim`](examples/sans_io_mem.nim) — zero-socket in-memory TLS 1.2 loopback
- [`examples/c_embed.c`](examples/c_embed.c) — calling `libnimvault` from C99

### C-ABI (`include/nimvault.h`)

```bash
# Linux
nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:libnimvault.so src/nimvault/cabi.nim
gcc -Iinclude examples/c_embed.c -L. -lnimvault -Wl,-rpath,. -o c_embed

# macOS
nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:libnimvault.dylib src/nimvault/cabi.nim
cc -Iinclude examples/c_embed.c -L. -lnimvault -Wl,-rpath,. -o c_embed

# Windows (MinGW)
nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:nimvault.dll src/nimvault/cabi.nim
gcc -Iinclude examples/c_embed.c nimvault.dll -o c_embed.exe
```

---

## Running tests

```bash
nimble test
```

Or individually:

```bash
nim c -r --hints:off tests/test_errors.nim
nim c -r --hints:off -d:nimvaultEmbedRoots tests/test_truststore.nim
nim c -r --hints:off tests/test_truststore.nim
nim c -r --hints:off tests/test_x509_keygen.nim
nim c -r --hints:off -d:nimvaultEmbedRoots tests/test_engine_loopback.nim
nim c -r --hints:off -d:nimvaultEmbedRoots --threads:on tests/test_client_async.nim
```

---

## AI usage note

Transparency first: AI was used to grind out the boring repetitive lookup tables and boilerplate — specifically the RFC 5246 TLS alert / BearSSL error diagnostic table in `errors.nim` and initial ASN.1 DER parsing/test scaffolding. Every crypto primitive comes straight from audited BearSSL 0.6 (zero rolled-our-own TLS math), and everything is verified by CI across Linux, macOS, and Windows.

## Licenses

- `nimvault`: MIT ([LICENSE](LICENSE))
- BearSSL 0.6: MIT (`src/nimvault/vendor/bearssl/LICENSE.txt`)
- Mozilla CA bundle (`src/nimvault/vendor/cacert.pem`): MPL-2.0 ([THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md))
