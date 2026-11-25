## Stable C-ABI export of nimvault's Sans-I/O TLS engine, trust store, and diagnostics.
## Build shared library:
##   nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:libnimvault.so src/nimvault/cabi.nim
##   nim c --app:lib -d:release -d:nimvaultEmbedRoots -o:nimvault.dll src/nimvault/cabi.nim

import ./errors
import ./truststore
import ./engine

const NimvaultVersionCstr = "0.1.0"

proc copyStrToCbuf(s: string, outBuf: cstring, cap: csize_t): csize_t =
  if outBuf == nil or cap == 0:
    return csize_t(s.len)
  let maxCopy = min(s.len, int(cap) - 1)
  if maxCopy > 0:
    copyMem(outBuf, unsafeAddr s[0], maxCopy)
  cast[ptr UncheckedArray[char]](outBuf)[maxCopy] = '\0'
  csize_t(maxCopy)

proc nimvault_version*(): cstring {.exportc, dynlib, cdecl.} =
  cstring(NimvaultVersionCstr)

proc nimvault_has_embedded_roots*(): cint {.exportc, dynlib, cdecl.} =
  if hasEmbeddedRoots(): 1.cint else: 0.cint

proc nimvault_truststore_info*(outSource: cstring, sourceCap: csize_t,
                               outCertCount: ptr cint): cint {.exportc, dynlib, cdecl.} =
  let res = resolveTrustStore()
  if not res.isOk:
    if outCertCount != nil: outCertCount[] = 0
    discard copyStrToCbuf(res.err.message, outSource, sourceCap)
    return 0.cint
  if outCertCount != nil:
    outCertCount[] = cint(res.val.certCount)
  discard copyStrToCbuf(res.val.sourcePath, outSource, sourceCap)
  1.cint

proc nimvault_client_new*(serverName: cstring, caBundlePath: cstring,
                          insecureSkipVerify: cint): pointer {.exportc, dynlib, cdecl.} =
  var cfg = defaultTlsConfig(if serverName != nil: $serverName else: "")
  if caBundlePath != nil and ($caBundlePath).len > 0:
    cfg.caBundlePath = $caBundlePath
  cfg.insecureSkipVerify = (insecureSkipVerify != 0)

  let res = newClientEngine(cfg)
  if not res.isOk:
    return nil
  let eng = res.val
  GC_ref(eng)
  cast[pointer](eng)

proc nimvault_client_new_with_pem*(serverName: cstring, caPem: cstring,
                                   caPemLen: csize_t,
                                   insecureSkipVerify: cint): pointer {.exportc, dynlib, cdecl.} =
  var cfg = defaultTlsConfig(if serverName != nil: $serverName else: "")
  if caPem != nil and caPemLen > 0:
    var pemStr = newString(int(caPemLen))
    copyMem(addr pemStr[0], caPem, int(caPemLen))
    cfg.caPemOverride = pemStr
  cfg.insecureSkipVerify = (insecureSkipVerify != 0)

  let res = newClientEngine(cfg)
  if not res.isOk:
    return nil
  let eng = res.val
  GC_ref(eng)
  cast[pointer](eng)

proc nimvault_server_new*(certPem: cstring, certPemLen: csize_t,
                          keyPem: cstring, keyPemLen: csize_t): pointer {.exportc, dynlib, cdecl.} =
  if certPem == nil or keyPem == nil or certPemLen == 0 or keyPemLen == 0:
    return nil
  var cStr = newString(int(certPemLen))
  copyMem(addr cStr[0], certPem, int(certPemLen))
  var kStr = newString(int(keyPemLen))
  copyMem(addr kStr[0], keyPem, int(keyPemLen))

  let res = newServerEngine(defaultServerConfig(cStr, kStr))
  if not res.isOk:
    return nil
  let eng = res.val
  GC_ref(eng)
  cast[pointer](eng)

proc nimvault_engine_free*(handle: pointer) {.exportc, dynlib, cdecl.} =
  if handle == nil: return
  let eng = cast[TlsEngine](handle)
  eng.close()
  GC_unref(eng)

proc nimvault_engine_next_action*(handle: pointer): cint {.exportc, dynlib, cdecl.} =
  if handle == nil: return cint(ord(taError))
  let eng = cast[TlsEngine](handle)
  cint(ord(eng.nextAction()))

proc nimvault_engine_feed_encrypted*(handle: pointer, data: ptr byte,
                                     len: csize_t): csize_t {.exportc, dynlib, cdecl.} =
  if handle == nil or data == nil or len == 0: return 0
  let eng = cast[TlsEngine](handle)
  csize_t(eng.feedEncrypted(toOpenArray(cast[ptr UncheckedArray[byte]](data), 0, int(len) - 1)))

proc nimvault_engine_drain_encrypted*(handle: pointer, dest: ptr byte,
                                      cap: csize_t): csize_t {.exportc, dynlib, cdecl.} =
  if handle == nil or dest == nil or cap == 0: return 0
  let eng = cast[TlsEngine](handle)
  csize_t(eng.drainEncryptedRaw(dest, int(cap)))

proc nimvault_engine_write_plaintext*(handle: pointer, data: ptr byte,
                                      len: csize_t): csize_t {.exportc, dynlib, cdecl.} =
  if handle == nil or data == nil or len == 0: return 0
  let eng = cast[TlsEngine](handle)
  csize_t(eng.writePlaintext(toOpenArray(cast[ptr UncheckedArray[byte]](data), 0, int(len) - 1)))

proc nimvault_engine_read_plaintext*(handle: pointer, dest: ptr byte,
                                     cap: csize_t): csize_t {.exportc, dynlib, cdecl.} =
  if handle == nil or dest == nil or cap == 0: return 0
  let eng = cast[TlsEngine](handle)
  csize_t(eng.readPlaintextRaw(dest, int(cap)))

proc nimvault_engine_flush*(handle: pointer) {.exportc, dynlib, cdecl.} =
  if handle == nil: return
  let eng = cast[TlsEngine](handle)
  eng.flush()

proc nimvault_engine_close*(handle: pointer) {.exportc, dynlib, cdecl.} =
  if handle == nil: return
  let eng = cast[TlsEngine](handle)
  eng.closeNotify()

proc nimvault_engine_last_error_code*(handle: pointer): cint {.exportc, dynlib, cdecl.} =
  if handle == nil: return -1.cint
  let eng = cast[TlsEngine](handle)
  cint(eng.rawErrorCode())

proc nimvault_engine_last_error_diagnostic*(handle: pointer, outBuf: cstring,
                                            cap: csize_t): csize_t {.exportc, dynlib, cdecl.} =
  if handle == nil: return 0
  let eng = cast[TlsEngine](handle)
  copyStrToCbuf(formatDiagnostic(eng.lastError()), outBuf, cap)
