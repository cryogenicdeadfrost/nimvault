# Sans-I/O TLS state machine. No sockets live here -- feed bytes in, drain bytes out.

import ./errors
import ./truststore
import ./x509
import ./backend_bearssl

type
  TlsVersion* = enum
    tvTls10 = 0x0301
    tvTls11 = 0x0302
    tvTls12 = 0x0303

  TlsAction* = enum
    taNeedWrite     # encrypted records queued; write them to the transport
    taNeedRead      # need more wire bytes from the peer
    taAppDataReady  # decrypted plaintext waiting to be read
    taReady         # handshake done; safe to send plaintext
    taClosed        # clean close_notify finished
    taError         # something blew up; check lastError()

  TlsConfig* = object
    serverName*: string
    caBundlePath*: string
    caPemOverride*: string
    allowEmbeddedFallback*: bool
    insecureSkipVerify*: bool
    alpnProtocols*: seq[string]
    failOnAlpnMismatch*: bool
    minVersion*: TlsVersion
    maxVersion*: TlsVersion
    validationTimeUnix*: uint64 # 0 => use OS clock (override for deterministic expiry tests)

  TlsServerConfig* = object
    certPem*: string
    keyPem*: string
    alpnProtocols*: seq[string]
    failOnAlpnMismatch*: bool
    minVersion*: TlsVersion
    maxVersion*: TlsVersion

  PeerInfo* = object
    protocolVersion*: string
    cipherSuite*: string
    cipherSuiteId*: uint16
    selectedAlpn*: string
    serverName*: string
    chainLength*: int
    verified*: bool
    hasPeerCert*: bool
    peerCert*: CertInfo
    trustSource*: string
    trustAnchorCount*: int

  TlsEngineObj* = object
    handle: NvEngineHandle
    isServer*: bool
    serverName*: string
    insecureSkipVerify*: bool
    trustSource*: string
    trustAnchorCount*: int
    handshakeCompleted*: bool

  TlsEngine* = ref TlsEngineObj

proc defaultTlsConfig*(serverName = ""): TlsConfig =
  TlsConfig(
    serverName: serverName,
    allowEmbeddedFallback: true,
    insecureSkipVerify: false,
    minVersion: tvTls12,
    maxVersion: tvTls12,
    validationTimeUnix: 0'u64
  )

proc defaultServerConfig*(certPem, keyPem: string): TlsServerConfig =
  TlsServerConfig(
    certPem: certPem,
    keyPem: keyPem,
    minVersion: tvTls12,
    maxVersion: tvTls12
  )

proc close*(e: TlsEngine) =
  if e != nil and e.handle != nil:
    nv_engine_free(e.handle)
    e.handle = nil

proc `=destroy`*(e: TlsEngineObj) =
  if e.handle != nil:
    nv_engine_free(e.handle)

proc newClientEngine*(config: TlsConfig): TlsResult[TlsEngine] =
  if ord(config.minVersion) > ord(config.maxVersion):
    return err[TlsEngine](
      teInvalidConfig,
      "minVersion cannot be higher than maxVersion",
      suggestion = "Set minVersion <= maxVersion (default: TLS 1.2)."
    )

  var caPem = ""
  var trustSource = "verification-disabled"
  if not config.insecureSkipVerify:
    if config.caPemOverride.len > 0:
      caPem = config.caPemOverride
      trustSource = "in-memory-pem"
    else:
      let trustRes = resolveTrustStore(
        explicitPath = config.caBundlePath,
        allowEmbeddedFallback = config.allowEmbeddedFallback
      )
      if not trustRes.isOk:
        return err[TlsEngine](trustRes.err)
      caPem = trustRes.val.pemData
      trustSource = trustRes.val.sourcePath

  var alpnPtrs: seq[cstring] = @[]
  for proto in config.alpnProtocols:
    if proto.len > 0: alpnPtrs.add(cstring(proto))

  var taCount: cint = 0
  var outErr: cint = 0
  let sniCstr: cstring = if config.serverName.len > 0: cstring(config.serverName) else: nil
  let caCstr: cstring = if caPem.len > 0: cstring(caPem) else: nil
  let alpnPtr: ptr cstring = if alpnPtrs.len > 0: addr alpnPtrs[0] else: nil

  let h = nv_client_create(
    sniCstr, caCstr, csize_t(caPem.len),
    if config.insecureSkipVerify: 1.cint else: 0.cint,
    cuint(ord(config.minVersion)), cuint(ord(config.maxVersion)),
    alpnPtr, csize_t(alpnPtrs.len),
    if config.failOnAlpnMismatch: 1.cint else: 0.cint,
    config.validationTimeUnix,
    addr taCount, addr outErr
  )
  if h == nil:
    if outErr > 0:
      return err[TlsEngine](decodeBearErr(int(outErr), config.serverName))
    return err[TlsEngine](teInternalError, "Failed to init BearSSL client engine (code " & $outErr & ")")

  if not config.insecureSkipVerify and taCount == 0:
    nv_engine_free(h)
    return err[TlsEngine](
      teTrustStoreInvalid,
      "Trust bundle parsed 0 usable RSA/EC trust anchors",
      likelyCause = "CA bundle has no RSA or ECDSA roots that BearSSL understands.",
      suggestion = "Use a standard Mozilla/OS PEM bundle."
    )

  ok(TlsEngine(
    handle: h,
    isServer: false,
    serverName: config.serverName,
    insecureSkipVerify: config.insecureSkipVerify,
    trustSource: trustSource,
    trustAnchorCount: int(taCount),
    handshakeCompleted: false
  ))

proc newServerEngine*(config: TlsServerConfig): TlsResult[TlsEngine] =
  if config.certPem.len == 0 or config.keyPem.len == 0:
    return err[TlsEngine](teInvalidConfig, "Server engine needs both certPem and keyPem")
  if ord(config.minVersion) > ord(config.maxVersion):
    return err[TlsEngine](teInvalidConfig, "minVersion cannot be higher than maxVersion")

  var alpnPtrs: seq[cstring] = @[]
  for proto in config.alpnProtocols:
    if proto.len > 0: alpnPtrs.add(cstring(proto))
  let alpnPtr: ptr cstring = if alpnPtrs.len > 0: addr alpnPtrs[0] else: nil

  var outErr: cint = 0
  let h = nv_server_create(
    cstring(config.certPem), csize_t(config.certPem.len),
    cstring(config.keyPem), csize_t(config.keyPem.len),
    cuint(ord(config.minVersion)), cuint(ord(config.maxVersion)),
    alpnPtr, csize_t(alpnPtrs.len),
    if config.failOnAlpnMismatch: 1.cint else: 0.cint,
    addr outErr
  )
  if h == nil:
    if outErr > 0: return err[TlsEngine](decodeBearErr(int(outErr)))
    return err[TlsEngine](teInvalidConfig, "Failed to init BearSSL server engine (code " & $outErr & ")")

  ok(TlsEngine(handle: h, isServer: true, trustSource: "server", handshakeCompleted: false))

proc rawState*(e: TlsEngine): uint32 {.inline.} =
  if e == nil or e.handle == nil: return BR_SSL_CLOSED
  uint32(nv_engine_state(e.handle))

proc rawErrorCode*(e: TlsEngine): int {.inline.} =
  if e == nil or e.handle == nil: return 0
  int(nv_engine_last_error(e.handle))

proc lastError*(e: TlsEngine): TlsError =
  decodeBearErr(e.rawErrorCode(), if e != nil: e.serverName else: "")

proc isHandshakeDone*(e: TlsEngine): bool =
  if e == nil: return false
  if e.handshakeCompleted: return true
  if (e.rawState() and (BR_SSL_SENDAPP or BR_SSL_RECVAPP)) != 0'u32:
    e.handshakeCompleted = true
    return true
  false

proc nextAction*(e: TlsEngine): TlsAction =
  if e == nil: return taClosed
  let st = e.rawState()
  if (st and BR_SSL_CLOSED) != 0'u32:
    return if e.rawErrorCode() != 0: taError else: taClosed

  if (st and (BR_SSL_SENDAPP or BR_SSL_RECVAPP)) != 0'u32:
    e.handshakeCompleted = true

  # Drain outgoing records first so alerts/handshake flights never stall waiting on reads
  if (st and BR_SSL_SENDREC) != 0'u32: return taNeedWrite
  if (st and BR_SSL_RECVAPP) != 0'u32: return taAppDataReady
  if (st and BR_SSL_SENDAPP) != 0'u32: return taReady
  if (st and BR_SSL_RECVREC) != 0'u32: return taNeedRead
  taClosed

proc needsWrite*(e: TlsEngine): bool {.inline.} = (e.rawState() and BR_SSL_SENDREC) != 0'u32
proc needsRead*(e: TlsEngine): bool {.inline.} = (e.rawState() and BR_SSL_RECVREC) != 0'u32
proc hasAppData*(e: TlsEngine): bool {.inline.} = (e.rawState() and BR_SSL_RECVAPP) != 0'u32
proc canWriteAppData*(e: TlsEngine): bool {.inline.} = (e.rawState() and BR_SSL_SENDAPP) != 0'u32

proc feedEncrypted*(e: TlsEngine, data: openArray[byte]): int =
  if e == nil or e.handle == nil or data.len == 0: return 0
  int(nv_engine_feed_encrypted(e.handle, unsafeAddr data[0], csize_t(data.len)))

proc drainEncryptedRaw*(e: TlsEngine, dest: ptr byte, cap: int): int =
  if e == nil or e.handle == nil or dest == nil or cap <= 0: return 0
  int(nv_engine_drain_encrypted(e.handle, dest, csize_t(cap)))

proc drainEncrypted*(e: TlsEngine, dest: var openArray[byte]): int =
  if e == nil or e.handle == nil or dest.len == 0: return 0
  int(nv_engine_drain_encrypted(e.handle, addr dest[0], csize_t(dest.len)))

proc drainEncryptedAll*(e: TlsEngine): seq[byte] =
  var chunk: array[4096, byte]
  while e.needsWrite():
    let n = e.drainEncrypted(chunk)
    if n <= 0: break
    let oldLen = result.len
    result.setLen(oldLen + n)
    copyMem(addr result[oldLen], addr chunk[0], n)

proc writePlaintext*(e: TlsEngine, data: openArray[byte]): int =
  if e == nil or e.handle == nil or data.len == 0: return 0
  int(nv_engine_write_plaintext(e.handle, unsafeAddr data[0], csize_t(data.len)))

proc writePlaintext*(e: TlsEngine, text: string): int =
  if text.len == 0: return 0
  e.writePlaintext(text.toOpenArrayByte(0, text.high))

proc readPlaintextRaw*(e: TlsEngine, dest: ptr byte, cap: int): int =
  if e == nil or e.handle == nil or dest == nil or cap <= 0: return 0
  int(nv_engine_read_plaintext(e.handle, dest, csize_t(cap)))

proc readPlaintext*(e: TlsEngine, dest: var openArray[byte]): int =
  if e == nil or e.handle == nil or dest.len == 0: return 0
  int(nv_engine_read_plaintext(e.handle, addr dest[0], csize_t(dest.len)))

proc flush*(e: TlsEngine) =
  if e != nil and e.handle != nil: nv_engine_flush(e.handle)

proc closeNotify*(e: TlsEngine) =
  if e != nil and e.handle != nil: nv_engine_close(e.handle)

proc peerInfo*(e: TlsEngine): PeerInfo =
  if e == nil or e.handle == nil: return PeerInfo()

  let ver = uint32(nv_engine_get_version(e.handle))
  let suite = nv_engine_get_cipher_suite(e.handle)
  let alpnC = nv_engine_get_alpn(e.handle)
  let sniC = nv_engine_get_server_name(e.handle)
  let chainLen = int(nv_engine_get_peer_chain_len(e.handle))
  let x509Err = uint32(nv_engine_get_x509_error(e.handle))

  result = PeerInfo(
    protocolVersion: tlsVersionName(ver),
    cipherSuite: cipherSuiteName(suite),
    cipherSuiteId: suite,
    selectedAlpn: if alpnC != nil: $alpnC else: "",
    serverName: if sniC != nil and ($sniC).len > 0: $sniC else: e.serverName,
    chainLength: chainLen,
    verified: (not e.insecureSkipVerify) and (x509Err == 0'u32) and (e.rawErrorCode() == 0) and (chainLen > 0),
    trustSource: e.trustSource,
    trustAnchorCount: e.trustAnchorCount
  )

  var derLen: csize_t = 0
  let derPtr = nv_engine_get_peer_cert(e.handle, addr derLen)
  if derPtr != nil and derLen > 0:
    var der = newSeq[byte](int(derLen))
    copyMem(addr der[0], derPtr, int(derLen))
    let parsed = parseCertDer(der)
    if parsed.isOk:
      result.hasPeerCert = true
      result.peerCert = parsed.val
