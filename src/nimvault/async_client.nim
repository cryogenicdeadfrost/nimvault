# Async std/asyncdispatch + std/asyncnet TLS wrapper over the same Sans-I/O engine.

import std/[asyncdispatch, asyncnet]
import ./errors
import ./engine

type
  AsyncVaultSocket* = ref object
    sock*: AsyncSocket
    engine*: TlsEngine
    closed*: bool

proc flushWireAsync(vs: AsyncVaultSocket): Future[VaultResult[bool]] {.async.} =
  var buf: array[4096, byte]
  while vs.engine.needsWrite():
    let n = vs.engine.drainEncrypted(buf)
    if n <= 0: break
    var chunk = newString(n)
    copyMem(addr chunk[0], addr buf[0], n)
    try:
      await vs.sock.send(chunk)
    except CatchableError as e:
      return err[bool](veIoError, "Async socket write failed: " & e.msg)
  return ok(true)

proc slurpWireAsync(vs: AsyncVaultSocket): Future[VaultResult[int]] {.async.} =
  try:
    # Socket MUST be unbuffered (buffered = false), otherwise asyncnet.recv waits for all 4096 bytes.
    let data = await vs.sock.recv(4096)
    if data.len == 0: return ok(0)
    var fed = 0
    while fed < data.len:
      let c = vs.engine.feedEncrypted(data.toOpenArrayByte(fed, data.high))
      if c <= 0: break
      fed += c
    return ok(data.len)
  except CatchableError as e:
    return err[int](veIoError, "Async socket read failed: " & e.msg)

proc closeAsync*(vs: AsyncVaultSocket): Future[void] {.async.} =
  if vs == nil or vs.closed: return
  vs.closed = true
  try:
    vs.engine.closeNotify()
    discard await flushWireAsync(vs)
  except CatchableError:
    discard
  vs.engine.close()
  if vs.sock != nil:
    try: vs.sock.close()
    except CatchableError: discard

proc peerInfo*(vs: AsyncVaultSocket): PeerInfo =
  if vs == nil: return PeerInfo()
  vs.engine.peerInfo()

proc crankHandshakeAsync(vs: AsyncVaultSocket): Future[VaultResult[bool]] {.async.} =
  while true:
    case vs.engine.nextAction()
    of taNeedWrite:
      let w = await flushWireAsync(vs)
      if not w.isOk: return w
    of taNeedRead:
      let r = await slurpWireAsync(vs)
      if not r.isOk: return err[bool](r.err)
      if r.val == 0:
        let e = if vs.engine.rawErrorCode() != 0: vs.engine.lastError()
                else: VaultError(kind: veIoError, alertCode: -1,
                                 message: "Peer closed socket during async TLS handshake")
        return err[bool](e)
    of taReady, taAppDataReady:
      return ok(true)
    of taError:
      discard await flushWireAsync(vs)
      return err[bool](vs.engine.lastError())
    of taClosed:
      return err[bool](veConnectionClosed, "TLS engine closed during handshake")

proc connectAsync*(host: string, port = 443,
                   config = defaultTlsConfig()): Future[VaultResult[AsyncVaultSocket]] {.async.} =
  var cfg = config
  if cfg.serverName.len == 0: cfg.serverName = host

  let engRes = newClientEngine(cfg)
  if not engRes.isOk: return err[AsyncVaultSocket](engRes.err)

  let sock = newAsyncSocket(buffered = false)
  try:
    await sock.connect(host, Port(port))
  except CatchableError as e:
    sock.close()
    engRes.val.close()
    return err[AsyncVaultSocket](veIoError, "Async TCP connect to " & host & ":" & $port & " failed: " & e.msg)

  let vs = AsyncVaultSocket(sock: sock, engine: engRes.val, closed: false)
  let hs = await crankHandshakeAsync(vs)
  if not hs.isOk:
    await vs.closeAsync()
    return err[AsyncVaultSocket](hs.err)
  return ok(vs)

proc dialAsync*(host: string, port = 443,
                config = defaultTlsConfig()): Future[VaultResult[AsyncVaultSocket]] =
  connectAsync(host, port, config)

proc wrapServerAsync*(sock: AsyncSocket, certPem, keyPem: string,
                      alpnProtocols: seq[string] = @[]): Future[VaultResult[AsyncVaultSocket]] {.async.} =
  var cfg = defaultServerConfig(certPem, keyPem)
  cfg.alpnProtocols = alpnProtocols
  let engRes = newServerEngine(cfg)
  if not engRes.isOk: return err[AsyncVaultSocket](engRes.err)

  let vs = AsyncVaultSocket(sock: sock, engine: engRes.val, closed: false)
  let hs = await crankHandshakeAsync(vs)
  if not hs.isOk:
    vs.engine.close()
    return err[AsyncVaultSocket](hs.err)
  return ok(vs)

proc sendAsync*(vs: AsyncVaultSocket, data: string): Future[VaultResult[int]] {.async.} =
  if vs == nil or vs.closed:
    return err[int](veConnectionClosed, "Cannot send on closed AsyncVaultSocket")
  var offset = 0
  while offset < data.len:
    if vs.engine.canWriteAppData():
      let n = vs.engine.writePlaintext(data.toOpenArrayByte(offset, data.high))
      if n > 0:
        offset += n
        vs.engine.flush()
    let w = await flushWireAsync(vs)
    if not w.isOk: return err[int](w.err)
    let act = vs.engine.nextAction()
    if act == taError: return err[int](vs.engine.lastError())
    elif act == taClosed: return err[int](veConnectionClosed, "TLS connection closed during async send")
  return ok(offset)

proc recvAsync*(vs: AsyncVaultSocket, maxBytes = 4096): Future[VaultResult[string]] {.async.} =
  if vs == nil or vs.closed: return ok("")
  var outBuf = newSeq[byte](max(1, maxBytes))
  while true:
    if vs.engine.hasAppData():
      let n = vs.engine.readPlaintext(outBuf)
      if n > 0:
        var s = newString(n)
        copyMem(addr s[0], addr outBuf[0], n)
        return ok(s)

    case vs.engine.nextAction()
    of taAppDataReady: continue
    of taNeedWrite:
      let w = await flushWireAsync(vs)
      if not w.isOk: return err[string](w.err)
    of taNeedRead, taReady:
      let r = await slurpWireAsync(vs)
      if not r.isOk: return err[string](r.err)
      if r.val == 0:
        if vs.engine.rawErrorCode() != 0:
          return err[string](vs.engine.lastError())
        return ok("")
    of taClosed: return ok("")
    of taError: return err[string](vs.engine.lastError())
