## Asynchronous std/asyncdispatch + std/asyncnet TLS adapter
## driven by the exact same Sans-I/O TlsEngine.

import std/[asyncdispatch, asyncnet]
import ./errors
import ./engine

type
  AsyncVaultSocket* = ref object
    sock*: AsyncSocket
    engine*: TlsEngine
    closed*: bool

proc drainToAsyncSocket(vs: AsyncVaultSocket): Future[VaultResult[bool]] {.async.} =
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

proc pumpReadFromAsyncSocket(vs: AsyncVaultSocket): Future[VaultResult[int]] {.async.} =
  try:
    let data = await vs.sock.recv(4096)
    if data.len == 0:
      return ok(0)
    var fed = 0
    while fed < data.len:
      let c = vs.engine.feedEncrypted(data.toOpenArrayByte(fed, data.high))
      if c <= 0: break
      fed += c
    return ok(data.len)
  except CatchableError as e:
    return err[int](veIoError, "Async socket read failed: " & e.msg)

proc closeAsync*(vs: AsyncVaultSocket): Future[void] {.async.} =
  if vs == nil or vs.closed:
    return
  vs.closed = true
  try:
    vs.engine.closeNotify()
    discard await drainToAsyncSocket(vs)
  except CatchableError:
    discard
  vs.engine.close()
  if vs.sock != nil:
    try:
      vs.sock.close()
    except CatchableError:
      discard

proc peerInfo*(vs: AsyncVaultSocket): PeerInfo =
  if vs == nil: return PeerInfo()
  vs.engine.peerInfo()

proc connectAsync*(host: string, port = 443,
                   config = defaultTlsConfig()): Future[VaultResult[AsyncVaultSocket]] {.async.} =
  ## Connects asynchronously and drives the Sans-I/O TLS handshake with `await`.
  var cfg = config
  if cfg.serverName.len == 0:
    cfg.serverName = host

  var engRes = newClientEngine(cfg)
  if not engRes.isOk:
    return err[AsyncVaultSocket](engRes.err)

  let sock = newAsyncSocket(buffered = false)
  try:
    await sock.connect(host, Port(port))
  except CatchableError as e:
    sock.close()
    engRes.val.close()
    return err[AsyncVaultSocket](
      veIoError,
      "Async TCP connection to " & host & ":" & $port & " failed: " & e.msg
    )

  var vs = AsyncVaultSocket(
    sock: sock,
    engine: engRes.val,
    closed: false
  )

  while true:
    case vs.engine.nextAction()
    of taNeedWrite:
      let w = await drainToAsyncSocket(vs)
      if not w.isOk:
        await vs.closeAsync()
        return err[AsyncVaultSocket](w.err)
    of taNeedRead:
      let r = await pumpReadFromAsyncSocket(vs)
      if not r.isOk:
        await vs.closeAsync()
        return err[AsyncVaultSocket](r.err)
      if r.val == 0:
        let e = if vs.engine.rawErrorCode() != 0: vs.engine.lastError()
                else: VaultError(kind: veIoError, alertCode: -1,
                                 message: "Peer closed connection during async TLS handshake")
        await vs.closeAsync()
        return err[AsyncVaultSocket](e)
    of taReady, taAppDataReady:
      return ok(vs)
    of taError:
      discard await drainToAsyncSocket(vs)
      let e = vs.engine.lastError()
      await vs.closeAsync()
      return err[AsyncVaultSocket](e)
    of taClosed:
      await vs.closeAsync()
      return err[AsyncVaultSocket](veConnectionClosed, "TLS engine closed during handshake")

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
    let w = await drainToAsyncSocket(vs)
    if not w.isOk:
      return err[int](w.err)
    let act = vs.engine.nextAction()
    if act == taError:
      return err[int](vs.engine.lastError())
    elif act == taClosed:
      return err[int](veConnectionClosed, "TLS connection closed during async send")
  return ok(offset)

proc recvAsync*(vs: AsyncVaultSocket, maxBytes = 4096): Future[VaultResult[string]] {.async.} =
  if vs == nil or vs.closed:
    return ok("")
  var outBuf = newSeq[byte](max(1, maxBytes))
  while true:
    if vs.engine.hasAppData():
      let n = vs.engine.readPlaintext(outBuf)
      if n > 0:
        var s = newString(n)
        copyMem(addr s[0], addr outBuf[0], n)
        return ok(s)

    case vs.engine.nextAction()
    of taAppDataReady:
      continue
    of taNeedWrite:
      let w = await drainToAsyncSocket(vs)
      if not w.isOk: return err[string](w.err)
    of taNeedRead, taReady:
      let r = await pumpReadFromAsyncSocket(vs)
      if not r.isOk: return err[string](r.err)
      if r.val == 0:
        if vs.engine.rawErrorCode() != 0:
          return err[string](vs.engine.lastError())
        return ok("")
    of taClosed:
      return ok("")
    of taError:
      return err[string](vs.engine.lastError())
