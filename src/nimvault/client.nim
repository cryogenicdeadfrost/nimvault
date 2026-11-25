## Synchronous std/net TLS client wrapper driven by the Sans-I/O TlsEngine.
## Zero -d:ssl, zero OpenSSL, zero dynamic libraries.

import std/[net, nativesockets, strutils, monotimes, times, tables]
import ./errors
import ./engine

type
  VaultSocket* = ref object
    sock*: Socket
    engine*: TlsEngine
    timeoutMs*: int
    closed*: bool

  ProbeReport* = object
    host*: string
    port*: int
    success*: bool
    handshakeMs*: float
    peerInfo*: PeerInfo
    error*: VaultError

  HttpResponse* = object
    statusCode*: int
    statusLine*: string
    headers*: Table[string, string]
    body*: string
    peerInfo*: PeerInfo

proc sendAllRaw(sock: Socket, data: openArray[byte]): VaultResult[bool] =
  var sent = 0
  while sent < data.len:
    try:
      let n = sock.send(unsafeAddr data[sent], data.len - sent)
      if n <= 0:
        return err[bool](veIoError, "Socket closed while writing encrypted TLS records")
      sent += n
    except CatchableError as e:
      return err[bool](veIoError, "Socket write failed: " & e.msg,
                       likelyCause = "Peer reset connection or network error.")
  ok(true)

proc drainToSocket(vs: VaultSocket): VaultResult[bool] =
  var buf: array[4096, byte]
  while vs.engine.needsWrite():
    let n = vs.engine.drainEncrypted(buf)
    if n <= 0: break
    let w = sendAllRaw(vs.sock, buf.toOpenArray(0, n - 1))
    if not w.isOk:
      return w
  ok(true)

proc pumpReadFromSocket(vs: VaultSocket): VaultResult[int] =
  var buf: array[4096, byte]
  try:
    if vs.timeoutMs > 0:
      var fds = @[vs.sock.getFd()]
      if selectRead(fds, vs.timeoutMs) == 0:
        return err[int](veIoError, "Socket read timed out after " & $vs.timeoutMs & "ms",
                        likelyCause = "Peer stopped responding or firewall dropped packets.",
                        suggestion = "Increase timeout or verify host/port reachability.")
    let n = vs.sock.recv(addr buf[0], buf.len)
    if n <= 0:
      return ok(0)
    var fed = 0
    while fed < n:
      let c = vs.engine.feedEncrypted(buf.toOpenArray(fed, n - 1))
      if c <= 0:
        break
      fed += c
    return ok(n)
  except CatchableError as e:
    return err[int](veIoError, "Socket read failed: " & e.msg,
                    likelyCause = "Connection reset by peer or network interruption.")

proc close*(vs: VaultSocket) =
  if vs == nil or vs.closed:
    return
  vs.closed = true
  try:
    vs.engine.closeNotify()
    discard drainToSocket(vs)
  except CatchableError:
    discard
  vs.engine.close()
  if vs.sock != nil:
    try:
      vs.sock.close()
    except CatchableError:
      discard

proc peerInfo*(vs: VaultSocket): PeerInfo =
  if vs == nil: return PeerInfo()
  vs.engine.peerInfo()

proc driveHandshake(vs: VaultSocket): VaultResult[bool] =
  ## Textbook 20-line Sans-I/O loop driving the TLS handshake over std/net.Socket.
  while true:
    case vs.engine.nextAction()
    of taNeedWrite:
      let w = drainToSocket(vs)
      if not w.isOk: return w
    of taNeedRead:
      let r = pumpReadFromSocket(vs)
      if not r.isOk: return err[bool](r.err)
      if r.val == 0:
        let brErr = vs.engine.rawErrorCode()
        if brErr != 0:
          return err[bool](vs.engine.lastError())
        return err[bool](
          veIoError,
          "Peer closed TCP connection unexpectedly during TLS handshake",
          likelyCause = "Server rejected the connection, requires TLS 1.3 only, or port is not speaking TLS.",
          suggestion = "Verify the port serves TLS and check firewall/SNI settings."
        )
    of taReady, taAppDataReady:
      return ok(true)
    of taError:
      # Flush any pending fatal alert to peer before returning diagnostic
      discard drainToSocket(vs)
      return err[bool](vs.engine.lastError())
    of taClosed:
      return err[bool](veConnectionClosed, "TLS engine closed during handshake")

proc connect*(host: string, port = 443, config = defaultTlsConfig(),
              timeoutMs = 10_000): VaultResult[VaultSocket] =
  ## Connects via TCP and completes a verified TLS handshake using BearSSL.
  var cfg = config
  if cfg.serverName.len == 0:
    cfg.serverName = host

  var engRes = newClientEngine(cfg)
  if not engRes.isOk:
    return err[VaultSocket](engRes.err)

  let sock = newSocket(buffered = false)
  try:
    sock.connect(host, Port(port), timeout = timeoutMs)
  except CatchableError as e:
    sock.close()
    engRes.val.close()
    return err[VaultSocket](
      veIoError,
      "TCP connection to " & host & ":" & $port & " failed: " & e.msg,
      likelyCause = "DNS resolution failed, host unreachable, or port refused.",
      suggestion = "Check hostname, port number, and network connectivity."
    )

  var vs = VaultSocket(
    sock: sock,
    engine: engRes.val,
    timeoutMs: timeoutMs,
    closed: false
  )

  let hs = driveHandshake(vs)
  if not hs.isOk:
    vs.close()
    return err[VaultSocket](hs.err)

  ok(vs)

proc probe*(host: string, port = 443, config = defaultTlsConfig(),
            timeoutMs = 10_000): ProbeReport =
  ## Probes a TLS endpoint and returns rich PeerInfo + diagnostics even if verification fails.
  var cfg = config
  if cfg.serverName.len == 0:
    cfg.serverName = host

  result = ProbeReport(host: host, port: port, success: false)

  var engRes = newClientEngine(cfg)
  if not engRes.isOk:
    result.error = engRes.err
    return result

  let t0 = getMonoTime()
  let sock = newSocket(buffered = false)
  try:
    sock.connect(host, Port(port), timeout = timeoutMs)
  except CatchableError as e:
    sock.close()
    engRes.val.close()
    result.error = VaultError(
      kind: veIoError,
      alertCode: -1,
      message: "TCP connection to " & host & ":" & $port & " failed: " & e.msg,
      likelyCause: "DNS resolution failed, host unreachable, or port refused.",
      suggestion: "Check hostname, port number, and network connectivity."
    )
    return result

  var vs = VaultSocket(
    sock: sock,
    engine: engRes.val,
    timeoutMs: timeoutMs,
    closed: false
  )

  let hs = driveHandshake(vs)
  let elapsed = inMicroseconds(getMonoTime() - t0).float / 1000.0
  result.handshakeMs = elapsed
  result.peerInfo = vs.engine.peerInfo()

  if hs.isOk:
    result.success = true
  else:
    result.success = false
    result.error = hs.err

  vs.close()

proc send*(vs: VaultSocket, data: openArray[byte]): VaultResult[int] =
  ## Encrypts and sends all bytes over the TLS connection.
  if vs == nil or vs.closed:
    return err[int](veConnectionClosed, "Cannot send on closed VaultSocket")
  var offset = 0
  while offset < data.len:
    if vs.engine.canWriteAppData():
      let n = vs.engine.writePlaintext(data.toOpenArray(offset, data.high))
      if n > 0:
        offset += n
        vs.engine.flush()
    let w = drainToSocket(vs)
    if not w.isOk:
      return err[int](w.err)
    let act = vs.engine.nextAction()
    if act == taError:
      return err[int](vs.engine.lastError())
    elif act == taClosed:
      return err[int](veConnectionClosed, "TLS connection closed during send")
  ok(offset)

proc send*(vs: VaultSocket, text: string): VaultResult[int] =
  if text.len == 0: return ok(0)
  vs.send(text.toOpenArrayByte(0, text.high))

proc recv*(vs: VaultSocket, maxBytes = 4096): VaultResult[string] =
  ## Reads decrypted application data from the TLS connection.
  ## Returns empty string on clean peer EOF / close_notify.
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
      let w = drainToSocket(vs)
      if not w.isOk: return err[string](w.err)
    of taNeedRead, taReady:
      let r = pumpReadFromSocket(vs)
      if not r.isOk: return err[string](r.err)
      if r.val == 0:
        let brErr = vs.engine.rawErrorCode()
        if brErr != 0:
          return err[string](vs.engine.lastError())
        return ok("")
    of taClosed:
      return ok("")
    of taError:
      return err[string](vs.engine.lastError())

proc httpGet*(host: string, path = "/", port = 443,
              config = defaultTlsConfig(), timeoutMs = 10_000): VaultResult[HttpResponse] =
  ## Minimal HTTPS GET helper demonstrating zero-OpenSSL HTTPS requests.
  var cfg = config
  if cfg.serverName.len == 0:
    cfg.serverName = host
  if cfg.alpnProtocols.len == 0:
    cfg.alpnProtocols = @["http/1.1"]

  let connRes = connect(host, port, cfg, timeoutMs)
  if not connRes.isOk:
    return err[HttpResponse](connRes.err)
  let vs = connRes.val
  defer: vs.close()

  let reqPath = if path.len == 0: "/" else: path
  let req = "GET " & reqPath & " HTTP/1.1\r\n" &
            "Host: " & host & "\r\n" &
            "User-Agent: nimvault/0.1.0\r\n" &
            "Accept: */*\r\n" &
            "Connection: close\r\n\r\n"
  let sendRes = vs.send(req)
  if not sendRes.isOk:
    return err[HttpResponse](sendRes.err)

  var raw = ""
  while true:
    let chunkRes = vs.recv(8192)
    if not chunkRes.isOk:
      if raw.len > 0: break
      return err[HttpResponse](chunkRes.err)
    if chunkRes.val.len == 0:
      break
    raw.add(chunkRes.val)

  var resp = HttpResponse(headers: initTable[string, string](), peerInfo: vs.peerInfo())
  let sep = raw.find("\r\n\r\n")
  let headerPart = if sep >= 0: raw[0 ..< sep] else: raw
  resp.body = if sep >= 0: raw[sep + 4 .. ^1] else: ""

  let headerLines = headerPart.split("\r\n")
  if headerLines.len > 0:
    resp.statusLine = headerLines[0]
    let parts = headerLines[0].split(' ')
    if parts.len >= 2:
      try:
        resp.statusCode = parseInt(parts[1])
      except ValueError:
        resp.statusCode = 0
    for i in 1 ..< headerLines.len:
      let colon = headerLines[i].find(':')
      if colon > 0:
        let k = headerLines[i][0 ..< colon].strip().toLowerAscii()
        let v = headerLines[i][colon + 1 .. ^1].strip()
        resp.headers[k] = v

  ok(resp)
